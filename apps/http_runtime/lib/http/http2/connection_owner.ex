defmodule HTTP.HTTP2.ConnectionOwner do
  @moduledoc """
  Long-lived, single-writer HTTP/2 connection runtime.

  The protocol state remains in `HTTP.HTTP2.Connection`; this process owns the
  socket, serializes writes, and routes incoming frames to request owners.
  """
  use GenServer
  import Bitwise

  alias HTTP.HTTP2.{
    Boundary,
    Connection,
    Frame,
    HPACK,
    Scheduler,
    Settings,
    StreamState,
    WireProfile
  }

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @default_queue_bytes 1_048_576
  @default_max_streams 100
  @default_drain_timeout 30_000

  @type transport :: module() | map()
  @type t :: %{
          lifecycle: :connecting | :initializing | :ready | :draining | :closed,
          socket: term(),
          transport: transport(),
          connection: Connection.t(),
          streams: %{optional(pos_integer()) => map()},
          refs: %{optional(reference()) => pos_integer()},
          bytes: non_neg_integer(),
          max_queue_bytes: pos_integer(),
          queue_peak_bytes: non_neg_integer(),
          wrote_preface?: boolean()
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @spec activate(pid()) :: :ok | {:error, term()}
  def activate(owner), do: GenServer.call(owner, :activate)

  @spec send_data(pid(), pos_integer(), binary(), boolean()) :: :ok | {:error, term()}
  def send_data(owner, id, data, end_stream? \\ false),
    do: GenServer.call(owner, {:send_data, id, data, end_stream?})

  @spec open_stream(pid(), list(), keyword()) ::
          {:ok, %{id: pos_integer(), ref: reference()}} | {:error, term()}
  def open_stream(owner, headers, opts \\ []) when is_pid(owner) and is_list(headers) do
    GenServer.call(owner, {:open_stream, headers, opts})
  end

  @spec cancel(pid(), reference() | pos_integer()) :: :ok | {:error, term()}
  def cancel(owner, ref), do: GenServer.call(owner, {:cancel, ref})

  @spec release_stream(pid(), reference() | pos_integer()) :: :ok
  def release_stream(owner, ref), do: GenServer.call(owner, {:release_stream, ref})

  @doc "Acknowledges the oldest DATA delivery after application consumption."
  def acknowledge(owner, id), do: GenServer.call(owner, {:acknowledge, id})

  @spec receive_bytes(pid(), binary()) :: :ok | {:error, term()}
  def receive_bytes(owner, bytes) when is_binary(bytes),
    do: GenServer.call(owner, {:receive_bytes, bytes})

  @spec send_event(pid(), term()) :: :ok | {:error, term()}
  def send_event(owner, event), do: GenServer.call(owner, {:event, event})

  @spec status(pid()) :: map()
  def status(owner), do: GenServer.call(owner, :status)

  @impl true
  def init(opts) do
    with {:ok, profile} <- WireProfile.compile(Keyword.get(opts, :profile, :native_v1)),
         {:ok, digest} <- WireProfile.digest(profile) do
      transport = Keyword.get(opts, :transport, HTTP.Transport.TCP)
      socket = Keyword.get(opts, :socket)

      connection =
        Connection.new(
          receive_window: profile.connection_initial_window,
          hpack: profile.hpack
        )

      state = %{
        lifecycle: :initializing,
        socket: socket,
        transport: transport,
        profile: profile,
        profile_digest: digest,
        connection: connection,
        streams: %{},
        scheduler: Scheduler.new(),
        refs: %{},
        buffer: <<>>,
        response_events: [],
        init_settings: [],
        peer_settings?: false,
        capability_waiters: %{},
        bytes: 0,
        queue_peak_bytes: 0,
        max_queue_bytes: Keyword.get(opts, :max_queue_bytes, @default_queue_bytes),
        max_streams: Keyword.get(opts, :max_streams, @default_max_streams),
        wrote_preface?: false,
        close_reason: nil,
        upload_stalls: %{},
        write_closed?: false,
        activate?: Keyword.get(opts, :activate?, true),
        drain_timeout: Keyword.get(opts, :drain_timeout, @default_drain_timeout),
        drain_timer: nil,
        pool: nil,
        pool_key: nil,
        pool_monitor: nil,
        settings_timer: nil,
        returned_connection_credit: 0,
        max_receive_buffer_bytes: max(1_048_576, profile.connection_initial_window),
        settings_timeout: Keyword.get(opts, :settings_timeout, 10_000),
        write_timeout: Keyword.get(opts, :write_timeout, 1_000)
      }

      {:ok, state, {:continue, :initialize}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_continue(:initialize, state) do
    result =
      with :ok <-
             set_transport_options(state,
               send_timeout: state.write_timeout,
               send_timeout_close: true
             ),
           do: initialize_wire(state)

    case result do
      {:ok, state} ->
        timer = Process.send_after(self(), :settings_timeout, state.settings_timeout)
        state = %{state | lifecycle: :ready, settings_timer: timer}

        case if(state.activate?, do: activate_socket(state), else: {:ok, state}) do
          {:ok, state} -> {:noreply, state}
          {:error, reason} -> {:stop, reason, %{state | lifecycle: :closed, close_reason: reason}}
        end

      {:error, reason, state} ->
        {:stop, reason, state}

      {:error, reason} ->
        {:stop, reason, state}
    end
  end

  def handle_info(:http2_shutdown_exclusive, state), do: {:stop, :normal, state}

  def handle_info(:close_after_write_failure, state), do: {:stop, :normal, state}

  def handle_info(:settings_timeout, state) do
    if state.connection.local.pending_ack? do
      notify_all(state, {:http2, :transport_error, :settings_timeout})
      {:stop, :normal, %{state | lifecycle: :closed, close_reason: :settings_timeout}}
    else
      {:noreply, state}
    end
  end

  def handle_info({:http2_pool, pool, key}, state) do
    monitor = Process.monitor(pool)
    state = %{state | pool: pool, pool_key: key, pool_monitor: monitor}
    report_capacity(state)
    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{pool_monitor: monitor} = state) do
    notify_all(state, {:http2, :transport_error, :pool_down})
    {:stop, :normal, %{state | lifecycle: :closed, close_reason: :pool_down}}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.monitor == monitor end) do
      {id, _entry} ->
        discard_request(state, id)

      nil ->
        {:noreply, %{state | capability_waiters: Map.delete(state.capability_waiters, monitor)}}
    end
  end

  def handle_info({:http2_release_request, ref}, state), do: discard_request(state, ref)

  def handle_info({:http2_release_completed, ref}, state),
    do: async_reply(handle_call({:release_stream, ref}, nil, state))

  def handle_info({:http2_acknowledge_data, id}, state),
    do: async_reply(handle_call({:acknowledge, id}, nil, state))

  def handle_info({:http2_await_capability, pid, generation}, state) do
    cond do
      state.peer_settings? ->
        send(
          pid,
          {:http2_capability, generation,
           state.connection.peer.values.enable_connect_protocol == 1}
        )

        {:noreply, state}

      map_size(state.capability_waiters) >= state.max_streams ->
        send(pid, {:http2_capability, generation, {:error, :capacity}})
        {:noreply, state}

      true ->
        monitor = Process.monitor(pid)

        {:noreply,
         %{
           state
           | capability_waiters: Map.put(state.capability_waiters, monitor, {pid, generation})
         }}
    end
  end

  # Stream tasks submit one bounded write at a time. References qualify both the
  # stream generation and each write, so delayed submissions cannot reach reuse.
  def handle_info({:http2_write, id, generation, ref, data, end_stream?}, state)
      when is_binary(data) and is_boolean(end_stream?) do
    entry = state.streams[id]
    stream = state.connection.streams[id]

    reason = write_admission_reason(entry, stream, generation, data)

    if reason do
      if entry && entry.ref == generation,
        do: notify_stream(state, id, {:write, ref, {:error, reason}})

      {:noreply, state}
    else
      state = put_in(state.streams[id].pending_write, {ref, data, end_stream?})
      notify_stream(state, id, {:write, ref, :accepted})

      case drain_pending_body(state, 0) do
        {:ok, state} -> {:noreply, state}
        {:error, reason, state} -> {:stop, reason, state}
      end
    end
  end

  def handle_info(:drain_bodies, state) do
    case drain_pending_body(state, 0) do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:stop, reason, state}
    end
  end

  def handle_info({:body_chunk, bridge, chunk, ack_ref}, state) do
    case dispatch_event(state, {:body_chunk, bridge, chunk, ack_ref}) do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:noreply, %{state | close_reason: reason}}
      {:error, reason} -> {:noreply, %{state | close_reason: reason}}
    end
  end

  def handle_info({:body_eof, bridge}, state) do
    case dispatch_event(state, {:body_eof, bridge}) do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:noreply, %{state | close_reason: reason}}
    end
  end

  def handle_info({:body_error, bridge, reason}, state) do
    case dispatch_event(state, {:body_error, bridge, reason}) do
      {:ok, state} -> {:noreply, state}
      {:error, error, state} -> {:noreply, %{state | close_reason: {error, reason}}}
    end
  end

  def handle_info({:drain_timeout, token}, %{drain_timer: {_timer, token}} = state) do
    notify_all(state, {:http2, :drain_timeout})
    {:stop, :drain_timeout, %{state | drain_timer: nil, lifecycle: :closed}}
  end

  def handle_info({:drain_timeout, _timer}, state), do: {:noreply, state}

  @impl true
  def handle_info(message, state) do
    case normalize_transport(state, message) do
      {:data, data} ->
        case process_bytes(state, data) do
          {:reply, :ok, state} ->
            case activate_socket(state) do
              {:ok, state} ->
                {:noreply, state}

              {:error, reason} ->
                notify_transport_error(state, reason)
                {:stop, :normal, %{state | lifecycle: :closed, close_reason: reason}}
            end

          {:reply, {:error, reason}, state} ->
            notify_transport_error(state, reason)
            {:stop, :normal, %{state | lifecycle: :closed, close_reason: reason}}
        end

      :closed ->
        notify_all(state, {:http2, :transport_closed})
        {:stop, :normal, %{state | lifecycle: :closed, close_reason: :closed}}

      {:error, reason} ->
        notify_transport_error(state, reason)
        {:stop, :normal, %{state | lifecycle: :closed, close_reason: reason}}

      :unknown ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply,
     Map.take(state, [
       :lifecycle,
       :profile_digest,
       :wrote_preface?,
       :bytes,
       :max_queue_bytes,
       :queue_peak_bytes,
       :close_reason
     ])
     |> Map.put(:stream_ids, Map.keys(state.streams))
     |> Map.merge(runtime_measurements(state)), state}
  end

  def handle_call(:activate, _from, state) do
    case set_transport_options(state, send_timeout: state.write_timeout, send_timeout_close: true) do
      :ok ->
        case activate_socket(state) do
          {:ok, state} ->
            {:reply, :ok, state}

          {:error, reason} ->
            notify_transport_error(state, reason)

            {:stop, :normal, {:error, reason},
             %{state | lifecycle: :closed, close_reason: reason}}
        end

      {:error, reason} ->
        notify_transport_error(state, reason)
        {:stop, :normal, {:error, reason}, %{state | lifecycle: :closed, close_reason: reason}}
    end
  end

  def handle_call({:send_data, id, data, end_stream?}, _from, state)
      when is_integer(id) and is_binary(data) and is_boolean(end_stream?) do
    case dispatch_event(state, {:data, id, data, end_stream?}) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:open_stream, _headers, _opts}, _from, %{lifecycle: lifecycle} = state)
      when lifecycle in [:draining, :closed],
      do: {:reply, {:error, lifecycle}, state}

  def handle_call({:open_stream, _headers, _opts}, _from, state)
      when map_size(state.streams) >= state.max_streams,
      do: {:reply, {:error, :capacity}, state}

  def handle_call({:open_stream, headers, opts}, from, state) do
    deadline = Keyword.get(opts, :deadline_at)
    write_limit = Keyword.get(opts, :max_write_bytes, 16_777_230)
    subscriber = Keyword.get(opts, :subscriber, elem(from, 0))

    cond do
      not is_integer(write_limit) or write_limit <= 0 ->
        {:reply, {:error, :invalid_max_write_bytes}, state}

      is_integer(deadline) and deadline <= System.monotonic_time(:millisecond) ->
        {:reply, {:error, :opening_timeout}, state}

      is_integer(deadline) and not Process.alive?(subscriber) ->
        {:reply, {:error, :subscriber_down}, state}

      true ->
        do_open_stream(headers, opts, from, state)
    end
  end

  def handle_call({:cancel, ref_or_id}, _from, state) do
    case stream_id(state, ref_or_id) do
      {:ok, id} ->
        case Connection.cancel_headers(state.connection, id) do
          {:ok, connection, effects} ->
            case write_effects(state, effects) do
              {:ok, state} ->
                cancel_body_bridge(state, id)
                state = terminal_stream(state, id, {:http2, :cancelled})
                {:reply, :ok, %{state | connection: connection}}

              {:error, reason, state} ->
                notify_transport_error(state, reason)

                {:stop, :normal, {:error, reason},
                 %{state | lifecycle: :closed, close_reason: reason}}
            end
        end

      :error ->
        {:reply, {:error, :unknown_stream}, state}
    end
  end

  def handle_call({:acknowledge, id}, _from, state) do
    case get_in(state.streams, [id, :deliveries]) do
      nil ->
        {:reply, {:error, :unknown_stream}, state}

      deliveries ->
        case :queue.out(deliveries) do
          {{:value, bytes}, rest} ->
            case acknowledge_bytes(state, id, bytes) do
              {:ok, state} ->
                {:reply, :ok, put_in(state.streams[id].deliveries, rest)}

              {:error, reason, state} ->
                notify_transport_error(state, reason)

                {:stop, :normal, {:error, reason},
                 %{state | lifecycle: :closed, close_reason: reason}}
            end

          {:empty, _} ->
            {:reply, {:error, :unknown_delivery}, state}
        end
    end
  end

  def handle_call({:release_stream, ref_or_id}, _from, state) do
    case stream_id(state, ref_or_id) do
      {:ok, id} ->
        state = close_unfinished_upload(state, id)
        ref = get_in(state, [:streams, id, :ref])
        Process.demonitor(state.streams[id].monitor, [:flush])
        stop_body_bridge(state, id)
        bytes = state.connection.streams[id].unacknowledged

        state =
          case acknowledge_bytes(state, id, bytes) do
            {:ok, state} -> state
            {:error, reason, state} -> %{state | lifecycle: :closed, close_reason: reason}
          end

        state = finish_upload_stall(state, id, :stopped)

        state = %{
          state
          | streams: Map.delete(state.streams, id),
            refs: Map.delete(state.refs, ref),
            scheduler: Scheduler.remove(state.scheduler, id),
            connection: Connection.remove_stream(state.connection, id)
        }

        emit_runtime(state, :released)

        if state.lifecycle == :closed or
             (state.lifecycle == :draining and map_size(state.streams) == 0) do
          {:stop, :normal, :ok, state}
        else
          {:reply, :ok, state}
        end

      :error ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:receive_bytes, bytes}, _from, state) do
    process_bytes(state, bytes)
  end

  def handle_call({:event, event}, _from, state) do
    case dispatch_event(state, event) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def format_status(status) do
    Map.update(status, :state, %{}, fn state ->
      Map.take(state, [
        :lifecycle,
        :close_reason,
        :profile_digest,
        :max_streams,
        :queue_peak_bytes,
        :max_receive_buffer_bytes
      ])
    end)
  end

  @impl true
  def terminate(reason, state) do
    Enum.each(state.upload_stalls, fn {_id, started} -> emit_stall(started, :closed) end)

    HTTP.Runtime.Telemetry.http2_runtime(
      :connection_close,
      close_category(state.close_reason || reason),
      %{}
    )

    emit_runtime(state, :closed)
    Enum.each(Map.keys(state.streams), &stop_body_bridge(state, &1))
    close_transport(state)
    :ok
  end

  defp discard_request(state, ref) do
    case handle_call({:cancel, ref}, nil, state) do
      {:reply, _, state} ->
        case handle_call({:release_stream, ref}, nil, state) do
          {:reply, _, state} -> {:noreply, state}
          {:stop, reason, _, state} -> {:stop, reason, state}
        end

      {:stop, reason, _, state} ->
        {:stop, reason, state}
    end
  end

  defp do_open_stream(headers, opts, from, state) do
    request_ref = Keyword.get(opts, :request_ref, make_ref())

    with {:ok, stream, connection} <-
           Connection.open_stream(state.connection,
             request_ref: request_ref,
             purpose: Keyword.get(opts, :purpose, :request),
             request_method:
               if(List.keyfind(headers, ":method", 0) == {":method", "HEAD"}, do: :head)
           ),
         ordered_headers <- order_headers(state.profile, headers, stream.purpose),
         {:ok, connection, effects} <-
           Connection.commit_headers(connection, stream.id, ordered_headers,
             end_stream: Keyword.get(opts, :end_stream, is_nil(Keyword.get(opts, :body_bridge))),
             max_frame_size: state.profile.max_header_fragment,
             priority: state.profile.priority
           ),
         {:ok, state} <- write_effects(state, effects) do
      result = %{id: stream.id, ref: request_ref}

      state = %{
        state
        | connection: connection,
          streams:
            Map.put(state.streams, stream.id, %{
              ref: request_ref,
              pid: Keyword.get(opts, :subscriber, elem(from, 0)),
              monitor: Process.monitor(Keyword.get(opts, :subscriber, elem(from, 0))),
              committed?: true,
              terminal?: false,
              body_bridge: Keyword.get(opts, :body_bridge),
              upload_stopped?: false,
              pending_body: nil,
              pending_write: nil,
              max_write_bytes: Keyword.get(opts, :max_write_bytes, 16_777_230),
              byte_stream?: Keyword.get(opts, :byte_stream, false),
              deliveries: :queue.new()
            }),
          refs: Map.put(state.refs, request_ref, stream.id),
          scheduler: Scheduler.add(state.scheduler, stream.id)
      }

      emit_runtime(state, :opened)
      {:reply, {:ok, result}, state}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}

      {:error, reason, failed_state} ->
        notify_transport_error(failed_state, reason)

        {:stop, :normal, {:error, reason},
         %{failed_state | lifecycle: :closed, close_reason: reason}}
    end
  end

  defp initialize_wire(state) do
    entries = state.profile.settings
    {:ok, increment} = WireProfile.initial_window_increment(state.profile)

    {:ok, connection, [{:settings, settings}]} =
      Connection.update_local_settings(state.connection, entries)

    settings_frame = Frame.encode(:settings, 0, 0, settings)

    initial_window =
      if increment > 0,
        do: Frame.encode(:window_update, 0, 0, <<0::1, increment::31>>),
        else: <<>>

    case transport_send(%{state | connection: connection}, [
           @preface,
           settings_frame,
           initial_window
         ]) do
      :ok ->
        {:ok, %{state | connection: connection, wrote_preface?: true, init_settings: entries}}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp write_effects(state, effects) do
    Enum.reduce_while(effects, {:ok, state}, fn effect, {:ok, state} ->
      case effect do
        {:headers, _id, frames} ->
          send_frames(state, frames)

        {:priority, id, dependency, weight, exclusive} ->
          payload = <<if(exclusive, do: 1, else: 0)::1, dependency::31, weight - 1::8>>
          send_frames(state, [Frame.encode(:priority, 0, id, payload)])

        {:rst_stream, id, _reason} ->
          send_frames(state, [Frame.encode(:rst_stream, 0, id, <<8::32>>)], :control)

        {:settings, payload} ->
          send_frames(state, [Frame.encode(:settings, 0, 0, payload)])

        {:settings_ack, _entries} ->
          send_frames(state, [Frame.encode(:settings, 0x1, 0, <<>>)], :control)

        {:data, _id, frame} ->
          send_frames(state, [frame])

        {:window_update, id, increment} ->
          send_frames(
            state,
            [Frame.encode(:window_update, 0, id, <<0::1, increment::31>>)],
            :control
          )

        _ ->
          {:cont, {:ok, state}}
      end
      |> case do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason, state} -> {:halt, {:error, reason, state}}
      end
    end)
  end

  defp send_frames(state, frames, kind \\ :required)
  defp send_frames(%{lifecycle: :closed} = state, _frames, _kind), do: {:error, :closed, state}
  defp send_frames(%{write_closed?: true} = state, _frames, :control), do: {:ok, state}

  defp send_frames(%{write_closed?: true} = state, _frames, :required),
    do: fail_write(state, :closed)

  defp send_frames(state, frames, kind) do
    bytes = IO.iodata_length(frames)
    queue_bytes = state.bytes + bytes

    if queue_bytes > state.max_queue_bytes do
      {:error, :writer_queue_full, state}
    else
      state = %{state | queue_peak_bytes: max(state.queue_peak_bytes, queue_bytes)}

      case transport_send(state, frames) do
        :ok ->
          {:ok, %{state | bytes: max(state.bytes - bytes, 0)}}

        {:error, :closed} when kind == :control ->
          # A closed write side does not invalidate bytes already buffered for
          # parsing. Retire the connection and let END_STREAM/EOF decide each
          # request; the drain timer and original request deadlines still apply.
          {:ok, drain_closed_writer(state)}

        {:error, :einval} when kind == :control ->
          # OTP TCP/TLS senders can report einval while their close notification is
          # still in flight. Only retire an optional control write after every
          # response is protocol-complete; required writes and partial responses
          # must still fail. The connection is never reused after this failure.
          if state.transport in [HTTP.Transport.TCP, HTTP.Transport.SSL] and
               responses_complete?(state) do
            {:ok, drain_closed_writer(state)}
          else
            fail_write(state, :einval)
          end

        {:error, reason} ->
          fail_write(state, reason)
      end
    end
  end

  defp responses_complete?(state) do
    map_size(state.streams) > 0 and
      Enum.all?(state.connection.streams, fn {_, stream} ->
        stream.response_phase == :complete
      end)
  end

  defp fail_write(state, reason) do
    notify_transport_error(state, reason)
    close_transport(state)
    send(self(), :close_after_write_failure)
    {:error, reason, %{state | lifecycle: :closed, close_reason: reason}}
  end

  # Transports can reject writes while complete or partial response bytes remain
  # buffered (including ex_ssl after close_notify). Stop admission/uploads, then
  # let the parser and original request
  # deadlines decide completion; a failed control write is never END_STREAM.
  defp drain_closed_writer(state) do
    if state.pool, do: GenServer.cast(state.pool, {:owner_draining, state.pool_key, self()})
    _ = if state.drain_timer, do: Process.cancel_timer(elem(state.drain_timer, 0))
    token = make_ref()
    timeout = if state.drain_timeout > 0, do: state.drain_timeout, else: @default_drain_timeout
    timer = Process.send_after(self(), {:drain_timeout, token}, timeout)
    Enum.each(Map.keys(state.streams), &stop_body_bridge(state, &1))
    streams = Map.new(state.streams, fn {id, entry} -> {id, %{entry | pending_body: nil}} end)

    %{
      state
      | lifecycle: :draining,
        write_closed?: true,
        close_reason: :closed,
        streams: streams,
        drain_timer: {timer, token}
    }
  end

  defp process_bytes(state, bytes) do
    buffer = state.buffer <> bytes

    case decode_frames(state, buffer) do
      {:reply, :ok, state} ->
        state.response_events
        |> Enum.reverse()
        |> Enum.each(fn {id, event} -> notify_stream(state, id, event) end)

        {:reply, :ok, %{state | response_events: []}}

      {:reply, error, state} ->
        # Opt-in byte streams keep admitted bytes before a connection terminal
        # error. Ordinary Fetch delivery retains its accepted response policy.
        state.response_events
        |> Enum.reverse()
        |> Enum.each(fn {id, event} -> flush_terminal_byte_event(state, id, event) end)

        {:reply, error, %{state | response_events: []}}
    end
  end

  defp decode_frames(state, buffer) do
    case Boundary.decode(buffer, state.connection.local.values.max_frame_size) do
      {:error, reason} ->
        {:reply, {:error, reason}, state}

      :more ->
        {:reply, :ok, %{state | buffer: buffer}}

      {:ok, frame, rest} ->
        case validate_and_dispatch(state, frame) do
          {:ok, state} -> decode_frames(state, rest)
          {:error, reason, state} -> {:reply, {:error, reason}, state}
        end
    end
  end

  defp validate_and_dispatch(state, frame) do
    continuation = if state.connection.header_block, do: state.connection.header_block.stream_id

    case Boundary.validate(frame, state.peer_settings?, continuation) do
      :ok ->
        case {frame, state.streams[frame.stream_id]} do
          {%{type: :window_update, stream_id: id, payload: <<_::1, increment::31>>},
           %{terminal?: true}}
          when id > 0 and increment > 0 ->
            {:ok, state}

          {%{type: :data, payload: payload}, %{terminal?: true}} ->
            discard_closed_data(state, payload)

          _ ->
            dispatch_frame(state, frame)
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp dispatch_frame(state, %{type: :ping, flags: flags, payload: payload}) do
    if Frame.flag?(flags, 1),
      do: {:ok, state},
      else: send_frames(state, [Frame.encode(:ping, 1, 0, payload)], :control)
  end

  defp dispatch_frame(state, %{type: :rst_stream, stream_id: id, payload: <<code::32>>}) do
    case Connection.stream(state.connection, id) do
      {:ok, %{response_phase: :complete} = stream} when code == 0 ->
        {:ok, stream} = StreamState.rst(stream, code)
        {:ok, %{state | connection: Connection.put_stream(state.connection, stream)}}

      {:ok, stream} ->
        HTTP.Runtime.Telemetry.http2_runtime(:peer_reset, :received, %{error_code: code})
        {:ok, stream} = StreamState.rst(stream, code)
        state = terminal_stream(state, id, {:http2, :reset, code})
        events = Enum.reject(state.response_events, fn {stream_id, _} -> stream_id == id end)

        {:ok,
         %{
           state
           | connection: Connection.put_stream(state.connection, stream),
             response_events: events
         }}

      :error when rem(id, 2) == 1 and id < state.connection.next_stream_id ->
        {:ok, state}

      :error ->
        {:error, :protocol_error, state}
    end
  end

  defp dispatch_frame(state, %{type: :push_promise}),
    do: {:error, :push_disabled, state}

  defp dispatch_frame(state, %{
         type: :priority,
         stream_id: id,
         payload: <<_exclusive::1, dependency::31, _weight>>
       }) do
    if id == dependency, do: {:error, :protocol_error, state}, else: {:ok, state}
  end

  defp dispatch_frame(state, %{type: :settings, flags: flags, payload: payload}) do
    if Frame.flag?(flags, 0x1) do
      case Connection.acknowledge_settings(state.connection) do
        {:ok, connection, _} ->
          _ = if state.settings_timer, do: Process.cancel_timer(state.settings_timer)

          timer =
            if connection.local.pending_ack?,
              do: Process.send_after(self(), :settings_timeout, state.settings_timeout)

          {:ok, %{state | connection: connection, settings_timer: timer}}

        {:error, reason} ->
          {:error, reason, state}
      end
    else
      with {:ok, entries} <- Settings.decode(payload),
           {:ok, connection, effects} <-
             Connection.update_peer_settings(state.connection, entries),
           {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
        Enum.each(state.capability_waiters, fn {monitor, {pid, generation}} ->
          Process.demonitor(monitor, [:flush])

          send(
            pid,
            {:http2_capability, generation, connection.peer.values.enable_connect_protocol == 1}
          )
        end)

        state = %{state | connection: connection, peer_settings?: true, capability_waiters: %{}}
        report_capacity(state)
        drain_pending_body(state, 0)
      else
        {:error, reason} -> settings_failure(state, reason)
        {:error, reason, _} -> {:error, reason, state}
      end
    end
  end

  defp dispatch_frame(state, %{
         type: :goaway,
         payload: <<_reserved::1, last::31, error::32, _debug::binary>>
       }) do
    case Connection.receive_goaway(state.connection, last) do
      {:ok, connection, _} ->
        HTTP.Runtime.Telemetry.http2_runtime(:peer_goaway, :received, %{error_code: error})
        if state.pool, do: GenServer.cast(state.pool, {:owner_draining, state.pool_key, self()})

        state =
          Enum.reduce(state.streams, state, fn {id, _}, acc ->
            if id > last do
              terminal_stream(
                acc,
                id,
                {:http2, :stream_error, {:goaway, last, error, :unprocessed}}
              )
            else
              notify_stream(acc, id, {:http2, :goaway, last, error})
              acc
            end
          end)

        _ = if state.drain_timer, do: Process.cancel_timer(elem(state.drain_timer, 0))

        {timer_ref, timer_token} =
          if state.drain_timeout > 0 do
            token = make_ref()
            {Process.send_after(self(), {:drain_timeout, token}, state.drain_timeout), token}
          else
            {nil, nil}
          end

        {:ok,
         %{
           state
           | connection: connection,
             lifecycle: :draining,
             drain_timer: {timer_ref, timer_token}
         }}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp dispatch_frame(state, %{
         type: :priority_update,
         stream_id: 0,
         payload: <<0::1, target_stream_id::31, value::binary>>
       }) do
    case Connection.priority_update(state.connection, 0, target_stream_id, value) do
      {:ok, connection, _effects} ->
        {:ok, %{state | connection: connection}}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp dispatch_frame(state, %{type: :priority_update}),
    do: {:error, :invalid_priority_update, state}

  defp dispatch_frame(
         %{connection: connection} = state,
         %{type: :window_update, stream_id: id, payload: <<_reserved::1, increment::31>>}
       )
       when id > 0 and rem(id, 2) == 1 and id < connection.next_stream_id and
              not is_map_key(connection.streams, id) and increment > 0,
       do: {:ok, state}

  defp dispatch_frame(state, %{
         type: :window_update,
         stream_id: id,
         payload: <<_reserved::1, increment::31>>
       })
       when increment > 0 do
    with {:ok, connection, effects} <-
           Connection.update_send_window(state.connection, id, increment),
         {:ok, state} <- write_effects(%{state | connection: connection}, effects),
         {:ok, state} <- drain_pending_body(state, id) do
      {:ok, state}
    else
      {:error, reason} -> {:error, reason, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp dispatch_frame(state, %{type: :window_update}),
    do: {:error, :invalid_window_update, state}

  defp dispatch_frame(state, %{type: :headers, stream_id: id, flags: flags} = frame) do
    case Boundary.header_payload(frame) do
      {:ok, payload} ->
        cond do
          byte_size(payload) > 65_536 ->
            {:error, :header_block_too_large, state}

          Frame.flag?(flags, 0x4) ->
            decode_headers(state, id, payload, flags)

          true ->
            block = %{stream_id: id, fragments: [payload], flags: flags, size: byte_size(payload)}
            {:ok, %{state | connection: %{state.connection | header_block: block}}}
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp dispatch_frame(
         %{connection: %{header_block: %{stream_id: id} = block}} = state,
         %{type: :continuation, stream_id: id, payload: payload, flags: flags}
       ) do
    size = block.size + byte_size(payload)

    cond do
      size > 65_536 ->
        {:error, :header_block_too_large, state}

      Frame.flag?(flags, 0x4) ->
        encoded = block.fragments |> Enum.reverse() |> IO.iodata_to_binary() |> Kernel.<>(payload)
        state = %{state | connection: %{state.connection | header_block: nil}}
        decode_headers(state, id, encoded, block.flags ||| flags)

      true ->
        next = %{block | fragments: [payload | block.fragments], size: size}
        {:ok, %{state | connection: %{state.connection | header_block: next}}}
    end
  end

  defp dispatch_frame(%{connection: %{header_block: %{}}} = state, _frame),
    do: {:error, :expected_continuation, state}

  defp dispatch_frame(state, %{type: :continuation}),
    do: {:error, :unexpected_continuation, state}

  defp dispatch_frame(
         %{connection: connection} = state,
         %{type: :data, stream_id: id, payload: payload}
       )
       when id > 0 and rem(id, 2) == 1 and id < connection.next_stream_id and
              not is_map_key(connection.streams, id) do
    discard_closed_data(state, payload)
  end

  defp dispatch_frame(state, %{type: :data, stream_id: id, flags: flags} = frame) do
    with {:ok, payload, wire_bytes} <- Boundary.data_payload(frame),
         {:ok, connection, _effects} <-
           Connection.receive_data(state.connection, id, wire_bytes, Frame.flag?(flags, 1)) do
      state = %{state | connection: connection}

      case StreamState.receive_response_data(
             connection.streams[id],
             byte_size(payload),
             Frame.flag?(flags, 1)
           ) do
        {:ok, stream} ->
          state = %{state | connection: Connection.put_stream(connection, stream)}

          if payload == "" and not Frame.flag?(flags, 1),
            do: acknowledge_bytes(state, id, wire_bytes),
            else: queue_data(state, id, payload, flags, wire_bytes)

        {:error, reason} ->
          fail_stream(state, id, reason)
      end
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp dispatch_frame(state, _frame), do: {:ok, state}

  defp settings_failure(state, reason)
       when reason in [:invalid_enable_connect_protocol, :enable_connect_protocol_reversed] do
    # RFC 8441 section 3 requires a connection PROTOCOL_ERROR. No server-initiated
    # streams are processed by this client, so the GOAWAY last-stream ID is zero.
    case send_frames(state, [Frame.encode(:goaway, 0, 0, <<0::1, 0::31, 1::32>>)]) do
      {:ok, state} -> {:error, reason, state}
      {:error, _write_reason, state} -> {:error, reason, state}
    end
  end

  defp settings_failure(state, reason), do: {:error, reason, state}

  defp queue_data(state, id, payload, flags, wire_bytes) do
    entry = state.streams[id]

    case state.response_events do
      [{^id, {:http2, :data, previous, previous_flags}} | rest]
      when entry.byte_stream? and :erlang.band(previous_flags, 1) == 0 ->
        if :queue.len(entry.deliveries) >= 64 do
          {{:value, bytes}, deliveries} = :queue.out_r(entry.deliveries)

          state = %{
            state
            | response_events: [{id, {:http2, :data, previous <> payload, flags}} | rest]
          }

          state = put_in(state.streams[id].deliveries, :queue.in(bytes + wire_bytes, deliveries))
          return_connection_credit(state)
        else
          queue_delivery(state, id, payload, flags, wire_bytes)
        end

      _ ->
        queue_delivery(state, id, payload, flags, wire_bytes)
    end
  end

  defp queue_delivery(state, id, payload, flags, wire_bytes) do
    if :queue.len(state.streams[id].deliveries) >= 128 do
      fail_stream(state, id, :delivery_buffer_full)
    else
      state = %{
        state
        | response_events: [{id, {:http2, :data, payload, flags}} | state.response_events]
      }

      state = update_in(state.streams[id].deliveries, &:queue.in(wire_bytes, &1))
      return_connection_credit(state)
    end
  end

  defp acknowledge_bytes(state, _id, 0), do: {:ok, state}

  defp acknowledge_bytes(state, id, bytes) do
    case Connection.acknowledge_data(state.connection, id, bytes) do
      {:ok, connection, _effects} ->
        already_returned = min(bytes, state.returned_connection_credit)

        connection = %{
          connection
          | connection_receive_window: connection.connection_receive_window - already_returned
        }

        connection_bytes = bytes - already_returned
        effects = [{:window_update, id, bytes}]

        effects =
          if connection_bytes > 0,
            do: [{:window_update, 0, connection_bytes} | effects],
            else: effects

        state = %{
          state
          | connection: connection,
            returned_connection_credit: state.returned_connection_credit - already_returned
        }

        with {:ok, state} <- write_effects(state, effects), do: return_connection_credit(state)

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  # Connection credit may return on admission to the finite per-stream delivery
  # buffers. Stream credit returns only on consumption. Include unused on-wire
  # allowance in the global budget, so a peer cannot overrun it in flight.
  defp return_connection_credit(state) do
    emit_runtime(state, :receive_credit)
    connection = state.connection

    increment =
      Enum.min([
        connection.connection_unacknowledged - state.returned_connection_credit,
        state.max_receive_buffer_bytes - connection.connection_unacknowledged -
          connection.connection_receive_window,
        state.profile.connection_initial_window - connection.connection_receive_window
      ])

    if increment > 0 do
      {:ok, connection, _} = Connection.update_receive_window(connection, 0, increment)

      state = %{
        state
        | connection: connection,
          returned_connection_credit: state.returned_connection_credit + increment
      }

      write_effects(state, [{:window_update, 0, increment}])
    else
      {:ok, state}
    end
  end

  defp decode_headers(state, id, block, flags) do
    case HPACK.decode(state.connection.decoder, block) do
      {:ok, decoder, headers} ->
        state = %{state | connection: %{state.connection | decoder: decoder}}

        case Connection.stream(state.connection, id) do
          {:ok, stream} ->
            case StreamState.receive_response_headers(stream, headers, Frame.flag?(flags, 1)) do
              {:ok, stream, phase} ->
                state = %{state | connection: Connection.put_stream(state.connection, stream)}
                phase = upload_phase(stream, phase)
                state = stop_upload(state, id, phase)

                {:ok,
                 %{
                   state
                   | response_events: [
                       {id, {:http2, :headers, headers, flags}} | state.response_events
                     ]
                 }}

              {:error, reason} ->
                fail_stream(state, id, reason)
            end

          :error when rem(id, 2) == 1 and id < state.connection.next_stream_id ->
            {:ok, state}

          :error ->
            {:error, :protocol_error, state}
        end

      {:error, reason} ->
        {:error, {:hpack, reason}, state}
    end
  end

  defp discard_closed_data(state, payload) do
    # Discarded in-flight DATA still consumes and returns connection credit.
    size = byte_size(payload)

    cond do
      size > state.connection.connection_receive_window -> {:error, :flow_control_error, state}
      size == 0 -> {:ok, state}
      true -> write_effects(state, [{:window_update, 0, size}])
    end
  end

  defp fail_stream(state, id, reason) do
    state = terminal_stream(state, id, {:http2, :stream_error, reason})

    connection =
      Connection.put_stream(state.connection, StreamState.close(state.connection.streams[id]))

    send_frames(
      %{state | connection: connection},
      [Frame.encode(:rst_stream, 0, id, <<1::32>>)],
      :control
    )
  end

  defp dispatch_event(state, {:goaway, last}),
    do: dispatch_frame(state, %{type: :goaway, payload: <<0::1, last::31, 0::32>>})

  defp dispatch_event(state, {:bytes, bytes}) when is_binary(bytes) do
    case process_bytes(state, bytes) do
      {:reply, :ok, state} -> {:ok, state}
      {:reply, {:error, reason}, state} -> {:error, reason, state}
    end
  end

  defp dispatch_event(%{write_closed?: true} = state, {event, _bridge})
       when event == :body_eof,
       do: {:ok, state}

  defp dispatch_event(%{write_closed?: true} = state, {:body_chunk, _bridge, _chunk, _ack_ref}),
    do: {:ok, state}

  defp dispatch_event(state, {:body_chunk, bridge, chunk, ack_ref})
       when is_pid(bridge) and is_binary(chunk) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.body_bridge == bridge end) do
      {_id, %{upload_stopped?: true}} ->
        {:ok, state}

      {id, %{pending_body: nil}} ->
        state = put_in(state.streams[id].pending_body, {bridge, chunk, ack_ref})
        drain_pending_body(state, id)

      {_id, _entry} ->
        {:error, :body_buffer_full, state}

      nil ->
        {:ok, state}
    end
  end

  defp dispatch_event(state, {:data, id, data, end_stream?}) do
    with {:ok, connection, effects} <-
           Connection.send_data(state.connection, id, data, end_stream?),
         {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
      {:ok, state}
    else
      {:error, reason} -> {:error, reason, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp dispatch_event(state, {:body_eof, bridge}) when is_pid(bridge) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.body_bridge == bridge end) do
      {_id, %{upload_stopped?: true}} ->
        {:ok, state}

      {id, _entry} ->
        case Connection.send_data(state.connection, id, <<>>, true) do
          {:ok, connection, effects} ->
            write_effects(%{state | connection: connection}, effects)

          {:error, reason} ->
            {:error, reason, state}
        end

      nil ->
        {:ok, state}
    end
  end

  defp dispatch_event(state, {:body_error, bridge, reason}) when is_pid(bridge) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.body_bridge == bridge end) do
      {_id, %{upload_stopped?: true}} ->
        {:ok, state}

      {id, _entry} ->
        case Connection.cancel_headers(state.connection, id) do
          {:ok, connection, effects} ->
            case write_effects(%{state | connection: connection}, effects) do
              {:ok, state} ->
                {:ok, terminal_stream(state, id, {:http2, :body_error, reason})}

              {:error, write_reason, state} ->
                {:error, write_reason, state}
            end
        end

      nil ->
        {:ok, state}
    end
  end

  defp dispatch_event(state, _), do: {:ok, state}

  defp drain_pending_body(%{write_closed?: true} = state, _id), do: {:ok, state}

  defp drain_pending_body(state, 0) do
    ids =
      state.streams
      |> Enum.filter(fn {_id, entry} ->
        not is_nil(entry.pending_body) or not is_nil(entry.pending_write)
      end)
      |> Enum.map(&elem(&1, 0))

    {ids, scheduler} = Scheduler.ready(state.scheduler, ids)
    state = %{state | scheduler: scheduler}

    Enum.reduce_while(ids, {:ok, state}, fn id, {:ok, state} ->
      case drain_pending_body(state, id) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason, state} -> {:halt, {:error, reason, state}}
      end
    end)
  end

  defp drain_pending_body(state, id) do
    case get_in(state, [:streams, id, :pending_body]) do
      {bridge, chunk, ack_ref} ->
        quantum = min(state.profile.max_data_frame, 16_384)

        case Connection.send_data_prefix(state.connection, id, chunk, false, quantum) do
          {:ok, connection, _sent, rest, effects} ->
            with {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
              state = finish_upload_stall(state, id, :resumed)

              if rest == "" do
                send(bridge, {:body_ack, ack_ref})
                {:ok, put_in(state.streams[id].pending_body, nil)}
              else
                state =
                  put_in(state.streams[id].pending_body, {bridge, :binary.copy(rest), ack_ref})

                send(self(), :drain_bodies)
                {:ok, state}
              end
            end

          {:error, :flow_control_blocked} ->
            {:ok, start_upload_stall(state, id)}

          {:error, reason} ->
            send(bridge, {:body_error, reason})
            {:error, {:body_backpressure, reason}, state}
        end

      _ ->
        drain_pending_write(state, id)
    end
  end

  defp write_admission_reason(entry, stream, generation, data) do
    cond do
      is_nil(entry) or entry.ref != generation ->
        :unknown_stream

      stream.purpose != :extended_connect or stream.response_phase != :tunnel ->
        :extended_connect_not_established

      stream.end_stream_sent? ->
        :local_end

      entry.terminal? ->
        :closed

      not is_nil(entry.pending_write) ->
        :write_pending

      byte_size(data) > entry.max_write_bytes ->
        :write_buffer_full

      true ->
        nil
    end
  end

  defp drain_pending_write(state, id) do
    case get_in(state, [:streams, id, :pending_write]) do
      {ref, "", false} ->
        notify_stream(state, id, {:write, ref, :done})
        {:ok, put_in(state.streams[id].pending_write, nil)}

      {ref, data, end_stream?} ->
        quantum = min(state.profile.max_data_frame, 16_384)

        case Connection.send_data_prefix(state.connection, id, data, end_stream?, quantum) do
          {:ok, connection, sent, rest, effects} ->
            with {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
              if sent > 0, do: notify_stream(state, id, {:write, ref, {:progress, sent}})

              if rest == "" do
                notify_stream(state, id, {:write, ref, :done})
                {:ok, put_in(state.streams[id].pending_write, nil)}
              else
                send(self(), :drain_bodies)

                {:ok,
                 put_in(state.streams[id].pending_write, {ref, :binary.copy(rest), end_stream?})}
              end
            end

          {:error, :flow_control_blocked} ->
            {:ok, state}

          {:error, reason} ->
            notify_stream(state, id, {:write, ref, {:error, reason}})
            {:ok, put_in(state.streams[id].pending_write, nil)}
        end

      nil ->
        {:ok, state}
    end
  end

  defp set_transport_options(%{transport: transport, socket: socket}, options) do
    cond do
      is_map(transport) and is_function(transport[:setopts], 2) ->
        transport[:setopts].(socket, options)

      is_atom(transport) and function_exported?(transport, :setopts, 2) ->
        transport.setopts(socket, options)

      true ->
        :ok
    end
  end

  defp activate_socket(%{transport: transport, socket: socket} = state)
       when not is_nil(socket) do
    result =
      cond do
        is_map(transport) and is_function(transport[:setopts], 2) ->
          transport[:setopts].(socket, active: :once)

        is_atom(transport) and function_exported?(transport, :setopts, 2) ->
          transport.setopts(socket, active: :once)

        true ->
          :ok
      end

    case result do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp activate_socket(state), do: {:ok, state}

  defp normalize_transport(%{transport: transport, socket: socket}, message) do
    cond do
      is_map(transport) and is_function(transport[:normalize_message], 2) ->
        transport[:normalize_message].(message, socket)

      is_atom(transport) and function_exported?(transport, :normalize_message, 2) ->
        transport.normalize_message(message, socket)

      true ->
        :unknown
    end
  end

  defp notify_stream(state, id, message) do
    case state.streams[id] do
      %{pid: pid, terminal?: false} when is_pid(pid) -> send(pid, {:http2, id, message})
      _ -> :ok
    end
  end

  defp cancel_body_bridge(state, id) do
    case get_in(state, [:streams, id, :body_bridge]) do
      bridge when is_pid(bridge) ->
        GenServer.cast(bridge, :stop)
        :ok

      _ ->
        :ok
    end
  end

  defp upload_phase(%{response_phase: :tunnel}, _phase), do: :tunnel
  defp upload_phase(_stream, phase), do: phase

  defp stop_upload(state, _id, phase) when phase in [:informational, :tunnel], do: state

  defp stop_upload(state, id, _phase) do
    entry = state.streams[id]

    if entry.upload_stopped? do
      state
    else
      if is_pid(entry.body_bridge), do: GenServer.cast(entry.body_bridge, :early_response)

      state
      |> finish_upload_stall(id, :stopped)
      |> put_in([:streams, id], %{entry | upload_stopped?: true, pending_body: nil})
      |> Map.update!(:scheduler, &Scheduler.remove(&1, id))
    end
  end

  defp close_unfinished_upload(state, id) do
    stream = state.connection.streams[id]

    if stream.state != :closed and not stream.end_stream_sent? do
      {:ok, connection, effects} = Connection.cancel_headers(state.connection, id)

      case write_effects(%{state | connection: connection}, effects) do
        {:ok, state} -> state
        {:error, reason, state} -> %{state | lifecycle: :closed, close_reason: reason}
      end
    else
      state
    end
  end

  defp terminal_stream(state, id, message) do
    state = flush_byte_stream_events(state, id)
    state = finish_upload_stall(state, id, :stopped)
    notify_stream(state, id, message)
    stop_body_bridge(state, id)

    case state.streams[id] do
      nil ->
        state

      entry ->
        state
        |> put_in([:streams, id], %{
          entry
          | terminal?: true,
            upload_stopped?: true,
            pending_body: nil,
            pending_write: nil
        })
        |> Map.update!(:connection, fn connection ->
          Connection.put_stream(connection, StreamState.close(connection.streams[id]))
        end)
    end
  end

  defp flush_terminal_byte_event(state, id, event) do
    if get_in(state, [:streams, id, :byte_stream?]), do: notify_stream(state, id, event)
  end

  defp flush_byte_stream_events(state, id) do
    if get_in(state, [:streams, id, :byte_stream?]) do
      {pending, rest} = Enum.split_with(state.response_events, fn {stream, _} -> stream == id end)
      pending |> Enum.reverse() |> Enum.each(fn {_, event} -> notify_stream(state, id, event) end)
      %{state | response_events: rest}
    else
      state
    end
  end

  defp async_reply({:reply, _result, state}), do: {:noreply, state}
  defp async_reply({:stop, reason, _result, state}), do: {:stop, reason, state}

  defp notify_transport_error(%{lifecycle: :closed}, _reason), do: :ok

  defp notify_transport_error(state, reason),
    do: notify_all(state, {:http2, :transport_error, reason})

  defp notify_all(state, message),
    do: Enum.each(Map.keys(state.streams), &notify_stream(state, &1, message))

  defp stream_id(state, id) when is_integer(id),
    do: if(Map.has_key?(state.streams, id), do: {:ok, id}, else: :error)

  defp stream_id(state, ref) when is_reference(ref), do: Map.fetch(state.refs, ref)
  defp stream_id(_, _), do: :error

  defp runtime_measurements(state) do
    pending =
      Enum.reduce(state.streams, 0, fn
        {_id, %{pending_body: {_bridge, bytes, _ref}}}, total -> total + byte_size(bytes)
        {_id, %{pending_write: {_ref, bytes, _end}}}, total -> total + byte_size(bytes)
        _, total -> total
      end)

    %{
      active_streams: map_size(state.streams),
      protocol_streams: map_size(state.connection.streams),
      buffered_receive_bytes: state.connection.connection_unacknowledged,
      pending_upload_bytes: pending,
      receive_budget_bytes: state.max_receive_buffer_bytes,
      writer_batch_peak_bytes: state.queue_peak_bytes
    }
  end

  defp emit_runtime(state, event),
    do:
      HTTP.Runtime.Telemetry.http2_connection(event, state.lifecycle, runtime_measurements(state))

  defp start_upload_stall(state, id) do
    %{state | upload_stalls: Map.put_new(state.upload_stalls, id, System.monotonic_time())}
  end

  defp finish_upload_stall(state, id, outcome) do
    case Map.pop(state.upload_stalls, id) do
      {nil, _} ->
        state

      {started, stalls} ->
        emit_stall(started, outcome)
        %{state | upload_stalls: stalls}
    end
  end

  defp emit_stall(started, outcome) do
    duration_us =
      System.convert_time_unit(System.monotonic_time() - started, :native, :microsecond)

    HTTP.Runtime.Telemetry.http2_runtime(:flow_control_stall, outcome, %{
      count: 1,
      duration_us: duration_us
    })
  end

  defp close_category(nil), do: :normal
  defp close_category(:normal), do: :normal
  defp close_category(:closed), do: :transport_closed
  defp close_category(:settings_timeout), do: :settings_timeout
  defp close_category(:pool_down), do: :pool_down
  defp close_category(:drain_timeout), do: :drain_timeout
  defp close_category(:protocol_error), do: :protocol_error
  defp close_category(:flow_control_error), do: :flow_control_error
  defp close_category(_), do: :other_error

  defp report_capacity(%{pool: pool} = state) when is_pid(pool) do
    limit = state.connection.max_streams
    limit = if limit == :infinity, do: state.max_streams, else: min(limit, state.max_streams)

    if state.peer_settings? do
      GenServer.cast(
        pool,
        {:owner_settings, state.pool_key, self(),
         %{extended_connect: state.connection.peer.values.enable_connect_protocol == 1}, limit}
      )
    else
      GenServer.cast(pool, {:owner_capacity, state.pool_key, self(), limit})
    end
  end

  defp report_capacity(_), do: :ok

  defp stop_body_bridge(state, id) do
    case get_in(state.streams, [id, :body_bridge]) do
      pid when is_pid(pid) and pid != self() -> GenServer.cast(pid, :stop)
      _ -> :ok
    end
  end

  defp order_headers(profile, headers, purpose) do
    {pseudo, regular} =
      Enum.split_with(headers, fn {name, _} -> String.starts_with?(name, ":") end)

    WireProfile.order_headers(profile, pseudo, regular, purpose)
  end

  defp transport_send(%{transport: transport, socket: socket}, data) do
    cond do
      is_map(transport) and is_function(transport[:send], 2) -> transport.send.(socket, data)
      function_exported?(transport, :send, 2) -> transport.send(socket, data)
      true -> {:error, :invalid_transport}
    end
  end

  defp close_transport(%{transport: transport, socket: socket}) when not is_nil(socket) do
    cond do
      is_map(transport) and is_function(transport[:close], 1) -> transport.close.(socket)
      is_atom(transport) and function_exported?(transport, :close, 1) -> transport.close(socket)
      true -> :ok
    end
  end

  defp close_transport(_), do: :ok
end
