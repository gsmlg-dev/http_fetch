defmodule HTTP.HTTP2.ConnectionOwner do
  @moduledoc """
  Long-lived, single-writer HTTP/2 connection runtime.

  The protocol state remains in `HTTP.HTTP2.Connection`; this process owns the
  socket, serializes writes, and routes incoming frames to request owners.
  """
  use GenServer
  import Bitwise

  alias HTTP.HTTP2.{Connection, Frame, Scheduler, Settings, WireProfile}

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
          send_window: profile.connection_initial_window,
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
        init_settings: [],
        bytes: 0,
        max_queue_bytes: Keyword.get(opts, :max_queue_bytes, @default_queue_bytes),
        max_streams: Keyword.get(opts, :max_streams, @default_max_streams),
        wrote_preface?: false,
        close_reason: nil,
        activate?: Keyword.get(opts, :activate?, true),
        drain_timeout: Keyword.get(opts, :drain_timeout, @default_drain_timeout),
        drain_timer: nil
      }

      {:ok, state, {:continue, :initialize}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_continue(:initialize, state) do
    case initialize_wire(state) do
      {:ok, state} ->
        state = %{state | lifecycle: :ready}
        state = if state.activate?, do: activate_socket(state), else: state
        {:noreply, state}

      {:error, reason, state} ->
        {:stop, reason, state}
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
          {:reply, :ok, state} -> {:noreply, activate_socket(state)}
          {:reply, {:error, reason}, state} -> {:stop, reason, state}
        end

      :closed ->
        notify_all(state, {:http2, :transport_closed})
        {:noreply, %{state | lifecycle: :closed, close_reason: :closed}}

      {:error, reason} ->
        notify_all(state, {:http2, :transport_error, reason})
        {:stop, reason, state}

      :unknown ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply,
     Map.take(state, [:lifecycle, :profile_digest, :wrote_preface?, :bytes, :close_reason])
     |> Map.put(:stream_ids, Map.keys(state.streams)), state}
  end

  def handle_call(:activate, _from, state), do: {:reply, :ok, activate_socket(state)}

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
    request_ref = Keyword.get(opts, :request_ref, make_ref())

    with {:ok, stream, connection} <-
           Connection.open_stream(state.connection, request_ref: request_ref),
         ordered_headers <- order_headers(state.profile, headers),
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
              committed?: true,
              body_bridge: Keyword.get(opts, :body_bridge),
              pending_body: nil
            }),
          refs: Map.put(state.refs, request_ref, stream.id),
          scheduler: Scheduler.add(state.scheduler, stream.id)
      }

      {:reply, {:ok, result}, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      {:error, reason, _state} -> {:reply, {:error, reason}, state}
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
                notify_stream(state, id, {:http2, :cancelled})
                {:reply, :ok, %{state | connection: connection}}

              {:error, reason, state} ->
                {:reply, {:error, reason}, state}
            end
        end

      :error ->
        {:reply, {:error, :unknown_stream}, state}
    end
  end

  def handle_call({:release_stream, ref_or_id}, _from, state) do
    case stream_id(state, ref_or_id) do
      {:ok, id} ->
        ref = get_in(state, [:streams, id, :ref])

        state = %{
          state
          | streams: Map.delete(state.streams, id),
            refs: Map.delete(state.refs, ref),
            scheduler: Scheduler.remove(state.scheduler, id)
        }

        if state.lifecycle == :draining and map_size(state.streams) == 0 do
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
  def terminate(_reason, state) do
    close_transport(state)
    :ok
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
          send_frames(state, [Frame.encode(:rst_stream, 0, id, <<8::32>>)])

        {:settings, payload} ->
          send_frames(state, [Frame.encode(:settings, 0, 0, payload)])

        {:settings_ack, _entries} ->
          send_frames(state, [Frame.encode(:settings, 0x1, 0, <<>>)])

        {:data, _id, frame} ->
          send_frames(state, [frame])

        {:window_update, id, increment} ->
          send_frames(state, [Frame.encode(:window_update, 0, id, <<0::1, increment::31>>)])

        _ ->
          {:cont, {:ok, state}}
      end
      |> case do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason, state} -> {:halt, {:error, reason, state}}
      end
    end)
  end

  defp send_frames(state, frames) do
    bytes = IO.iodata_length(frames)

    if state.bytes + bytes > state.max_queue_bytes do
      {:error, :writer_queue_full, state}
    else
      case transport_send(state, frames) do
        :ok -> {:ok, %{state | bytes: max(state.bytes - bytes, 0)}}
        {:error, reason} -> {:error, reason, state}
      end
    end
  end

  defp process_bytes(state, bytes) do
    buffer = state.buffer <> bytes
    decode_frames(state, buffer)
  end

  defp decode_frames(state, buffer) do
    case Frame.decode(buffer) do
      :more ->
        {:reply, :ok, %{state | buffer: buffer}}

      {:ok, frame, rest} ->
        case dispatch_frame(state, frame) do
          {:ok, state} -> decode_frames(state, rest)
          {:error, reason, state} -> {:reply, {:error, reason}, state}
        end
    end
  end

  defp dispatch_frame(state, %{type: :settings, flags: flags, payload: payload}) do
    if Frame.flag?(flags, 0x1) do
      case Connection.acknowledge_settings(state.connection) do
        {:ok, connection, _} -> {:ok, %{state | connection: connection}}
        {:error, reason} -> {:error, reason, state}
      end
    else
      with {:ok, entries} <- Settings.decode(payload),
           {:ok, connection, effects} <-
             Connection.update_peer_settings(state.connection, entries),
           {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
        {:ok, %{state | connection: connection}}
      else
        {:error, reason} -> {:error, reason, state}
        {:error, reason, _} -> {:error, reason, state}
      end
    end
  end

  defp dispatch_frame(state, %{
         type: :goaway,
         payload: <<_reserved::1, last::31, _error::32, _debug::binary>>
       }) do
    case Connection.receive_goaway(state.connection, last) do
      {:ok, connection, _} ->
        notify_all(state, {:http2, :goaway, last})

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
    with {:ok, connection, _effects} <-
           Connection.priority_update(state.connection, 0, target_stream_id, value) do
      {:ok, %{state | connection: connection}}
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp dispatch_frame(state, %{type: :priority_update}),
    do: {:error, :invalid_priority_update, state}

  defp dispatch_frame(state, %{
         type: :window_update,
         stream_id: id,
         payload: <<0::1, increment::31>>
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

  defp dispatch_frame(state, %{type: :headers, stream_id: id, payload: payload, flags: flags}) do
    if state.connection.header_block do
      {:error, :expected_continuation, state}
    else
      if Frame.flag?(flags, 0x4) do
        decode_headers(state, id, payload, flags)
      else
        block = %{stream_id: id, fragments: [payload], flags: flags, size: byte_size(payload)}
        {:ok, %{state | connection: %{state.connection | header_block: block}}}
      end
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

  defp dispatch_frame(state, %{type: type, stream_id: id, payload: payload, flags: flags})
       when type in [:data] do
    ref = get_in(state, [:streams, id, :ref])
    end_stream? = Frame.flag?(flags, 0x1)

    with {:ok, connection, effects} <-
           Connection.receive_data(state.connection, id, byte_size(payload), end_stream?),
         {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
      if ref, do: notify_stream(state, id, {:http2, type, payload, flags}), else: :ok
      {:ok, state}
    else
      {:error, :closed, _state} ->
        if ref, do: notify_stream(state, id, {:http2, type, payload, flags}), else: :ok
        {:ok, state}

      {:error, :stream_closed} ->
        if ref, do: notify_stream(state, id, {:http2, type, payload, flags}), else: :ok
        {:ok, state}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp dispatch_frame(state, _frame), do: {:ok, state}

  defp decode_headers(state, id, block, flags) do
    case HTTP.HTTP2.HPACK.decode(state.connection.decoder, block) do
      {:ok, decoder, headers} ->
        state = %{state | connection: %{state.connection | decoder: decoder}}
        ref = get_in(state, [:streams, id, :ref])
        if ref, do: notify_stream(state, id, {:http2, :headers, headers, flags}), else: :ok
        {:ok, state}

      {:error, reason} ->
        {:error, {:hpack, reason}, state}
    end
  end

  defp dispatch_event(state, {:goaway, last}),
    do: dispatch_frame(state, %{type: :goaway, payload: <<0::1, last::31, 0::32>>})

  defp dispatch_event(state, {:bytes, bytes}) when is_binary(bytes) do
    case process_bytes(state, bytes) do
      {:reply, :ok, state} -> {:ok, state}
      {:reply, {:error, reason}, state} -> {:error, reason, state}
    end
  end

  defp dispatch_event(state, {:body_chunk, bridge, chunk, ack_ref})
       when is_pid(bridge) and is_binary(chunk) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.body_bridge == bridge end) do
      {id, _entry} ->
        case Connection.send_data(state.connection, id, chunk) do
          {:ok, connection, effects} ->
            with {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
              send(bridge, {:body_ack, ack_ref})
              {:ok, state}
            end

          {:error, :flow_control_blocked} ->
            streams =
              update_in(state.streams, [id, :pending_body], fn _ -> {bridge, chunk, ack_ref} end)

            {:ok, %{state | streams: streams, scheduler: Scheduler.add(state.scheduler, id)}}

          {:error, reason} ->
            send(bridge, {:body_error, reason})
            {:error, {:body_backpressure, reason}, state}
        end

      nil ->
        {:error, :unknown_body_bridge, state}
    end
  end

  defp dispatch_event(state, {:data, id, data, end_stream?}) do
    with {:ok, connection, effects} <-
           Connection.send_data(state.connection, id, data, end_stream?),
         {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
      {:ok, state}
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp dispatch_event(state, {:body_eof, bridge}) when is_pid(bridge) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.body_bridge == bridge end) do
      {id, _entry} ->
        case Connection.send_data(state.connection, id, <<>>, true) do
          {:ok, connection, effects} ->
            with {:ok, state} <- write_effects(%{state | connection: connection}, effects),
                 do: {:ok, state}

          {:error, reason} ->
            {:error, reason, state}
        end

      nil ->
        {:error, :unknown_body_bridge, state}
    end
  end

  defp dispatch_event(state, {:body_error, bridge, reason}) when is_pid(bridge) do
    case Enum.find(state.streams, fn {_id, entry} -> entry.body_bridge == bridge end) do
      {id, _entry} ->
        case Connection.cancel_headers(state.connection, id) do
          {:ok, connection, effects} ->
            case write_effects(%{state | connection: connection}, effects) do
              {:ok, state} ->
                notify_stream(state, id, {:http2, :body_error, reason})
                {:ok, state}

              {:error, write_reason, state} ->
                {:error, write_reason, state}
            end
        end

      nil ->
        {:error, :unknown_body_bridge, state}
    end
  end

  defp dispatch_event(state, _), do: {:ok, state}

  defp drain_pending_body(state, 0) do
    ids =
      state.streams
      |> Enum.filter(fn {_id, entry} -> not is_nil(entry.pending_body) end)
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
        case Connection.send_data(state.connection, id, chunk) do
          {:ok, connection, effects} ->
            with {:ok, state} <- write_effects(%{state | connection: connection}, effects) do
              send(bridge, {:body_ack, ack_ref})
              {:ok, put_in(state.streams[id].pending_body, nil)}
            end

          {:error, :flow_control_blocked} ->
            {:ok, state}

          {:error, reason} ->
            send(bridge, {:body_error, reason})
            {:error, {:body_backpressure, reason}, state}
        end

      _ ->
        {:ok, state}
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
      :ok -> state
      {:error, reason} -> %{state | lifecycle: :closed, close_reason: reason}
    end
  end

  defp activate_socket(state), do: state

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
    case get_in(state, [:streams, id, :pid]) do
      pid when is_pid(pid) -> send(pid, {:http2, id, message})
      _ -> :ok
    end
  end

  defp cancel_body_bridge(state, id) do
    case get_in(state, [:streams, id, :body_bridge]) do
      bridge when is_pid(bridge) ->
        _ = HTTP.HTTP2.BodyBridge.cancel(bridge)
        :ok

      _ ->
        :ok
    end
  end

  defp notify_all(state, message),
    do: Enum.each(Map.keys(state.streams), &notify_stream(state, &1, message))

  defp stream_id(state, id) when is_integer(id),
    do: if(Map.has_key?(state.streams, id), do: {:ok, id}, else: :error)

  defp stream_id(state, ref) when is_reference(ref), do: Map.fetch(state.refs, ref)
  defp stream_id(_, _), do: :error

  defp order_headers(profile, headers) do
    {pseudo, regular} =
      Enum.split_with(headers, fn {name, _} -> String.starts_with?(name, ":") end)

    WireProfile.order_headers(profile, pseudo, regular)
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
