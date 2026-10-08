defmodule HTTP.WebSocket.Connection do
  @moduledoc false

  use GenServer

  alias HTTP.WebSocket
  alias HTTP.WebSocket.ArrayBuffer
  alias HTTP.WebSocket.Event.Close
  alias HTTP.WebSocket.Event.Error
  alias HTTP.WebSocket.Event.Message
  alias HTTP.WebSocket.Event.Open
  alias HTTP.WebSocket.Frame
  alias HTTP.WebSocket.Handshake
  alias HTTP.WebSocket.Options
  alias HTTP.WebSocket.Telemetry

  @connecting WebSocket.connecting()
  @open WebSocket.open()
  @closing WebSocket.closing()
  @closed WebSocket.closed()
  alias HTTP.Runtime.Delivery
  alias HTTP.Runtime.Stream

  defstruct options: nil,
            owner: nil,
            target: nil,
            uri: nil,
            telemetry_uri: nil,
            generation: nil,
            stream: nil,
            stream_monitor: nil,
            stream_handle: nil,
            worker: nil,
            worker_monitor: nil,
            transport: nil,
            socket: nil,
            http_version: nil,
            fallback?: false,
            ready_state: @connecting,
            parser: nil,
            protocol: "",
            extensions: "",
            binary_type: :blob,
            delivery: nil,
            raw_queue: :queue.new(),
            raw_bytes: 0,
            app_queue: :queue.new(),
            control_queue: :queue.new(),
            write: nil,
            buffered_amount: 0,
            pending_send_frames: 0,
            control_frames: 0,
            close_sent?: false,
            close_received?: false,
            local_end?: false,
            remote_end?: false,
            terminal: nil,
            close_code: nil,
            close_reason: "",
            opening_timer: nil,
            idle_timer: nil,
            close_timer: nil,
            connect_started_at: nil,
            opening_deadline: :infinity

  @spec start_link(Options.t()) :: GenServer.on_start()
  def start_link(%Options{} = options), do: GenServer.start_link(__MODULE__, options)

  def child_spec(%Options{ref: ref} = options) do
    %{
      id: {__MODULE__, ref},
      start: {__MODULE__, :start_link, [options]},
      restart: :temporary,
      type: :worker
    }
  end

  @impl true
  def init(%Options{} = options) do
    HTTP.OwnerMonitor.start(self(), options.owner)

    state = %__MODULE__{
      options: options,
      owner: options.owner,
      uri: options.uri,
      telemetry_uri:
        if(options.telemetry_url == :default, do: options.uri, else: options.telemetry_url),
      target: %WebSocket{pid: self(), ref: options.ref, url: options.url},
      binary_type: options.binary_type,
      delivery: Delivery.new(options),
      parser:
        Frame.new_parser(
          max_message_size: options.max_message_size,
          max_frame_parts: options.max_frame_parts
        )
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    Telemetry.connect_start(state.telemetry_uri)

    state = %{
      state
      | generation: make_ref(),
        connect_started_at: now(),
        opening_deadline: deadline(state.options.opening_timeout)
    }

    state = timer(state, :opening_timer, :opening_timeout, remaining(state.opening_deadline))

    if HTTP.Runtime.Options.h2?(state.options),
      do: connect_http2(state),
      else: {:noreply, connect_http1(state)}
  end

  @impl true
  def handle_call(:ready_state, _from, state), do: {:reply, state.ready_state, state}
  def handle_call(:buffered_amount, _from, state), do: {:reply, state.buffered_amount, state}
  def handle_call(:extensions, _from, state), do: {:reply, state.extensions, state}
  def handle_call(:protocol, _from, state), do: {:reply, state.protocol, state}
  def handle_call(:http_version, _from, state), do: {:reply, state.http_version, state}
  def handle_call(:binary_type, _from, state), do: {:reply, state.binary_type, state}

  def handle_call(:status, _from, state) do
    status =
      Map.merge(
        Delivery.status(state.delivery),
        Map.take(state, [
          :http_version,
          :ready_state,
          :buffered_amount,
          :raw_bytes,
          :pending_send_frames,
          :control_frames,
          :fallback?,
          :stream_handle
        ])
      )

    {:reply, status, state}
  end

  def handle_call({:set_binary_type, type}, _from, state),
    do: {:reply, :ok, %{state | binary_type: type}}

  def handle_call({:acknowledge, ref}, _from, state) do
    {:ok, delivery, events} = Delivery.acknowledge(state.delivery, ref)
    state = %{state | delivery: delivery}
    emit_deliveries(state, events)
    state = state |> drain_raw() |> reset_idle()
    stream_telemetry(state, :queue, :settled)
    call_result(:ok, advance(state))
  end

  def handle_call({:send, _data}, _from, %{ready_state: @connecting} = state),
    do: {:reply, {:error, :invalid_state}, state}

  def handle_call({:send, data}, _from, %{ready_state: ready} = state)
      when ready in [@closing, @closed] do
    case payload_size(data) do
      {:ok, bytes} -> {:reply, :ok, %{state | buffered_amount: state.buffered_amount + bytes}}
      error -> {:reply, error, state}
    end
  end

  def handle_call({:send, data}, _from, state) do
    with {:ok, opcode, payload, bytes} <- normalize_send_data(data),
         :ok <- send_capacity(state, bytes),
         {:ok, frame} <- Frame.encode(opcode, payload) do
      item = %{frame: frame, bytes: bytes, opcode: opcode, kind: :app}

      state = %{
        state
        | app_queue: :queue.in(item, state.app_queue),
          buffered_amount: state.buffered_amount + bytes,
          pending_send_frames: state.pending_send_frames + 1
      }

      state = pump_send(state)
      stream_telemetry(state, :queue, :send_admitted)
      call_result(:ok, advance(state))
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:close, code, reason, _payload}, _from, %{ready_state: @connecting} = state) do
    Telemetry.close_start(state.telemetry_uri, code)
    {:stop, :normal, :ok, finish(state, code || 1006, reason, false)}
  end

  def handle_call({:close, _code, _reason, _payload}, _from, %{ready_state: @closing} = state),
    do: {:reply, :ok, state}

  def handle_call({:close, code, reason, payload}, _from, state) do
    Telemetry.close_start(state.telemetry_uri, code)
    state = begin_close(state, code, reason, payload)
    call_result(:ok, advance(state))
  end

  @impl true
  def handle_info(
        {:opening_timeout, token},
        %{opening_timer: {_timer, token}, ready_state: @connecting} = state
      ),
      do: fail(state, if(state.stream, do: :opening_timeout, else: :timeout))

  def handle_info({:idle_timeout, token}, %{idle_timer: {_timer, token}} = state),
    do: transport_terminal(state, :idle_timeout)

  def handle_info({:close_timeout, token}, %{close_timer: {_timer, token}} = state) do
    state = %{
      state
      | terminal: timeout_terminal(state),
        raw_queue: :queue.new(),
        raw_bytes: 0
    }

    state = detach(state)
    advance(%{state | remote_end?: true, local_end?: true})
  end

  def handle_info(
        {:http1_ready, generation, worker, transport, socket},
        %{generation: generation, worker: worker} = state
      ) do
    send(worker, :transfer)
    {:noreply, %{state | transport: transport, socket: socket}}
  end

  def handle_info({:http1_ready, _generation, worker, transport, socket}, state) do
    send(worker, :cancel)
    transport.close(socket)
    {:noreply, state}
  end

  def handle_info(
        {:http1_connected, generation, worker, result},
        %{generation: generation, worker: worker} = state
      ) do
    send(worker, :accepted)
    Process.demonitor(state.worker_monitor, [:flush])
    state = %{state | worker: nil, worker_monitor: nil}

    case result do
      {:ok, negotiated, extra} ->
        state = established(state, negotiated, :http1)
        advance(admit_raw(state, extra, nil, :front))

      {:closed, negotiated, extra} ->
        state = established(%{state | remote_end?: true}, negotiated, :http1)
        advance(admit_raw(state, extra, nil, :front))

      {:error, reason} ->
        fail(state, reason)
    end
  end

  def handle_info(
        {:http_runtime, generation, pid, event},
        %{generation: generation, stream: pid} = state
      ),
      do: stream_event(state, event)

  def handle_info(
        {:DOWN, monitor, :process, pid, reason},
        %{worker_monitor: monitor, worker: pid} = state
      ),
      do: fail(state, {:connect_worker_down, reason})

  def handle_info(
        {:DOWN, monitor, :process, pid, reason},
        %{stream_monitor: monitor, stream: pid} = state
      ) do
    if state.local_end? and state.remote_end?,
      do: advance(%{state | stream_monitor: nil}),
      else: transport_terminal(state, {:stream_down, reason})
  end

  def handle_info(message, %{transport: transport, socket: socket} = state)
      when not is_nil(transport) and not is_nil(socket) do
    case transport.normalize_message(message, socket) do
      {:data, data} -> advance(state |> admit_raw(data, nil) |> reset_idle())
      :closed -> advance(%{state | remote_end?: true})
      {:error, reason} -> transport_terminal(state, reason)
      :unknown -> {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = detach(state)
    :ok
  end

  defp connect_http2(state) do
    with {:ok, request} <-
           Handshake.extended_connect_request(
             state.uri,
             state.options.protocols,
             state.options.headers
           ),
         request = %{
           request
           | transport_options: HTTP.Runtime.Options.transport_options(state.options)
         },
         {:ok, pid, _generation} <-
           Stream.start(request, self(),
             purpose: :extended_connect,
             generation: state.generation,
             opening_timeout: remaining(state.opening_deadline),
             max_write_bytes: max(state.options.max_send_queue + 14, 131)
           ) do
      {:noreply, %{state | stream: pid, stream_monitor: Process.monitor(pid)}}
    else
      {:error, reason} -> fail(state, reason)
    end
  end

  defp connect_http1(state) do
    parent = self()

    {:ok, worker} =
      Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
        HTTP.OwnerMonitor.start(self(), parent)
        result = http1_open(state, parent)
        send(parent, {:http1_connected, state.generation, self(), result})

        receive do
          :accepted -> :ok
        after
          30_000 -> :ok
        end
      end)

    %{state | worker: worker, worker_monitor: Process.monitor(worker)}
  end

  defp http1_open(state, parent) do
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    with {:ok, request} <-
           Handshake.build_request(state.uri, state.options.protocols, state.options.headers, key),
         {:ok, transport, host, port} <- select_transport(state),
         {:ok, socket} <-
           transport.connect(
             host,
             port,
             [ssl: http1_ssl(state), socket_opts: state.options.socket_opts],
             bounded_timeout(state.options.connect_timeout, remaining(state.opening_deadline))
           ) do
      result =
        with :ok <- transport.send(socket, request),
             {:ok, status, headers, extra} <-
               recv_handshake(transport, socket, <<>>, state.opening_deadline),
             {:ok, negotiated} <-
               Handshake.validate_response(status, headers, key, state.options.protocols) do
          send(parent, {:http1_ready, state.generation, self(), transport, socket})

          receive do
            :transfer ->
              case transport.controlling_process(socket, parent) do
                :ok -> {:ok, negotiated, extra}
                # Upgrade validation and buffered frames precede this terminal outcome.
                {:error, :closed} -> {:closed, negotiated, extra}
                error -> error
              end

            :cancel ->
              {:error, :aborted}
          after
            remaining(state.opening_deadline) -> {:error, :timeout}
          end
        end

      if match?({:error, _}, result), do: transport.close(socket)
      result
    end
  end

  defp select_transport(%{options: %{unix_socket: path}}) when is_binary(path),
    do: {:ok, HTTP.Transport.Unix, path, 0}

  defp select_transport(%{uri: %{scheme: "ws", host: host, port: port}}),
    do: {:ok, HTTP.Transport.TCP, host, port || 80}

  defp select_transport(%{
         uri: %{scheme: "wss", host: host, port: port},
         options: %{tls_backend: backend}
       }),
       do: {:ok, HTTP.TLSBackend.transport(backend), host, port || 443}

  defp http1_ssl(%{uri: %{scheme: "wss"}, options: options}),
    do: Keyword.put(options.ssl, :alpn_advertised_protocols, ["http/1.1"])

  defp http1_ssl(state), do: state.options.ssl

  defp recv_handshake(transport, socket, buffer, deadline) do
    case Handshake.parse_response(buffer) do
      {:more, buffer} ->
        with {:ok, data} <- transport.recv(socket, 0, remaining(deadline)),
             do: recv_handshake(transport, socket, buffer <> data, deadline)

      result ->
        result
    end
  end

  defp stream_event(state, {:opened, handle}), do: {:noreply, %{state | stream_handle: handle}}

  defp stream_event(%{ready_state: @connecting} = state, {:headers, headers, _flags}) do
    {pseudo, ordinary} =
      Enum.split_with(headers, fn {name, _} -> String.starts_with?(name, ":") end)

    with [{":status", text}] <- pseudo,
         {status, ""} <- Integer.parse(text),
         true <- status >= 200 or {:informational, status},
         {:ok, negotiated} <-
           Handshake.validate_extended_response(status, ordinary, state.options.protocols) do
      advance(established(state, negotiated, :http2))
    else
      {:informational, status} when status != 101 -> {:noreply, state}
      {:error, reason} -> fail(state, reason)
      _ -> fail(state, :invalid_http2_status)
    end
  end

  defp stream_event(state, {:headers, _headers, _flags}),
    do: transport_terminal(state, :unexpected_headers)

  defp stream_event(%{ready_state: @connecting} = state, {:data, _data, _flags, _ref}),
    do: fail(state, :body_before_response)

  defp stream_event(state, {:data, data, _flags, ref}),
    do: advance(state |> admit_raw(data, {state.stream, ref}) |> reset_idle())

  defp stream_event(state, :remote_end), do: advance(%{state | remote_end?: true})
  defp stream_event(state, {:goaway, _last, _error}), do: {:noreply, state}
  defp stream_event(state, {:write, ref, event}), do: write_event(state, ref, event)

  defp stream_event(%{ready_state: @connecting} = state, {:error, reason})
       when reason in [:http1_negotiated, :extended_connect_not_supported] do
    if state.options.http_version == :auto and not state.fallback? and
         is_nil(state.options.http2_profile) do
      state = detach_stream(state)
      stream_telemetry(state, :fallback, reason)
      {:noreply, connect_http1(%{state | fallback?: true})}
    else
      fail(state, reason)
    end
  end

  defp stream_event(%{ready_state: @connecting} = state, {:error, reason}),
    do: fail(state, reason)

  defp stream_event(state, {:terminal, reason}), do: transport_terminal(state, reason)
  defp stream_event(state, {:error, reason}), do: transport_terminal(state, reason)

  defp established(state, negotiated, version) do
    state = state |> cancel_timer(:opening_timer)

    Telemetry.connect_stop(
      state.telemetry_uri,
      negotiated.protocol,
      now() - state.connect_started_at,
      version,
      state.fallback?
    )

    emit(state, %Open{target: state.target})

    state = %{
      state
      | ready_state: @open,
        http_version: version,
        protocol: negotiated.protocol,
        extensions: negotiated.extensions
    }

    stream_telemetry(state, :open, :accepted)
    reset_idle(state)
  end

  defp send_capacity(state, bytes) do
    if state.buffered_amount + bytes <= state.options.max_send_queue and
         state.pending_send_frames < state.options.max_send_frames,
       do: :ok,
       else: {:error, :send_queue_full}
  end

  defp pump_send(%{write: write} = state) when not is_nil(write), do: state

  defp pump_send(state) do
    case :queue.out(state.control_queue) do
      {{:value, item}, rest} ->
        submit(%{state | control_queue: rest}, item)

      {:empty, _} ->
        case :queue.out(state.app_queue) do
          {{:value, item}, rest} -> submit(%{state | app_queue: rest}, item)
          {:empty, _} -> state
        end
    end
  end

  defp submit(%{stream: stream} = state, item) when is_pid(stream) do
    ref = Stream.write(stream, item.frame)

    write =
      item
      |> Map.delete(:frame)
      |> Map.merge(%{
        ref: ref,
        overhead: byte_size(item.frame) - item.bytes,
        remaining: item.bytes
      })

    %{state | write: write}
  end

  defp submit(state, item) do
    case state.transport.send(state.socket, item.frame) do
      :ok ->
        state |> complete_item(item) |> pump_send()

      {:error, :closed}
      when item.kind == :close and state.http_version == :http1 and state.close_received? ->
        # Preserve HTTP/1's complete peer Close classification after peer EOF.
        complete_item(state, item)

      {:error, reason} ->
        park_terminal(state, reason, 1006, "", false)
    end
  end

  defp write_event(%{write: %{ref: ref} = write} = state, ref, {:progress, sent}) do
    overhead = max(write.overhead - sent, 0)
    payload = min(max(sent - write.overhead, 0), write.remaining)

    state = %{
      state
      | write: %{write | overhead: overhead, remaining: write.remaining - payload},
        buffered_amount: state.buffered_amount - payload
    }

    advance(state)
  end

  defp write_event(%{write: %{ref: ref, kind: :half_close}} = state, ref, :done),
    do: advance(%{state | write: nil, local_end?: true})

  defp write_event(%{write: %{ref: ref} = write} = state, ref, :done) do
    state = %{
      state
      | write: nil,
        buffered_amount: state.buffered_amount + write.bytes - write.remaining
    }

    state = complete_item(state, write)

    state =
      if write.kind == :close and state.close_received?,
        do: half_close(state),
        else: pump_send(state)

    advance(state)
  end

  defp write_event(%{write: %{ref: ref}} = state, ref, {:error, reason}),
    do: transport_terminal(state, reason)

  defp write_event(state, _ref, _event), do: {:noreply, state}

  defp complete_item(state, %{kind: :app} = item) do
    Telemetry.message_sent(
      state.telemetry_uri,
      Atom.to_string(item.opcode),
      item.bytes,
      max(state.buffered_amount - item.bytes, 0)
    )

    %{
      state
      | pending_send_frames: state.pending_send_frames - 1,
        buffered_amount: max(state.buffered_amount - item.bytes, 0)
    }
  end

  defp complete_item(state, %{kind: :close}),
    do: %{state | close_sent?: true, control_frames: state.control_frames - 1}

  defp complete_item(state, _item), do: %{state | control_frames: state.control_frames - 1}

  defp half_close(%{stream: stream} = state) when is_pid(stream) do
    ref = Stream.half_close(stream)
    %{state | write: %{ref: ref, kind: :half_close, overhead: 0, remaining: 0}}
  end

  defp half_close(state), do: %{state | local_end?: true}

  defp queue_control(state, opcode, payload) do
    if state.control_frames >= state.options.max_control_frames do
      park_terminal(state, :control_queue_full, 1006, "", false)
    else
      {:ok, frame} = Frame.encode(opcode, payload)

      item = %{
        frame: frame,
        bytes: 0,
        opcode: opcode,
        kind: if(opcode == :close, do: :close, else: :control)
      }

      pump_send(%{
        state
        | control_queue: :queue.in(item, state.control_queue),
          control_frames: state.control_frames + 1
      })
    end
  end

  # Local close completes the current frame, discards unsent application frames,
  # then sends Close. Control priority never splices a partially written frame.
  defp begin_close(state, code, reason, payload) do
    queued_bytes = Enum.reduce(:queue.to_list(state.app_queue), 0, &(&1.bytes + &2))

    state = %{
      state
      | ready_state: @closing,
        close_code: code,
        close_reason: reason,
        buffered_amount: state.buffered_amount - queued_bytes,
        pending_send_frames: state.pending_send_frames - :queue.len(state.app_queue),
        app_queue: :queue.new()
    }

    state =
      state
      |> cancel_timer(:idle_timer)
      |> timer(:close_timer, :close_timeout, state.options.close_timeout)

    queue_control(state, :close, payload)
  end

  defp admit_raw(state, data, ref, position \\ :back)

  defp admit_raw(state, <<>>, ref, _position), do: settle_raw(state, <<>>, ref)

  defp admit_raw(state, data, ref, position) do
    if state.raw_bytes + byte_size(data) > raw_limit(state) do
      park_terminal(state, :consumer_overloaded, 1006, "", false)
    else
      ref =
        if ref && state.raw_bytes + byte_size(data) <= 1_048_576 do
          Stream.acknowledge(elem(ref, 0), elem(ref, 1))
          nil
        else
          ref
        end

      state = %{
        state
        | raw_queue:
            if(position == :front,
              do: :queue.in_r({:binary.copy(data), ref}, state.raw_queue),
              else: pack_raw(state.raw_queue, :binary.copy(data), ref)
            ),
          raw_bytes: state.raw_bytes + byte_size(data)
      }

      if :queue.len(state.raw_queue) > 128,
        do: park_terminal(state, :consumer_overloaded, 1006, "", false),
        else: drain_raw(state)
    end
  end

  defp pack_raw(queue, data, nil) do
    case :queue.out_r(queue) do
      {{:value, {previous, nil}}, rest} when byte_size(previous) + byte_size(data) <= 65_536 ->
        :queue.in({previous <> data, nil}, rest)

      _ ->
        :queue.in({data, nil}, queue)
    end
  end

  defp pack_raw(queue, data, ref), do: :queue.in({data, ref}, queue)

  defp raw_limit(state) do
    profile = state.options.http2_profile || HTTP.HTTP2.WireProfile.native_v1()
    settings = Map.new(profile.settings)
    1_048_576 + Map.get(settings, :initial_window_size, Map.get(settings, 4, 65_535))
  end

  defp parser_capacity?(%{options: %{delivery: :legacy}}), do: true

  defp parser_capacity?(state) do
    status = Delivery.status(state.delivery)

    status.queued_events < state.options.max_queue_events and
      status.queued_bytes + state.options.max_message_size + 7 <= state.options.max_queue_bytes
  end

  defp drain_raw(%{close_received?: true} = state) do
    Enum.each(:queue.to_list(state.raw_queue), fn {_data, ref} ->
      if ref, do: Stream.acknowledge(elem(ref, 0), elem(ref, 1))
    end)

    %{state | raw_queue: :queue.new(), raw_bytes: 0}
  end

  defp drain_raw(%{http_version: nil, worker: worker} = state) when is_pid(worker), do: state

  defp drain_raw(state) do
    if parser_capacity?(state) do
      case :queue.out(state.raw_queue) do
        {:empty, _} ->
          state

        {{:value, {data, ref}}, queue} ->
          state = %{state | raw_queue: queue, raw_bytes: state.raw_bytes - byte_size(data)}
          parse_raw(state, data, ref)
      end
    else
      stream_telemetry(state, :queue, :paused)
      state
    end
  end

  defp parse_raw(state, data, ref) do
    case Frame.parse_some(state.parser, data) do
      {:ok, parser, events, rest} ->
        parser = %{parser | buffer: :binary.copy(parser.buffer)}
        previous_terminal = state.terminal
        state = frame_events(%{state | parser: parser}, events)

        if is_nil(previous_terminal) and not is_nil(state.terminal) do
          discard_raw(state, ref)
        else
          state = settle_raw(state, rest, ref)

          if match?({_, _, _, true}, state.terminal) or state.close_received?,
            do: drain_closed(state),
            else: drain_raw(state)
        end

      {:error, {code, reason}} ->
        if ref, do: Stream.acknowledge(elem(ref, 0), elem(ref, 1))
        protocol_error(state, code, reason)
    end
  end

  defp discard_raw(state, ref) do
    Enum.each(:queue.to_list(state.raw_queue), fn {_data, queued_ref} ->
      if queued_ref, do: Stream.acknowledge(elem(queued_ref, 0), elem(queued_ref, 1))
    end)

    if ref, do: Stream.acknowledge(elem(ref, 0), elem(ref, 1))
    %{state | raw_queue: :queue.new(), raw_bytes: 0}
  end

  defp drain_closed(%{close_received?: true} = state), do: drain_raw(state)
  defp drain_closed(state), do: state

  defp protocol_error(state, code, reason) do
    state = %{state | raw_queue: :queue.new(), raw_bytes: 0}

    if state.terminal do
      state
    else
      {:ok, payload} = Frame.protocol_close_payload(code, Atom.to_string(reason))
      state = %{state | terminal: {reason, code, Atom.to_string(reason), true}}
      begin_close(state, code, Atom.to_string(reason), payload)
    end
  end

  defp settle_raw(state, <<>>, ref) do
    if ref, do: Stream.acknowledge(elem(ref, 0), elem(ref, 1))
    state
  end

  defp settle_raw(state, rest, ref),
    do: %{
      state
      | raw_queue: :queue.in_r({:binary.copy(rest), ref}, state.raw_queue),
        raw_bytes: state.raw_bytes + byte_size(rest)
    }

  defp frame_events(state, []), do: state

  defp frame_events(state, [{:message, opcode, data}]) do
    data = :binary.copy(data)

    message = %Message{
      target: state.target,
      data: message_payload(opcode, data, state.binary_type),
      origin: origin(state)
    }

    case Delivery.push(state.delivery, message, byte_size(data) + 7, state.owner) do
      {:ok, delivery, events} ->
        Telemetry.message_received(state.telemetry_uri, Atom.to_string(opcode), byte_size(data))
        emit_deliveries(state, events)
        state = %{state | delivery: delivery}
        stream_telemetry(state, :queue, :receive_admitted)
        state

      {:error, reason} ->
        park_terminal(state, reason, 1006, "", false)
    end
  end

  defp frame_events(%{terminal: terminal} = state, [{:ping, _payload}]) when not is_nil(terminal),
    do: state

  defp frame_events(state, [{:ping, payload}]), do: queue_control(state, :pong, payload)
  defp frame_events(state, [{:pong, _payload}]), do: state

  defp frame_events(state, [{:close, code, reason}]) do
    state = %{state | close_received?: true, close_code: code, close_reason: reason}

    if state.ready_state == @closing do
      if state.close_sent? and is_nil(state.write) and is_nil(state.terminal),
        do: half_close(state),
        else: state
    else
      {:ok, payload} = Frame.protocol_close_payload(code, reason)
      begin_close(state, code, reason, payload)
    end
  end

  defp timeout_terminal(%{terminal: {reason, _code, _text, true}, close_sent?: false}),
    do: {reason, 1006, "", false}

  defp timeout_terminal(state), do: state.terminal || {nil, 1006, "", false}

  defp transport_terminal(%{http_version: nil, worker: worker} = state, reason)
       when is_pid(worker),
       do: {:noreply, park_terminal(state, reason, 1006, "", false)}

  defp transport_terminal(state, reason) do
    state = state |> park_terminal(reason, 1006, "", false) |> detach()
    advance(state)
  end

  defp park_terminal(state, reason, code, text, require_write?) do
    %{
      state
      | terminal: state.terminal || {reason, code, text, require_write?},
        remote_end?: true,
        ready_state:
          if(is_nil(state.http_version) and is_pid(state.worker),
            do: state.ready_state,
            else: @closing
          )
    }
    |> cancel_timer(:idle_timer)
  end

  defp advance(%{http_version: nil, worker: worker} = state) when is_pid(worker),
    do: {:noreply, state}

  defp advance(state) do
    state = drain_raw(state)
    empty? = state.raw_bytes == 0 and Delivery.status(state.delivery).queued_events == 0

    cond do
      state.terminal && empty? ->
        finish_terminal(state)

      state.remote_end? and empty? and not state.close_received? ->
        {:stop, :normal, finish(state, 1006, "", false)}

      empty? and close_complete?(state) ->
        {:stop, :normal,
         finish(state, state.close_code, state.close_reason, not Frame.incomplete?(state.parser))}

      true ->
        rearm(state)
    end
  end

  defp finish_terminal(state) do
    {reason, code, text, require_write?} = state.terminal

    if require_write? and not state.close_sent? do
      {:noreply, state}
    else
      if reason, do: emit(state, %Error{target: state.target, reason: reason})
      {:stop, :normal, finish(state, code, text, false)}
    end
  end

  defp close_complete?(state) do
    state.close_received? and state.close_sent? and
      (state.http_version == :http1 or (state.remote_end? and state.local_end?))
  end

  defp rearm(%{transport: nil} = state), do: {:noreply, state}
  defp rearm(%{raw_bytes: bytes} = state) when bytes > 0, do: {:noreply, state}

  defp rearm(state) do
    case state.transport.setopts(state.socket, active: :once) do
      :ok -> {:noreply, state}
      {:error, :closed} -> advance(%{state | remote_end?: true, transport: nil, socket: nil})
      {:error, reason} -> transport_terminal(state, reason)
    end
  end

  defp fail(state, reason) do
    stream_telemetry(state, :error, :rejected)
    Telemetry.connect_exception(state.telemetry_uri, reason, now() - state.connect_started_at)
    emit(state, %Error{target: state.target, reason: reason})
    {:stop, :normal, finish(state, 1006, "", false)}
  end

  defp finish(state, code, reason, clean?) do
    state = detach(state)

    state = %{
      state
      | delivery: Delivery.clear(state.delivery),
        raw_queue: :queue.new(),
        raw_bytes: 0,
        app_queue: :queue.new(),
        control_queue: :queue.new(),
        write: nil,
        buffered_amount: 0,
        pending_send_frames: 0,
        control_frames: 0
    }

    stream_telemetry(state, :close, if(clean?, do: :clean, else: :abnormal))
    Telemetry.close_stop(state.telemetry_uri, code, clean?)
    emit(state, %Close{target: state.target, code: code, reason: reason, was_clean: clean?})
    %{state | ready_state: @closed}
  end

  defp detach_stream(state) do
    if state.stream, do: Stream.close(state.stream)
    if state.stream_monitor, do: Process.demonitor(state.stream_monitor, [:flush])
    %{state | stream: nil, stream_monitor: nil, stream_handle: nil}
  end

  defp detach(state) do
    state =
      state
      |> detach_stream()
      |> cancel_timer(:opening_timer)
      |> cancel_timer(:idle_timer)
      |> cancel_timer(:close_timer)

    if state.worker, do: Process.exit(state.worker, :kill)
    if state.worker_monitor, do: Process.demonitor(state.worker_monitor, [:flush])
    if state.transport && state.socket, do: state.transport.close(state.socket)
    %{state | worker: nil, worker_monitor: nil, transport: nil, socket: nil}
  end

  defp reset_idle(state) do
    state = cancel_timer(state, :idle_timer)

    if state.ready_state == @open and not Delivery.paused?(state.delivery),
      do: timer(state, :idle_timer, :idle_timeout, state.options.idle_timeout),
      else: state
  end

  defp timer(state, field, message, duration) do
    state = cancel_timer(state, field)

    if duration == :infinity do
      state
    else
      token = make_ref()
      Map.put(state, field, {Process.send_after(self(), {message, token}, duration), token})
    end
  end

  defp cancel_timer(state, field) do
    _ = if Map.get(state, field), do: Process.cancel_timer(elem(Map.get(state, field), 0))
    Map.put(state, field, nil)
  end

  defp deadline(:infinity), do: :infinity
  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout
  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
  defp bounded_timeout(:infinity, right), do: right
  defp bounded_timeout(left, :infinity), do: left
  defp bounded_timeout(left, right), do: min(left, right)
  defp now, do: System.monotonic_time(:microsecond)
  defp call_result(reply, {:noreply, state}), do: {:reply, reply, state}
  defp call_result(reply, {:stop, reason, state}), do: {:stop, reason, reply, state}

  defp stream_telemetry(state, event, outcome) do
    status = Delivery.status(state.delivery)

    HTTP.Runtime.Telemetry.stream(:web_socket, event, state.http_version || :unknown, outcome, %{
      queued_bytes: status.queued_bytes,
      queued_events: status.queued_events,
      raw_bytes: state.raw_bytes,
      buffered_amount: state.buffered_amount,
      pending_send_frames: state.pending_send_frames,
      control_frames: state.control_frames
    })
  end

  defp emit_deliveries(state, events),
    do:
      Enum.each(events, fn
        {event, nil} -> emit(state, event)
        {event, ref} -> send(state.owner, {WebSocket, state.target, event, ref})
      end)

  defp emit(state, event), do: send(state.owner, {WebSocket, state.target, event})

  defp message_payload(:text, data, _binary_type), do: data
  defp message_payload(:binary, data, :array_buffer), do: ArrayBuffer.new(data)
  defp message_payload(:binary, data, :blob), do: HTTP.Blob.new(data)

  defp origin(state) do
    port =
      case state.uri.port do
        nil -> ""
        port -> ":" <> Integer.to_string(port)
      end

    state.uri.scheme <> "://" <> state.uri.host <> port
  end

  defp normalize_send_data(%ArrayBuffer{data: data}) when is_binary(data) do
    {:ok, :binary, data, byte_size(data)}
  end

  defp normalize_send_data(%HTTP.Blob{} = blob) do
    data = HTTP.Blob.to_binary(blob)
    {:ok, :binary, data, byte_size(data)}
  end

  defp normalize_send_data(data) when is_binary(data) do
    if String.valid?(data) do
      {:ok, :text, data, byte_size(data)}
    else
      {:error, :invalid_text_data}
    end
  end

  defp normalize_send_data(_data), do: {:error, :unsupported_data}

  defp payload_size(data) do
    case normalize_send_data(data) do
      {:ok, _opcode, _payload, bytes} -> {:ok, bytes}
      {:error, _reason} = error -> error
    end
  end
end
