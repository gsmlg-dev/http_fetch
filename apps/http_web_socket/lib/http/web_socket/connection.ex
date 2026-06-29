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
  @close_timeout 5_000

  defstruct owner: nil,
            target: nil,
            uri: nil,
            url: nil,
            protocols: [],
            headers: [],
            timeout: 30_000,
            connect_timeout: 30_000,
            ssl: [],
            socket_opts: [],
            max_send_queue: 16 * 1024 * 1024,
            transport: nil,
            socket: nil,
            ready_state: @connecting,
            parser: nil,
            protocol: "",
            extensions: "",
            binary_type: :blob,
            buffered_amount: 0,
            close_sent?: false,
            close_received?: false,
            close_code: nil,
            close_reason: "",
            close_timer: nil,
            connect_started_at: nil

  @spec start_link(Options.t()) :: GenServer.on_start()
  def start_link(%Options{} = options) do
    GenServer.start_link(__MODULE__, options)
  end

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
    target = %WebSocket{pid: self(), ref: options.ref, url: options.url}

    state = %__MODULE__{
      owner: options.owner,
      target: target,
      uri: options.uri,
      url: options.url,
      protocols: options.protocols,
      headers: options.headers,
      timeout: options.timeout,
      connect_timeout: options.connect_timeout,
      ssl: options.ssl,
      socket_opts: options.socket_opts,
      max_send_queue: options.max_send_queue,
      binary_type: options.binary_type,
      parser: Frame.new_parser(max_message_size: options.max_message_size)
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    started_at = System.monotonic_time(:microsecond)
    Telemetry.connect_start(state.uri)

    case connect_and_upgrade(state) do
      {:ok, state, extra} ->
        duration = System.monotonic_time(:microsecond) - started_at
        Telemetry.connect_stop(state.uri, state.protocol, duration)
        emit(state, %Open{target: state.target})

        if extra != <<>> do
          send(self(), {:websocket_data, extra})
        end

        case rearm(state) do
          :ok -> {:noreply, %{state | ready_state: @open, connect_started_at: started_at}}
          {:error, reason} -> fail_connection(state, reason, started_at)
        end

      {:error, reason} ->
        fail_connection(state, reason, started_at)
    end
  end

  @impl true
  def handle_call(:ready_state, _from, state), do: {:reply, state.ready_state, state}
  def handle_call(:buffered_amount, _from, state), do: {:reply, state.buffered_amount, state}
  def handle_call(:extensions, _from, state), do: {:reply, state.extensions, state}
  def handle_call(:protocol, _from, state), do: {:reply, state.protocol, state}
  def handle_call(:binary_type, _from, state), do: {:reply, state.binary_type, state}

  def handle_call({:set_binary_type, binary_type}, _from, state) do
    {:reply, :ok, %{state | binary_type: binary_type}}
  end

  def handle_call({:send, _data}, _from, %{ready_state: @connecting} = state) do
    {:reply, {:error, :invalid_state}, state}
  end

  def handle_call({:send, data}, _from, %{ready_state: ready_state} = state)
      when ready_state in [@closing, @closed] do
    case payload_size(data) do
      {:ok, bytes} -> {:reply, :ok, %{state | buffered_amount: state.buffered_amount + bytes}}
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  def handle_call({:send, data}, _from, %{ready_state: @open} = state) do
    case send_data(state, data) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:stop, :normal, {:error, reason}, close_transport(state)}
    end
  end

  def handle_call({:close, code, reason, payload}, _from, state) do
    case close_from_api(state, code, reason, payload) do
      {:reply, reply, state} -> {:reply, reply, state}
      {:stop, reply, state} -> {:stop, :normal, reply, state}
    end
  end

  @impl true
  def handle_info({:websocket_data, data}, state), do: handle_socket_data(data, state)

  def handle_info(:close_timeout, state) do
    {:stop, :normal, finish_close(state, state.close_code || 1006, state.close_reason, false)}
  end

  def handle_info(message, %{transport: transport, socket: socket} = state)
      when not is_nil(transport) and not is_nil(socket) do
    case transport.normalize_message(message, socket) do
      {:data, data} -> handle_socket_data(data, state)
      :closed -> handle_transport_closed(state)
      {:error, reason} -> handle_transport_error(reason, state)
      :unknown -> {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp connect_and_upgrade(state) do
    key = state |> Map.get(:uri) |> generate_key()

    with {:ok, transport, host, port} <- select_transport(state.uri),
         {:ok, request} <-
           Handshake.build_request(state.uri, state.protocols, state.headers, key),
         {:ok, socket} <- connect(transport, host, port, state),
         :ok <- transport.send(socket, request),
         {:ok, status, headers, extra} <- recv_handshake(transport, socket, <<>>, state.timeout),
         {:ok, negotiated} <- Handshake.validate_response(status, headers, key, state.protocols) do
      {:ok,
       %{
         state
         | transport: transport,
           socket: socket,
           protocol: negotiated.protocol,
           extensions: negotiated.extensions,
           ready_state: @open
       }, extra}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp generate_key(_uri), do: :crypto.strong_rand_bytes(16) |> Base.encode64()

  defp select_transport(%URI{scheme: "ws", host: host, port: port}) do
    {:ok, HTTP.Transport.TCP, host, port || 80}
  end

  defp select_transport(%URI{scheme: "wss", host: host, port: port}) do
    {:ok, HTTP.Transport.SSL, host, port || 443}
  end

  defp select_transport(%URI{scheme: scheme}), do: {:error, {:unsupported_scheme, scheme}}

  defp connect(transport, host, port, state) do
    transport.connect(
      host,
      port,
      [ssl: state.ssl, socket_opts: state.socket_opts],
      state.connect_timeout
    )
  end

  defp recv_handshake(transport, socket, buffer, timeout) do
    case Handshake.parse_response(buffer) do
      {:ok, status, headers, extra} ->
        {:ok, status, headers, extra}

      {:more, buffer} ->
        with {:ok, data} <- recv(transport, socket, timeout) do
          recv_handshake(transport, socket, buffer <> data, timeout)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp recv(HTTP.Transport.TCP, socket, timeout), do: :gen_tcp.recv(socket, 0, timeout)
  defp recv(HTTP.Transport.SSL, socket, timeout), do: :ssl.recv(socket, 0, timeout)

  defp fail_connection(state, reason, started_at) do
    duration = System.monotonic_time(:microsecond) - started_at
    Telemetry.connect_exception(state.uri, reason, duration)
    emit(state, %Error{target: state.target, reason: reason})
    state = finish_close(%{state | ready_state: @closed}, 1006, "", false)
    {:stop, :normal, state}
  end

  defp handle_socket_data(data, state) do
    case Frame.parse(state.parser, data) do
      {:ok, parser, events} ->
        state = %{state | parser: parser}
        handle_frame_events(events, state)

      {:error, {code, reason}} ->
        emit(state, %Error{target: state.target, reason: reason})
        {:stop, :normal, close_with_code(state, code, Atom.to_string(reason), false)}
    end
  end

  defp handle_frame_events([], state) do
    case rearm(state) do
      :ok -> {:noreply, state}
      {:error, reason} -> handle_transport_error(reason, state)
    end
  end

  defp handle_frame_events([event | rest], state) do
    case handle_frame_event(event, state) do
      {:cont, state} -> handle_frame_events(rest, state)
      {:stop, state} -> {:stop, :normal, state}
    end
  end

  defp handle_frame_event({:message, opcode, data}, state) do
    payload = message_payload(opcode, data, state.binary_type)
    Telemetry.message_received(state.uri, Atom.to_string(opcode), byte_size(data))
    emit(state, %Message{target: state.target, data: payload, origin: origin(state)})
    {:cont, state}
  end

  defp handle_frame_event({:ping, payload}, state) do
    case Frame.encode(:pong, payload) do
      {:ok, frame} ->
        _ = state.transport.send(state.socket, frame)
        {:cont, state}

      {:error, _reason} ->
        {:stop, close_with_code(state, 1002, "invalid ping", false)}
    end
  end

  defp handle_frame_event({:pong, _payload}, state), do: {:cont, state}

  defp handle_frame_event({:close, code, reason}, state) do
    state = %{state | close_received?: true, close_code: code, close_reason: reason}

    state =
      if state.close_sent? do
        state
      else
        send_close_frame(state, close_payload_for_reply(code, reason))
      end

    {:stop, finish_close(state, code, reason, true)}
  end

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

  defp send_data(state, data) do
    with {:ok, opcode, payload, bytes} <- normalize_send_data(data),
         :ok <- validate_send_capacity(state, bytes),
         {:ok, frame} <- Frame.encode(opcode, payload) do
      buffered_amount = state.buffered_amount + bytes

      case state.transport.send(state.socket, frame) do
        :ok ->
          Telemetry.message_sent(
            state.uri,
            Atom.to_string(opcode),
            bytes,
            buffered_amount - bytes
          )

          {:ok, %{state | buffered_amount: buffered_amount - bytes}}

        {:error, reason} ->
          emit(state, %Error{target: state.target, reason: reason})

          {:error, reason,
           close_with_code(%{state | buffered_amount: buffered_amount}, 1006, "", false)}
      end
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp normalize_send_data(%ArrayBuffer{data: data, byte_length: bytes}) do
    {:ok, :binary, data, bytes}
  end

  defp normalize_send_data(%HTTP.Blob{} = blob) do
    {:ok, :binary, HTTP.Blob.to_binary(blob), HTTP.Blob.size(blob)}
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

  defp validate_send_capacity(state, bytes) do
    if state.buffered_amount + bytes <= state.max_send_queue do
      :ok
    else
      {:error, :send_queue_full}
    end
  end

  defp close_from_api(%{ready_state: @closed} = state, _code, _reason, _payload) do
    {:reply, :ok, state}
  end

  defp close_from_api(%{ready_state: @closing} = state, _code, _reason, _payload) do
    {:reply, :ok, state}
  end

  defp close_from_api(%{ready_state: @connecting} = state, code, reason, _payload) do
    Telemetry.close_start(state.uri, code)
    {:stop, :ok, finish_close(state, code || 1006, reason, false)}
  end

  defp close_from_api(%{ready_state: @open} = state, code, reason, payload) do
    Telemetry.close_start(state.uri, code)
    state = send_close_frame(state, payload)
    timer = Process.send_after(self(), :close_timeout, @close_timeout)

    state = %{
      state
      | ready_state: @closing,
        close_sent?: true,
        close_code: code,
        close_reason: reason,
        close_timer: timer
    }

    if state.close_received? do
      {:stop, :ok, finish_close(state, code, reason, true)}
    else
      {:reply, :ok, state}
    end
  end

  defp send_close_frame(state, payload) do
    with {:ok, frame} <- Frame.encode(:close, payload),
         :ok <- state.transport.send(state.socket, frame) do
      %{state | close_sent?: true}
    else
      _error -> state
    end
  end

  defp close_payload_for_reply(nil, _reason), do: <<>>
  defp close_payload_for_reply(code, reason), do: <<code::16, reason::binary>>

  defp close_with_code(state, code, reason, was_clean) do
    case Frame.close_payload(code, reason) do
      {:ok, payload} ->
        state
        |> send_close_frame(payload)
        |> finish_close(code, reason, was_clean)

      {:error, _reason} ->
        finish_close(state, code, "", was_clean)
    end
  end

  defp handle_transport_closed(%{ready_state: @closing} = state) do
    {:stop, :normal, finish_close(state, state.close_code, state.close_reason, true)}
  end

  defp handle_transport_closed(state) do
    {:stop, :normal, finish_close(state, 1006, "", false)}
  end

  defp handle_transport_error(reason, state) do
    emit(state, %Error{target: state.target, reason: reason})
    {:stop, :normal, finish_close(state, 1006, "", false)}
  end

  defp finish_close(state, code, reason, was_clean) do
    state = cancel_close_timer(state)
    state = close_transport(state)
    Telemetry.close_stop(state.uri, code, was_clean)

    emit(state, %Close{
      target: state.target,
      code: code,
      reason: reason || "",
      was_clean: was_clean
    })

    %{state | ready_state: @closed, socket: nil}
  end

  defp cancel_close_timer(%{close_timer: nil} = state), do: state

  defp cancel_close_timer(%{close_timer: timer} = state) do
    _ = Process.cancel_timer(timer)
    %{state | close_timer: nil}
  end

  defp close_transport(%{transport: nil} = state), do: state
  defp close_transport(%{socket: nil} = state), do: state

  defp close_transport(state) do
    _ = state.transport.close(state.socket)
    %{state | socket: nil}
  end

  defp rearm(%{transport: transport, socket: socket}) do
    transport.setopts(socket, active: :once)
  end

  defp emit(state, event) do
    send(state.owner, {WebSocket, state.target, event})
  end
end
