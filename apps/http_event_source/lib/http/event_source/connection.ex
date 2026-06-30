defmodule HTTP.EventSource.Connection do
  @moduledoc false

  use GenServer

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message
  alias HTTP.EventSource.Event.Open
  alias HTTP.EventSource.Options
  alias HTTP.EventSource.Parser
  alias HTTP.EventSource.Telemetry

  @connecting EventSource.connecting()
  @open EventSource.open()
  @closed EventSource.closed()

  defstruct owner: nil,
            target: nil,
            uri: nil,
            url: nil,
            headers: [],
            with_credentials: false,
            connect_timeout: 30_000,
            idle_timeout: :infinity,
            ssl: [],
            socket_opts: [],
            unix_socket: nil,
            max_line_size: 64 * 1024,
            transport: nil,
            socket: nil,
            http1: nil,
            parser: nil,
            ready_state: @connecting,
            last_event_id: "",
            reconnect_time: 3_000,
            max_reconnect_time: 30_000,
            reconnect_timer: nil,
            idle_timer: nil,
            attempt: 0,
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
    target = %EventSource{
      pid: self(),
      ref: options.ref,
      url: options.url,
      with_credentials: options.with_credentials
    }

    state = %__MODULE__{
      owner: options.owner,
      target: target,
      uri: options.uri,
      url: options.url,
      headers: options.headers,
      with_credentials: options.with_credentials,
      connect_timeout: options.connect_timeout,
      idle_timeout: options.idle_timeout,
      ssl: options.ssl,
      socket_opts: options.socket_opts,
      unix_socket: options.unix_socket,
      max_line_size: options.max_line_size,
      last_event_id: options.last_event_id,
      reconnect_time: options.reconnect_time,
      max_reconnect_time: options.max_reconnect_time
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state), do: {:noreply, connect(state)}

  @impl true
  def handle_call(:ready_state, _from, state), do: {:reply, state.ready_state, state}
  def handle_call(:last_event_id, _from, state), do: {:reply, state.last_event_id, state}
  def handle_call(:reconnect_time, _from, state), do: {:reply, state.reconnect_time, state}

  def handle_call(:close, _from, state) do
    state = close_state(state, :closed)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info(:reconnect, state), do: {:noreply, connect(%{state | reconnect_timer: nil})}

  def handle_info(:idle_timeout, state) do
    {:noreply, reconnect(state, :idle_timeout)}
  end

  def handle_info(message, %{transport: transport, socket: socket} = state)
      when not is_nil(transport) and not is_nil(socket) do
    case transport.normalize_message(message, socket) do
      {:data, data} -> handle_socket_data(state, data)
      :closed -> handle_transport_closed(state)
      {:error, reason} -> {:noreply, reconnect(state, reason)}
      :unknown -> {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp connect(state) do
    state = close_transport(cancel_idle_timer(state))
    started_at = System.monotonic_time(:microsecond)
    Telemetry.connect_start(state.uri)

    state =
      %{
        state
        | ready_state: @connecting,
          http1: HTTP.HTTP1.new(:get),
          parser:
            Parser.new(max_line_size: state.max_line_size, last_event_id: state.last_event_id),
          attempt: state.attempt + 1,
          connect_started_at: started_at
      }

    case open_transport(state) do
      {:ok, transport, socket} ->
        case send_request(transport, socket, state) do
          :ok ->
            case transport.setopts(socket, active: :once) do
              :ok ->
                %{state | transport: transport, socket: socket}

              {:error, reason} ->
                connect_exception(state, reason, started_at)
                reconnect(%{state | transport: transport, socket: socket}, reason)
            end

          {:error, reason} ->
            connect_exception(state, reason, started_at)
            reconnect(%{state | transport: transport, socket: socket}, reason)
        end

      {:error, reason} ->
        connect_exception(state, reason, started_at)
        reconnect(state, reason)
    end
  end

  defp open_transport(state) do
    with {:ok, transport, host, port} <- select_transport(state),
         {:ok, socket} <-
           transport.connect(
             host,
             port,
             [ssl: state.ssl, socket_opts: state.socket_opts],
             state.connect_timeout
           ) do
      {:ok, transport, socket}
    end
  end

  defp select_transport(%{unix_socket: unix_socket}) when is_binary(unix_socket) do
    {:ok, HTTP.Transport.Unix, unix_socket, 0}
  end

  defp select_transport(%{uri: %URI{scheme: "http", host: host, port: port}}) do
    {:ok, HTTP.Transport.TCP, host, port || 80}
  end

  defp select_transport(%{uri: %URI{scheme: "https", host: host, port: port}}) do
    {:ok, HTTP.Transport.SSL, host, port || 443}
  end

  defp select_transport(%{uri: %URI{scheme: scheme}}), do: {:error, {:unsupported_scheme, scheme}}

  defp send_request(transport, socket, state) do
    transport.send(socket, request_iodata(state))
  end

  defp request_iodata(state) do
    headers =
      state.headers
      |> HTTP.Headers.new()
      |> HTTP.Headers.set_default("Accept", "text/event-stream")
      |> HTTP.Headers.set_default("Cache-Control", "no-cache")
      |> maybe_set_last_event_id(state.last_event_id)

    %HTTP.Request{method: :get, url: state.uri, headers: headers}
    |> HTTP.Request.to_iodata()
  end

  defp maybe_set_last_event_id(headers, ""), do: headers

  defp maybe_set_last_event_id(headers, id) do
    headers = HTTP.Headers.delete(headers, "Last-Event-ID")
    %{headers | headers: headers.headers ++ [{"Last-Event-ID", id}]}
  end

  defp handle_socket_data(state, data) do
    state = reset_idle_timer(state)

    case HTTP.HTTP1.stream(state.http1, data) do
      {:ok, http1, events} ->
        state = %{state | http1: http1}
        handle_http_events(state, events)

      {:error, reason} ->
        {:stop, :normal, fatal(state, reason)}
    end
  end

  defp handle_transport_closed(state) do
    case HTTP.HTTP1.close(state.http1) do
      {:ok, http1, events} ->
        state = %{state | http1: http1}

        case handle_http_events(state, events) do
          {:noreply, %{ready_state: @open} = state} -> {:noreply, reconnect(state, :eof)}
          {:noreply, state} -> {:noreply, state}
          {:stop, _reason, state} -> {:stop, :normal, state}
        end

      {:error, reason} ->
        {:noreply, reconnect(state, reason)}
    end
  end

  defp handle_http_events(state, events) do
    Enum.reduce_while(events, {:cont, state}, fn event, {:cont, acc} ->
      case handle_http_event(acc, event) do
        {:cont, next} -> {:cont, {:cont, next}}
        {:halt, next} -> {:halt, {:halt, next}}
      end
    end)
    |> case do
      {:cont, state} -> rearm(state)
      {:halt, %{ready_state: @closed} = state} -> {:stop, :normal, state}
      {:halt, state} -> {:noreply, state}
    end
  end

  defp handle_http_event(state, {:headers, status, headers}) do
    case validate_response(status, headers) do
      :ok ->
        duration = System.monotonic_time(:microsecond) - state.connect_started_at
        Telemetry.connect_stop(state.uri, status, duration)
        emit(state, %Open{target: state.target})

        {:cont,
         %{
           state
           | ready_state: @open,
             attempt: 0,
             idle_timer: schedule_idle_timer(state)
         }}

      {:stop, reason} ->
        {:halt, fatal(state, reason)}

      {:error, reason} ->
        {:halt, fatal(state, reason)}
    end
  end

  defp handle_http_event(%{ready_state: @open} = state, {:body, chunk}) do
    case Parser.parse(state.parser, chunk) do
      {:ok, parser, events} ->
        state = %{state | parser: parser}
        {:cont, handle_parser_events(state, events)}

      {:error, reason} ->
        {:halt, fatal(state, reason)}
    end
  end

  defp handle_http_event(state, {:body, _chunk}), do: {:cont, state}

  defp handle_http_event(%{ready_state: @open} = state, :done) do
    case Parser.close(state.parser) do
      {:ok, parser, events} ->
        state = %{state | parser: parser}
        {:halt, reconnect(handle_parser_events(state, events), :eof)}

      {:error, reason} ->
        {:halt, fatal(state, reason)}
    end
  end

  defp handle_http_event(state, :done), do: {:halt, reconnect(state, :eof)}

  defp validate_response(204, _headers), do: {:stop, {:http_status, 204}}

  defp validate_response(200, headers) do
    case HTTP.Headers.get(headers, "content-type") do
      nil ->
        {:error, :invalid_content_type}

      content_type ->
        {media_type, _params} = HTTP.Headers.parse_content_type(content_type)

        if String.downcase(media_type) == "text/event-stream" do
          :ok
        else
          {:error, :invalid_content_type}
        end
    end
  end

  defp validate_response(status, _headers), do: {:error, {:http_status, status}}

  defp handle_parser_events(state, events) do
    Enum.reduce(events, state, &handle_parser_event(&2, &1))
  end

  defp handle_parser_event(state, {:event, type, data, last_event_id}) do
    Telemetry.message_received(state.uri, type, last_event_id, byte_size(data))

    emit(state, %Message{
      target: state.target,
      type: type,
      data: data,
      origin: origin(state),
      last_event_id: last_event_id
    })

    %{state | last_event_id: last_event_id}
  end

  defp handle_parser_event(state, {:retry, reconnect_time}) do
    %{state | reconnect_time: min(reconnect_time, state.max_reconnect_time)}
  end

  defp handle_parser_event(state, {:last_event_id, last_event_id}) do
    %{state | last_event_id: last_event_id}
  end

  defp rearm(%{ready_state: @closed} = state), do: {:noreply, state}

  defp rearm(%{transport: transport, socket: socket} = state) do
    case transport.setopts(socket, active: :once) do
      :ok -> {:noreply, state}
      {:error, reason} -> {:noreply, reconnect(state, reason)}
    end
  end

  defp reconnect(%{ready_state: @closed} = state, _reason), do: state

  defp reconnect(state, reason) do
    emit(state, %Error{target: state.target, reason: reason})
    Telemetry.reconnect_start(state.uri, reason, state.reconnect_time, state.attempt)

    state =
      state
      |> cancel_idle_timer()
      |> close_transport()
      |> cancel_reconnect_timer()

    timer = Process.send_after(self(), :reconnect, state.reconnect_time)
    %{state | ready_state: @connecting, reconnect_timer: timer}
  end

  defp fatal(state, reason) do
    if state.ready_state == @connecting do
      connect_started_at = state.connect_started_at || System.monotonic_time(:microsecond)
      connect_exception(state, reason, connect_started_at)
    end

    emit(state, %Error{target: state.target, reason: reason})
    close_state(state, reason)
  end

  defp close_state(state, reason) do
    state =
      state
      |> cancel_idle_timer()
      |> cancel_reconnect_timer()
      |> close_transport()

    Telemetry.close_stop(state.uri, reason)
    %{state | ready_state: @closed}
  end

  defp close_transport(%{transport: nil} = state), do: %{state | socket: nil}
  defp close_transport(%{socket: nil} = state), do: state

  defp close_transport(state) do
    _ = state.transport.close(state.socket)
    %{state | socket: nil, transport: nil}
  end

  defp cancel_reconnect_timer(%{reconnect_timer: nil} = state), do: state

  defp cancel_reconnect_timer(%{reconnect_timer: timer} = state) do
    _ = Process.cancel_timer(timer)
    %{state | reconnect_timer: nil}
  end

  defp schedule_idle_timer(%{idle_timeout: :infinity}), do: nil

  defp schedule_idle_timer(%{idle_timeout: timeout}),
    do: Process.send_after(self(), :idle_timeout, timeout)

  defp reset_idle_timer(%{ready_state: @open} = state) do
    state
    |> cancel_idle_timer()
    |> then(fn state -> %{state | idle_timer: schedule_idle_timer(state)} end)
  end

  defp reset_idle_timer(state), do: state

  defp cancel_idle_timer(%{idle_timer: nil} = state), do: state

  defp cancel_idle_timer(%{idle_timer: timer} = state) do
    _ = Process.cancel_timer(timer)
    %{state | idle_timer: nil}
  end

  defp connect_exception(state, reason, started_at) do
    duration = System.monotonic_time(:microsecond) - started_at
    Telemetry.connect_exception(state.uri, reason, duration)
  end

  defp origin(state) do
    port =
      case state.uri.port do
        nil -> ""
        port -> ":" <> Integer.to_string(port)
      end

    state.uri.scheme <> "://" <> state.uri.host <> port
  end

  defp emit(state, event) do
    send(state.owner, {EventSource, state.target, event})
  end
end
