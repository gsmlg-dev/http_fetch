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
  alias HTTP.Runtime.Delivery
  alias HTTP.Runtime.Stream

  @connecting EventSource.connecting()
  @open EventSource.open()
  @closed EventSource.closed()

  defstruct options: nil,
            generation: nil,
            worker: nil,
            worker_monitor: nil,
            stream: nil,
            stream_monitor: nil,
            stream_handle: nil,
            http_version: nil,
            delivery: nil,
            redirects: 0,
            raw_queue: :queue.new(),
            raw_bytes: 0,
            remote_end?: false,
            terminal_reason: nil,
            opening_timer: nil,
            owner: nil,
            target: nil,
            uri: nil,
            url: nil,
            headers: [],
            with_credentials: false,
            connect_timeout: 30_000,
            idle_timeout: :infinity,
            ssl: [],
            socket_opts: [],
            tls_backend: :ssl,
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
    _ = HTTP.OwnerMonitor.start(self(), options.owner)

    target = %EventSource{
      pid: self(),
      ref: options.ref,
      url: options.url,
      with_credentials: options.with_credentials
    }

    state = %__MODULE__{
      options: options,
      delivery: Delivery.new(options),
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
      tls_backend: options.tls_backend,
      unix_socket: options.unix_socket,
      max_line_size: options.max_line_size,
      last_event_id: options.last_event_id,
      reconnect_time: min(options.reconnect_time, options.max_reconnect_time),
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

  def handle_call(:http_version, _from, state), do: {:reply, state.http_version, state}

  def handle_call(:status, _from, state) do
    parser = state.parser || Parser.new()
    status = Delivery.status(state.delivery)

    status =
      Map.merge(status, %{
        http_version: state.http_version,
        ready_state: state.ready_state,
        stream_handle: state.stream_handle,
        parser_bytes:
          parser.event_bytes + byte_size(parser.buffer) +
            byte_size(parser.event_type) + byte_size(parser.last_event_id),
        parser_parts: parser.event_parts,
        raw_bytes: state.raw_bytes,
        raw_chunks: :queue.len(state.raw_queue),
        raw_limit_bytes: raw_limit(state)
      })

    {:reply, status, state}
  end

  def handle_call({:acknowledge, ref}, _from, state) do
    {:ok, delivery, events} = Delivery.acknowledge(state.delivery, ref)
    state = %{state | delivery: delivery}
    emit_deliveries(state, events)
    state = drain_raw(state)
    stream_telemetry(state, :queue, :settled)

    case finish_remote_end(state) do
      {:noreply, state} -> {:reply, :ok, reset_idle_timer(state)}
      {:stop, _, state} -> {:stop, :normal, :ok, state}
    end
  end

  def handle_call(:close, _from, state) do
    state = close_state(state, :closed)
    {:stop, :normal, :ok, state}
  end

  @impl true
  def handle_info({:reconnect, token}, %{reconnect_timer: {_timer, token}} = state),
    do: {:noreply, connect(%{state | reconnect_timer: nil, redirects: 0})}

  def handle_info(
        {:opening_timeout, generation},
        %{generation: generation, opening_timer: timer, ready_state: @connecting} = state
      )
      when not is_nil(timer),
      do: {:noreply, reconnect(state, :opening_timeout)}

  def handle_info({:idle_timeout, token}, %{idle_timer: {_timer, token}} = state),
    do: {:noreply, reconnect(state, :idle_timeout)}

  def handle_info(
        {:http1_connected, generation, worker, result},
        %{generation: generation, worker: worker} = state
      ) do
    send(worker, :accepted)
    Process.demonitor(state.worker_monitor, [:flush])
    state = %{state | worker: nil, worker_monitor: nil}

    case result do
      {:ok, transport, socket} ->
        state = %{state | transport: transport, socket: socket, http_version: :http1}

        case transport.setopts(socket, active: :once) do
          :ok -> {:noreply, state}
          {:error, reason} -> {:noreply, reconnect(state, reason)}
        end

      {:error, reason} ->
        if fatal_transport_error?(reason),
          do: {:stop, :normal, fatal(state, reason)},
          else: {:noreply, reconnect(state, reason)}
    end
  end

  def handle_info({:http1_connected, _generation, _worker, {:ok, transport, socket}}, state) do
    transport.close(socket)
    {:noreply, state}
  end

  def handle_info(
        {:http_runtime, generation, pid, event},
        %{generation: generation, stream: pid} = state
      ) do
    handle_stream_event(state, event)
  end

  def handle_info(
        {:DOWN, monitor, :process, pid, reason},
        %{stream_monitor: monitor, stream: pid} = state
      ) do
    park_terminal(state, {:stream_down, reason})
  end

  def handle_info(
        {:DOWN, monitor, :process, pid, reason},
        %{worker_monitor: monitor, worker: pid} = state
      ) do
    {:noreply, reconnect(state, {:connect_worker_down, reason})}
  end

  def handle_info(message, %{transport: transport, socket: socket} = state)
      when not is_nil(transport) and not is_nil(socket) do
    case transport.normalize_message(message, socket) do
      {:data, data} -> handle_socket_data(state, data)
      :closed -> handle_transport_closed(state)
      {:error, reason} -> park_terminal(state, reason)
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
            Parser.new(
              max_line_size: state.max_line_size,
              last_event_id: state.last_event_id,
              max_event_size: parser_limit(state.options),
              max_event_parts: state.options.max_event_parts
            ),
          attempt: state.attempt + 1,
          connect_started_at: started_at,
          remote_end?: false
      }

    state = %{state | generation: make_ref(), http_version: nil, stream_handle: nil}
    state = schedule_opening_timer(state)

    if HTTP.Runtime.Options.h2?(state.options) do
      case Stream.start(request(state), self(),
             opening_timeout: state.connect_timeout,
             generation: state.generation
           ) do
        {:ok, pid, _generation} ->
          %{state | stream: pid, stream_monitor: Process.monitor(pid)}

        {:error, reason} ->
          reconnect(state, reason)
      end
    else
      connect_http1(state)
    end
  end

  defp connect_http1(state) do
    parent = self()
    generation = state.generation

    {:ok, worker} =
      Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
        HTTP.OwnerMonitor.start(self(), parent)

        result =
          with {:ok, transport, socket} <- open_transport(state),
               :ok <- send_request(transport, socket, state) do
            case transport.controlling_process(socket, parent) do
              :ok ->
                {:ok, transport, socket}

              {:error, reason} ->
                transport.close(socket)
                {:error, reason}
            end
          end

        send(parent, {:http1_connected, generation, self(), result})

        receive do
          :accepted -> :ok
        after
          30_000 -> :ok
        end
      end)

    %{state | worker: worker, worker_monitor: Process.monitor(worker)}
  end

  defp open_transport(state) do
    with {:ok, transport, host, port} <- select_transport(state),
         {:ok, socket} <-
           transport.connect(
             host,
             port,
             [ssl: http1_ssl(state), socket_opts: state.socket_opts],
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

  defp select_transport(%{
         uri: %URI{scheme: "https", host: host, port: port},
         tls_backend: backend
       }) do
    {:ok, HTTP.TLSBackend.transport(backend), host, port || 443}
  end

  defp select_transport(%{uri: %URI{scheme: scheme}}), do: {:error, {:unsupported_scheme, scheme}}

  defp send_request(transport, socket, state) do
    transport.send(socket, request_iodata(state))
  end

  defp http1_ssl(state) do
    if state.uri.scheme == "https",
      do: Keyword.put(state.ssl, :alpn_advertised_protocols, ["http/1.1"]),
      else: state.ssl
  end

  defp request_iodata(state), do: HTTP.Request.to_iodata(request(state))

  defp request(state) do
    headers =
      state.headers
      |> HTTP.Headers.new()
      |> HTTP.Headers.set_default("User-Agent", HTTP.Headers.user_agent(:http_event_source))
      |> HTTP.Headers.set_default("Accept", "text/event-stream")
      |> HTTP.Headers.set_default("Cache-Control", "no-cache")
      |> maybe_set_last_event_id(state.last_event_id)

    %HTTP.Request{
      method: :get,
      url: state.uri,
      headers: headers,
      transport_options: HTTP.Runtime.Options.transport_options(state.options)
    }
  end

  defp maybe_set_last_event_id(headers, ""), do: HTTP.Headers.delete(headers, "Last-Event-ID")

  defp maybe_set_last_event_id(headers, id) do
    headers = HTTP.Headers.delete(headers, "Last-Event-ID")
    %{headers | headers: headers.headers ++ [{"Last-Event-ID", id}]}
  end

  defp handle_socket_data(state, data) do
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
          {:noreply, %{ready_state: @open} = state} -> park_terminal(state, :eof)
          {:noreply, state} -> {:noreply, state}
          {:stop, _reason, state} -> {:stop, :normal, state}
        end

      {:error, reason} ->
        park_terminal(state, reason)
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

  defp handle_http_event(state, {:headers, status, _headers}) when status in 100..199,
    do: {:cont, state}

  defp handle_http_event(%{ready_state: @open} = state, {:headers, _status, _headers}),
    do: {:cont, state}

  defp handle_http_event(state, {:headers, status, headers})
       when status in [301, 302, 303, 307, 308],
       do: redirect(state, headers)

  defp handle_http_event(state, {:headers, status, headers}) do
    case validate_response(status, headers) do
      :ok ->
        duration = System.monotonic_time(:microsecond) - state.connect_started_at
        Telemetry.connect_stop(state.uri, status, duration, state.http_version)
        emit(state, %Open{target: state.target})
        state = cancel_opening_timer(state)
        state = reset_idle_timer(%{state | ready_state: @open, attempt: 0})
        stream_telemetry(state, :open, :accepted)
        {:cont, state}

      {_kind, reason} ->
        {:halt, fatal(state, reason)}
    end
  end

  defp handle_http_event(%{ready_state: @open} = state, {:body, chunk}) do
    state = admit_raw(state, chunk, nil)

    if state.ready_state == @closed,
      do: {:halt, state},
      else: {:cont, reset_idle_timer(state)}
  end

  defp handle_http_event(state, {:body, _chunk}), do: {:cont, state}

  defp handle_http_event(%{ready_state: @open} = state, :done) do
    case park_terminal(state, :eof) do
      {:noreply, state} -> {:halt, state}
      {:stop, _reason, state} -> {:halt, state}
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
    Enum.reduce_while(events, state, fn event, state ->
      next = handle_parser_event(state, event)
      if next.ready_state == @closed, do: {:halt, next}, else: {:cont, next}
    end)
  end

  defp handle_parser_event(state, {:event, type, data, last_event_id}) do
    Telemetry.message_received(state.uri, type, last_event_id, byte_size(data))

    message = %Message{
      target: state.target,
      type: type,
      data: data,
      origin: origin(state),
      last_event_id: last_event_id
    }

    size = byte_size(data) + byte_size(type) + byte_size(last_event_id)

    case Delivery.push(state.delivery, message, size, state.owner) do
      {:ok, delivery, events} ->
        emit_deliveries(state, events)
        %{state | last_event_id: last_event_id, delivery: delivery}

      {:error, reason} ->
        fatal(state, reason)
    end
  end

  defp handle_parser_event(state, {:retry, reconnect_time}) do
    %{state | reconnect_time: min(reconnect_time, state.max_reconnect_time)}
  end

  defp handle_parser_event(state, {:last_event_id, last_event_id}) do
    %{state | last_event_id: last_event_id}
  end

  defp emit_deliveries(state, events) do
    Enum.each(events, fn
      {event, nil} -> emit(state, event)
      {event, ref} -> send(state.owner, {EventSource, state.target, event, ref})
    end)
  end

  defp rearm(%{ready_state: @closed} = state), do: {:noreply, state}

  defp rearm(%{options: %{delivery: :ack}, raw_bytes: bytes} = state) when bytes > 0,
    do: {:noreply, state}

  defp rearm(%{transport: nil} = state), do: {:noreply, state}

  defp rearm(%{transport: transport, socket: socket} = state) do
    case transport.setopts(socket, active: :once) do
      :ok -> {:noreply, state}
      {:error, :closed} -> handle_transport_closed(state)
      {:error, reason} -> {:noreply, reconnect(state, reason)}
    end
  end

  defp reconnect(%{ready_state: @closed} = state, _reason), do: state

  defp reconnect(state, reason) do
    stream_telemetry(state, :reconnect, :retrying)
    emit(state, %Error{target: state.target, reason: reason})
    Telemetry.reconnect_start(state.uri, reason, state.reconnect_time, state.attempt)

    state =
      state
      |> cancel_idle_timer()
      |> close_transport()
      |> cancel_reconnect_timer()

    token = make_ref()
    timer = Process.send_after(self(), {:reconnect, token}, state.reconnect_time)
    %{state | ready_state: @connecting, reconnect_timer: {timer, token}}
  end

  defp fatal(state, reason) do
    if state.options.delivery == :ack and Delivery.status(state.delivery).queued_events > 0 do
      state = state |> cancel_idle_timer() |> cancel_reconnect_timer() |> detach_transport()

      %{
        state
        | terminal_reason: {:fatal, reason},
          remote_end?: true,
          raw_queue: :queue.new(),
          raw_bytes: 0
      }
    else
      fatal_now(state, reason)
    end
  end

  defp fatal_now(state, reason) do
    stream_telemetry(state, :error, :rejected)

    if state.ready_state == @connecting do
      connect_started_at = state.connect_started_at || System.monotonic_time(:microsecond)
      connect_exception(state, reason, connect_started_at)
    end

    emit(state, %Error{target: state.target, reason: reason})
    close_state(state, reason)
  end

  defp close_state(state, reason) do
    stream_telemetry(state, :close, :completed)

    state =
      state
      |> cancel_idle_timer()
      |> cancel_reconnect_timer()
      |> close_transport()

    Telemetry.close_stop(state.uri, reason)
    %{state | ready_state: @closed, delivery: Delivery.clear(state.delivery)}
  end

  defp close_transport(state) do
    state = detach_transport(state)

    %{state | raw_queue: :queue.new(), raw_bytes: 0, remote_end?: false, terminal_reason: nil}
  end

  defp detach_transport(state) do
    state = cancel_opening_timer(state)
    if state.stream, do: Stream.close(state.stream)
    if state.stream_monitor, do: _ = Process.demonitor(state.stream_monitor, [:flush])
    if state.worker, do: _ = Process.exit(state.worker, :kill)
    if state.worker_monitor, do: _ = Process.demonitor(state.worker_monitor, [:flush])
    if state.transport && state.socket, do: _ = state.transport.close(state.socket)

    %{
      state
      | socket: nil,
        transport: nil,
        stream: nil,
        stream_monitor: nil,
        stream_handle: nil,
        worker: nil,
        worker_monitor: nil,
        generation: nil
    }
  end

  defp schedule_opening_timer(%{connect_timeout: :infinity} = state), do: state

  defp schedule_opening_timer(state) do
    timer =
      Process.send_after(self(), {:opening_timeout, state.generation}, state.connect_timeout)

    %{state | opening_timer: timer}
  end

  defp cancel_opening_timer(state) do
    _ = if state.opening_timer, do: Process.cancel_timer(state.opening_timer)
    %{state | opening_timer: nil}
  end

  defp cancel_reconnect_timer(state) do
    _ = cancel_timer(state.reconnect_timer)
    %{state | reconnect_timer: nil}
  end

  defp cancel_timer(nil), do: :ok
  defp cancel_timer({timer, _token}), do: Process.cancel_timer(timer)

  defp reset_idle_timer(%{ready_state: @open} = state) do
    state = cancel_idle_timer(state)

    if state.idle_timeout == :infinity or Delivery.paused?(state.delivery) do
      state
    else
      token = make_ref()
      timer = Process.send_after(self(), {:idle_timeout, token}, state.idle_timeout)
      %{state | idle_timer: {timer, token}}
    end
  end

  defp reset_idle_timer(state), do: state

  defp cancel_idle_timer(state) do
    _ = cancel_timer(state.idle_timer)
    %{state | idle_timer: nil}
  end

  @impl true
  def terminate(_reason, state) do
    _ = close_transport(state)
    :ok
  end

  defp handle_stream_event(state, {:opened, handle}),
    do:
      {:noreply,
       %{
         state
         | stream_handle: handle,
           http_version: :http2
       }}

  defp handle_stream_event(state, {:headers, headers, _flags}) do
    case List.keyfind(headers, ":status", 0) do
      {":status", status} ->
        case Integer.parse(status) do
          {status, ""} ->
            handle_http_events(state, [{:headers, status, HTTP.Headers.new(headers)}])

          _ ->
            {:stop, :normal, fatal(state, :invalid_http2_status)}
        end

      nil ->
        {:noreply, state}
    end
  end

  defp handle_stream_event(%{ready_state: @open} = state, {:data, data, _flags, ref}) do
    state = admit_raw(state, data, {state.stream, ref})

    if state.ready_state == @closed,
      do: {:stop, :normal, state},
      else: {:noreply, reset_idle_timer(state)}
  end

  defp handle_stream_event(state, {:data, _data, _flags, _ref}),
    do: {:stop, :normal, fatal(state, :body_before_response)}

  defp handle_stream_event(state, :remote_end) do
    finish_remote_end(%{state | remote_end?: true})
  end

  defp handle_stream_event(state, {:goaway, _last_id, _error}), do: {:noreply, state}

  defp handle_stream_event(state, {:error, :http1_negotiated}) do
    if state.options.http_version == :auto and is_nil(state.options.http2_profile) do
      state = close_transport(state)
      state = schedule_opening_timer(%{state | generation: make_ref()})
      stream_telemetry(state, :fallback, :protocol_unavailable)
      {:noreply, connect_http1(state)}
    else
      {:stop, :normal, fatal(state, :http1_negotiated)}
    end
  end

  defp handle_stream_event(state, {:terminal, reason}) do
    if fatal_transport_error?(reason),
      do: fatal_result(state, reason),
      else: park_terminal(state, reason)
  end

  defp handle_stream_event(state, {:error, reason}) do
    if fatal_transport_error?(reason),
      do: fatal_result(state, reason),
      else: park_terminal(state, reason)
  end

  defp fatal_transport_error?({:http2_not_negotiated, _}), do: true
  defp fatal_transport_error?({:tls_alert, _}), do: true
  defp fatal_transport_error?({:options, _}), do: true
  defp fatal_transport_error?({:http2, :stream_error, _}), do: true
  defp fatal_transport_error?(_), do: false

  defp fatal_result(state, reason) do
    state = fatal(state, reason)
    if state.ready_state == @closed, do: {:stop, :normal, state}, else: {:noreply, state}
  end

  defp finish_remote_end(%{ready_state: @closed} = state), do: {:stop, :normal, state}

  defp finish_remote_end(%{remote_end?: true, terminal_reason: nil} = state),
    do: park_terminal(state, :eof)

  defp finish_remote_end(%{terminal_reason: reason, raw_bytes: 0} = state)
       when not is_nil(reason) do
    if Delivery.status(state.delivery).queued_events == 0 do
      finish_terminal(state, reason)
    else
      {:noreply, state}
    end
  end

  defp finish_remote_end(state), do: rearm(state)

  defp finish_terminal(state, {:fatal, reason}),
    do: {:stop, :normal, fatal_now(state, reason)}

  defp finish_terminal(state, reason) do
    case Parser.close(state.parser) do
      {:ok, parser, events} ->
        state = handle_parser_events(%{state | parser: parser}, events)

        if Delivery.status(state.delivery).queued_events == 0,
          do: {:noreply, reconnect(state, reason)},
          else: {:noreply, state}

      {:error, error} ->
        {:stop, :normal, fatal_now(state, error)}
    end
  end

  defp park_terminal(%{terminal_reason: {:fatal, _}} = state, _reason),
    do: finish_remote_end(state)

  defp park_terminal(state, reason) do
    state = state |> cancel_idle_timer() |> detach_transport()
    finish_remote_end(%{state | terminal_reason: reason, remote_end?: true})
  end

  defp admit_raw(state, data, ref) do
    if state.raw_bytes + byte_size(data) > raw_limit(state) do
      fatal(state, :consumer_overloaded)
    else
      # Credit is returned on safe raw-buffer admission, independently of event
      # dispatch. Leave room for the entire unused receive allowance when the
      # application pauses, then withhold further credit until parsing resumes.
      ref = admit_credit(state, data, ref)

      state = %{
        state
        | raw_queue: pack_raw(state.raw_queue, :binary.copy(data), ref),
          raw_bytes: state.raw_bytes + byte_size(data)
      }

      if :queue.len(state.raw_queue) > 128,
        do: fatal(state, :consumer_overloaded),
        else: drain_raw(state)
    end
  end

  defp admit_credit(state, data, {stream, ref} = delivery) do
    if state.raw_bytes + byte_size(data) <= 1_048_576 do
      Stream.acknowledge(stream, ref)
      nil
    else
      delivery
    end
  end

  defp admit_credit(_state, _data, nil), do: nil

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

  defp drain_raw(%{ready_state: @closed} = state), do: state
  defp drain_raw(%{terminal_reason: {:fatal, _}} = state), do: state

  defp drain_raw(state) do
    if parser_capacity?(state) do
      parse_raw(state, :queue.out(state.raw_queue))
    else
      state
    end
  end

  defp parse_raw(state, {:empty, _}), do: state

  defp parse_raw(state, {{:value, {data, ref}}, queue}) do
    state = %{state | raw_queue: queue, raw_bytes: state.raw_bytes - byte_size(data)}

    case Parser.parse_some(state.parser, data) do
      {:ok, parser, events, rest} ->
        state = handle_parser_events(%{state | parser: parser}, events)
        drain_raw(settle_raw(state, rest, ref))

      {:error, reason} ->
        fatal(state, reason)
    end
  end

  defp settle_raw(state, <<>>, ref) do
    if ref, do: Stream.acknowledge(elem(ref, 0), elem(ref, 1))
    state
  end

  defp settle_raw(state, rest, ref) do
    %{
      state
      | raw_queue: :queue.in_r({rest, ref}, state.raw_queue),
        raw_bytes: state.raw_bytes + byte_size(rest)
    }
  end

  defp parser_limit(options), do: options.max_event_size

  defp parser_capacity?(%{options: %{delivery: :legacy}}), do: true

  defp parser_capacity?(state) do
    status = Delivery.status(state.delivery)
    reserve = parser_limit(state.options) + 7

    status.queued_events < state.options.max_queue_events and
      status.queued_bytes + reserve <= state.options.max_queue_bytes
  end

  defp redirect(state, headers) do
    location = HTTP.Headers.get(headers, "location")

    with true <- is_binary(location) or {:error, :invalid_redirect},
         true <- state.redirects < state.options.max_redirects or {:error, :too_many_redirects},
         uri = URI.merge(state.uri, location),
         true <-
           (uri.scheme in ["http", "https"] and is_binary(uri.host) and is_nil(uri.userinfo)) or
             {:error, :invalid_redirect},
         true <-
           not (state.uri.scheme == "https" and uri.scheme == "http") or
             {:error, :insecure_redirect},
         :ok <- redirect_identity(state, uri),
         {:ok, _} <- HTTP.Runtime.Options.validate(uri, Map.from_struct(state.options)) do
      headers =
        if same_origin?(state.uri, uri),
          do: state.headers,
          else:
            Enum.reject(state.headers, fn {name, _} ->
              String.downcase(name) in ["authorization", "proxy-authorization", "cookie", "host"]
            end)

      options = %{state.options | uri: uri, url: URI.to_string(uri), headers: headers}

      next = %{
        state
        | uri: uri,
          headers: headers,
          options: options,
          redirects: state.redirects + 1
      }

      {:halt, connect(next)}
    else
      {:error, reason} -> {:halt, fatal(state, reason)}
    end
  rescue
    _ -> {:halt, fatal(state, :invalid_redirect)}
  end

  defp redirect_identity(state, uri) do
    if not same_origin?(state.uri, uri) and
         Enum.any?([:cert, :certfile, :key, :keyfile], &Keyword.has_key?(state.ssl, &1)),
       do: {:error, :client_identity_cross_origin_redirect},
       else: :ok
  end

  defp same_origin?(left, right),
    do: {left.scheme, left.host, left.port} == {right.scheme, right.host, right.port}

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

  defp stream_telemetry(state, event, outcome) do
    status = Delivery.status(state.delivery)

    HTTP.Runtime.Telemetry.stream(
      :event_source,
      event,
      state.http_version || :unknown,
      outcome,
      %{
        queued_bytes: status.queued_bytes,
        queued_events: status.queued_events,
        raw_bytes: state.raw_bytes
      }
    )
  end

  defp emit(state, event) do
    send(state.owner, {EventSource, state.target, event})
  end
end
