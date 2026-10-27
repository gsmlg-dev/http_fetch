defmodule HTTP.ProtocolClient.Session do
  @moduledoc false
  use GenServer

  alias HTTP.{Headers, HTTP1, Request}
  alias HTTP.HTTP2.{ConnectionOwner, Settings, WireProfile}

  @max_streams 16
  @max_events 256
  @max_event_bytes 1_048_576
  @max_request_bytes 1_048_576

  def config(url, options) when is_binary(url) and is_list(options) do
    uri = URI.parse(url)
    timeout = Keyword.get(options, :timeout, 5_000)
    protocol = Keyword.get(options, :protocol, :http2)

    with true <- Keyword.keyword?(options),
         true <- Keyword.keys(options) -- [:timeout, :protocol, :settings] == [],
         true <- uri.scheme == "http" and is_binary(uri.host) and uri.host != "",
         true <- uri.userinfo == nil and uri.fragment == nil,
         true <- is_integer(timeout) and timeout > 0,
         true <- protocol in [:http1, :http2],
         {:ok, entries} <- settings(Keyword.get(options, :settings, [])) do
      {:ok, %{uri: uri, timeout: timeout, protocol: protocol, settings: entries, id: make_ref()}}
    else
      _ -> {:error, :invalid_options}
    end
  rescue
    _ -> {:error, :invalid_options}
  end

  def config(_, _), do: {:error, :invalid_options}

  defp settings(entries) when is_list(entries) do
    if Enum.all?(entries, fn
         {key, value} -> (is_atom(key) or is_integer(key)) and is_integer(value)
         _ -> false
       end) do
      entries =
        Enum.map(entries, fn {key, value} ->
          {if(is_atom(key), do: Settings.id(key) || key, else: key), value}
        end)

      with :ok <- Settings.validate(entries),
           true <- Enum.all?(entries, fn {key, value} -> key != 2 or value == 0 end) do
        {:ok, [{2, 0} | Enum.reject(entries, &(elem(&1, 0) == 2))]}
      else
        _ -> {:error, :invalid_settings}
      end
    else
      {:error, :invalid_settings}
    end
  end

  defp settings(_), do: {:error, :invalid_settings}

  @impl true
  def init({creator, config}) do
    Process.flag(:trap_exit, true)
    deadline = now() + config.timeout

    opts = [
      :binary,
      active: false,
      send_timeout: min(config.timeout, 1_000),
      send_timeout_close: true
    ]

    case :gen_tcp.connect(
           String.to_charlist(config.uri.host),
           config.uri.port,
           opts,
           config.timeout
         ) do
      {:ok, socket} ->
        state = %{
          id: config.id,
          creator_monitor: Process.monitor(creator),
          uri: config.uri,
          protocol: config.protocol,
          timeout: config.timeout,
          socket: socket,
          owner: nil,
          requests: %{},
          parser: nil,
          events: :queue.new(),
          event_count: 0,
          event_bytes: 0,
          waiter: nil,
          closed?: false
        }

        with {:ok, local} <- :inet.sockname(socket),
             {:ok, peer} <- :inet.peername(socket),
             {:ok, state} <- activate(state, config.settings, deadline) do
          {:ok, Map.merge(state, %{local_address: local, peer_address: peer})}
        else
          {:error, reason} ->
            :gen_tcp.close(socket)
            {:stop, reason}
        end

      {:error, reason} ->
        {:stop, reason}
    end
  end

  defp activate(%{protocol: :http1} = state, _entries, _deadline) do
    with :ok <- :inet.setopts(state.socket, active: :once), do: {:ok, state}
  end

  defp activate(state, entries, deadline) do
    Code.ensure_loaded!(HTTP.Transport.TCP)
    window = entries |> Enum.filter(&(elem(&1, 0) == 4)) |> List.last({4, 65_535}) |> elem(1)
    profile = %{WireProfile.native_v1() | settings: entries, stream_initial_window: window}

    with {:ok, owner} <-
           ConnectionOwner.start_link(
             socket: state.socket,
             transport: HTTP.Transport.TCP,
             activate?: false,
             profile: profile,
             max_streams: @max_streams,
             write_timeout: min(state.timeout, 1_000)
           ) do
      case :gen_tcp.controlling_process(state.socket, owner) do
        :ok ->
          case ConnectionOwner.activate(owner, deadline) do
            :ok -> {:ok, %{state | owner: owner}}
            {:error, reason} -> stop_failed_owner(owner, reason)
          end

        {:error, reason} ->
          stop_failed_owner(owner, reason)
      end
    end
  end

  defp stop_failed_owner(owner, reason) do
    with :ok <- stop_owner(owner, now() + 1_000), do: {:error, reason}
  end

  @impl true
  def handle_call({id, operation, deadline}, from, %{id: id} = state) do
    if operation != :recv and deadline <= now() do
      {:reply, {:error, :timeout}, state}
    else
      dispatch(operation, deadline, from, state)
    end
  end

  def handle_call(_, _from, state), do: {:reply, {:error, :invalid_session}, state}

  defp dispatch(:connection_info, _deadline, _from, state) do
    info = Map.take(state, [:id, :protocol, :local_address, :peer_address, :closed?])
    {:reply, {:ok, info}, state}
  end

  defp dispatch(:close, deadline, _from, state) do
    {result, state} = close_resources(state, deadline)
    {:stop, :normal, result, state}
  end

  defp dispatch(:recv, deadline, from, state) do
    cond do
      state.event_count > 0 ->
        {:reply, {:ok, :queue.to_list(state.events)},
         %{state | events: :queue.new(), event_count: 0, event_bytes: 0}}

      state.closed? ->
        {:reply, {:error, :closed}, state}

      state.waiter != nil ->
        {:reply, {:error, :receive_pending}, state}

      deadline <= now() ->
        {:reply, {:error, :timeout}, state}

      true ->
        token = make_ref()
        timer = Process.send_after(self(), {:receive_timeout, token}, remaining(deadline))
        {:noreply, %{state | waiter: {from, token, timer}}}
    end
  end

  defp dispatch(_operation, _deadline, _from, %{closed?: true} = state),
    do: {:reply, {:error, :closed}, state}

  defp dispatch({:request, method, path, headers, body}, deadline, _from, state) do
    with {:ok, request} <- build_request(state.uri, method, path, headers, body),
         true <- map_size(state.requests) < @max_streams || {:error, :capacity} do
      submit_request(state, request, deadline)
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp dispatch({:put_settings, entries}, deadline, _from, %{protocol: :http2} = state) do
    case settings(entries) do
      {:ok, entries} -> {:reply, owner_call(state, {:put_settings, entries}, deadline), state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp dispatch({:put_settings, _}, _deadline, _from, state),
    do: {:reply, {:error, :http2_required}, state}

  defp dispatch({:acknowledge, ref}, deadline, _from, %{protocol: :http2} = state) do
    case Map.fetch(state.requests, ref) do
      {:ok, id} -> {:reply, owner_call(state, {:acknowledge, id}, deadline), state}
      :error -> {:reply, {:error, :unknown_request}, state}
    end
  end

  defp dispatch({:acknowledge, _}, _deadline, _from, state),
    do: {:reply, {:error, :http2_required}, state}

  defp dispatch({:cancel, ref}, deadline, _from, state) do
    case Map.fetch(state.requests, ref) do
      :error ->
        {:reply, {:error, :unknown_request}, state}

      {:ok, id} when state.protocol == :http2 ->
        case owner_call(state, {:cancel, id}, deadline) do
          :ok ->
            state = finish(state, ref, {:error, ref, :cancelled})
            {:reply, :ok, state}

          error ->
            {:reply, error, state}
        end

      {:ok, _} ->
        {result, state} = close_resources(state, deadline)
        state = emit(%{state | requests: %{}, parser: nil}, {:error, ref, :cancelled})
        {:reply, result, state}
    end
  end

  defp build_request(uri, method, path, headers, body)
       when is_binary(path) and is_list(headers) and is_binary(body) and
              byte_size(body) <= @max_request_bytes do
    path_uri = URI.parse(path)

    if String.starts_with?(path, "/") and path_uri.host == nil and path_uri.fragment == nil and
         valid_headers?(headers) do
      request = %Request{
        url: %{uri | path: path_uri.path, query: path_uri.query},
        method: method,
        request_mode: :proxy,
        headers: Headers.new(headers),
        body: body
      }

      _ = Request.method_token(method)
      _ = Request.origin_form(request.url)
      _ = Request.to_iodata(request)
      {:ok, request}
    else
      {:error, :invalid_request}
    end
  rescue
    _ -> {:error, :invalid_request}
  end

  defp build_request(_, _, _, _, _), do: {:error, :invalid_request}

  defp valid_headers?(headers) do
    Enum.all?(headers, fn
      {name, value} when is_binary(name) and is_binary(value) ->
        name != "" and not String.starts_with?(name, ":") and
          not String.contains?(name <> value, ["\r", "\n", <<0>>])

      _ ->
        false
    end)
  end

  defp submit_request(%{protocol: :http1, requests: requests} = state, _request, _deadline)
       when map_size(requests) > 0,
       do: {:reply, {:error, :request_in_progress}, state}

  defp submit_request(%{protocol: :http1} = state, request, _deadline) do
    case :gen_tcp.send(state.socket, Request.to_iodata(request)) do
      :ok ->
        ref = make_ref()

        method =
          if Request.method_token(request.method) == "HEAD", do: :head, else: request.method

        parser = HTTP1.new(method)
        {:reply, {:ok, ref}, %{state | requests: %{ref => 1}, parser: parser}}

      {:error, reason} ->
        {:reply, {:error, reason}, disconnect(state, reason)}
    end
  end

  defp submit_request(state, request, deadline) do
    headers =
      [
        {":method", Request.method_token(request.method)},
        {":scheme", "http"},
        {":authority", Request.authority(state.uri)},
        {":path", Request.origin_form(request.url)}
      ] ++
        Enum.map(request.headers.headers, fn {name, value} -> {String.downcase(name), value} end)

    options = [subscriber: self(), end_stream: request.body == "", byte_stream: true]

    case owner_call(state, {:open_stream, headers, options}, deadline) do
      {:ok, %{id: id, ref: ref}} ->
        state = put_in(state.requests[ref], id)

        case send_body(state, id, request.body, deadline) do
          :ok ->
            {:reply, {:ok, ref}, state}

          {:error, reason} ->
            _ = owner_call(state, {:cancel, id}, deadline)
            _ = owner_call(state, {:release_stream, id}, deadline)
            {:reply, {:error, reason}, %{state | requests: Map.delete(state.requests, ref)}}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  defp send_body(_state, _id, "", _deadline), do: :ok

  defp send_body(state, id, body, deadline),
    do: owner_call(state, {:send_data, id, body, true}, deadline)

  defp owner_call(state, message, deadline) do
    GenServer.call(state.owner, message, max(remaining(deadline), 1))
  catch
    :exit, {:timeout, _} -> {:error, :operation_unconfirmed}
    :exit, _ -> {:error, :closed}
  end

  @impl true
  def handle_info({:tcp, socket, data}, %{socket: socket, protocol: :http1} = state) do
    state = parse_http1(state, data)

    state =
      if state.closed? do
        state
      else
        case :inet.setopts(socket, active: :once) do
          :ok -> state
          {:error, reason} -> disconnect(state, reason)
        end
      end

    {:noreply, state}
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket, protocol: :http1} = state) do
    state = close_http1(state)
    {:noreply, disconnect(state, :closed)}
  end

  def handle_info({:tcp_error, socket, reason}, %{socket: socket} = state),
    do: {:noreply, disconnect(state, reason)}

  def handle_info({:http2, id, event}, state) do
    case Enum.find(state.requests, fn {_ref, stream_id} -> stream_id == id end) do
      {ref, ^id} -> {:noreply, h2_event(state, ref, event)}
      nil -> {:noreply, state}
    end
  end

  def handle_info({:receive_timeout, token}, %{waiter: {from, token, _timer}} = state) do
    GenServer.reply(from, {:error, :timeout})
    {:noreply, %{state | waiter: nil}}
  end

  def handle_info({:DOWN, monitor, :process, _, _}, %{creator_monitor: monitor} = state),
    do: {:stop, :normal, state}

  def handle_info({:EXIT, owner, reason}, %{owner: owner} = state),
    do: {:noreply, disconnect(state, {:connection_down, reason})}

  def handle_info(_, state), do: {:noreply, state}

  defp parse_http1(%{parser: nil} = state, _data), do: disconnect(state, :unexpected_response)

  defp parse_http1(state, data) do
    case HTTP1.stream(state.parser, data) do
      {:ok, parser, events} ->
        ref = state.requests |> Map.keys() |> hd()
        state = Enum.reduce(events, %{state | parser: parser}, &h1_event(&2, ref, &1))

        if parser.state == :done and parser.buffer != "",
          do: disconnect(state, :unexpected_response_bytes),
          else: state

      {:error, reason} ->
        disconnect(state, reason)
    end
  end

  defp close_http1(%{parser: nil} = state), do: state

  defp close_http1(state) do
    case HTTP1.close(state.parser) do
      {:ok, parser, events} ->
        ref = state.requests |> Map.keys() |> hd()
        Enum.reduce(events, %{state | parser: parser}, &h1_event(&2, ref, &1))

      {:error, _} ->
        state
    end
  end

  defp h1_event(%{closed?: true} = state, _ref, _event), do: state

  defp h1_event(state, ref, {:headers, status, headers}),
    do: emit(state, {:headers, ref, status, headers.headers})

  defp h1_event(state, ref, {:body, data}), do: emit(state, {:data, ref, data})

  defp h1_event(state, ref, {:trailers, headers}),
    do: emit(state, {:trailers, ref, headers.headers})

  defp h1_event(state, ref, :done) do
    connection = (Headers.get(state.parser.headers, "connection") || "") |> String.downcase()

    close? =
      state.parser.version != "1.1" or
        "close" in Enum.map(String.split(connection, ",", trim: true), &String.trim/1)

    state = emit(%{state | requests: %{}, parser: nil}, {:done, ref})
    if close?, do: disconnect(state, :response_close), else: state
  end

  defp h2_event(state, ref, {:http2, :headers, headers, flags}) do
    state =
      case List.keyfind(headers, ":status", 0) do
        {":status", status} ->
          emit(
            state,
            {:headers, ref, String.to_integer(status),
             Enum.reject(headers, &(elem(&1, 0) == ":status"))}
          )

        nil ->
          emit(state, {:trailers, ref, headers})
      end

    if Bitwise.band(flags, 1) == 1, do: finish(state, ref, {:done, ref}), else: state
  end

  defp h2_event(state, ref, {:http2, :data, data, flags}) do
    state = emit(state, {:data, ref, data})
    if Bitwise.band(flags, 1) == 1, do: finish(state, ref, {:done, ref}), else: state
  end

  defp h2_event(state, ref, {:http2, :reset, reason}),
    do: finish(state, ref, {:error, ref, {:reset, reason}})

  defp h2_event(state, ref, {:http2, :cancelled}),
    do: finish(state, ref, {:error, ref, :cancelled})

  defp h2_event(state, ref, reason), do: finish(state, ref, {:error, ref, reason})

  defp finish(%{closed?: true} = state, _ref, _event), do: state

  defp finish(state, ref, event) do
    case Map.fetch(state.requests, ref) do
      {:ok, id} when state.protocol == :http2 ->
        _ = owner_call(state, {:release_stream, id}, now() + 1_000)

      _ ->
        :ok
    end

    emit(%{state | requests: Map.delete(state.requests, ref)}, event)
  end

  defp emit(%{waiter: {from, _token, timer}} = state, event) do
    _ = Process.cancel_timer(timer)
    GenServer.reply(from, {:ok, [event]})
    %{state | waiter: nil}
  end

  defp emit(state, event) do
    bytes = event_bytes(event)

    if state.event_count >= @max_events or state.event_bytes + bytes > @max_event_bytes do
      {_result, state} = close_resources(state, now() + 1_000)

      %{
        state
        | requests: %{},
          parser: nil,
          events: :queue.from_list([{:closed, :event_buffer_full}]),
          event_count: 1,
          event_bytes: 0
      }
    else
      %{
        state
        | events: :queue.in(event, state.events),
          event_count: state.event_count + 1,
          event_bytes: state.event_bytes + bytes
      }
    end
  end

  defp event_bytes({:data, _, data}), do: byte_size(data)
  defp event_bytes({:headers, _, _, fields}), do: fields_bytes(fields)
  defp event_bytes({:trailers, _, fields}), do: fields_bytes(fields)
  defp event_bytes(_), do: 0

  defp fields_bytes(fields),
    do:
      Enum.reduce(fields, 0, fn {name, value}, sum -> sum + byte_size(name) + byte_size(value) end)

  defp disconnect(%{closed?: true} = state, _reason), do: state

  defp disconnect(state, reason) do
    {_result, state} = close_resources(state, now() + 1_000)

    state =
      Enum.reduce(state.requests, state, fn {ref, _}, acc -> emit(acc, {:error, ref, reason}) end)

    emit(%{state | requests: %{}, parser: nil}, {:closed, reason})
  end

  defp close_resources(state, deadline) do
    owner_result = stop_owner(state.owner, deadline)
    socket_result = if state.socket, do: :gen_tcp.close(state.socket), else: :ok
    confirmed? = state.socket == nil or :erlang.port_info(state.socket) == :undefined

    result =
      if owner_result == :ok and socket_result == :ok and confirmed?,
        do: :ok,
        else: {:error, :cleanup_unconfirmed}

    {result, %{state | socket: nil, owner: nil, closed?: true}}
  end

  defp stop_owner(nil, _deadline), do: :ok

  defp stop_owner(owner, deadline) do
    monitor = Process.monitor(owner)

    try do
      if Process.alive?(owner),
        do: GenServer.stop(owner, :normal, max(div(remaining(deadline), 2), 1))
    catch
      :exit, _ -> Process.exit(owner, :kill)
    end

    receive do
      {:DOWN, ^monitor, :process, ^owner, _reason} -> :ok
    after
      remaining(deadline) ->
        Process.demonitor(monitor, [:flush])
        {:error, :cleanup_unconfirmed}
    end
  end

  @impl true
  def terminate(_reason, state) do
    _ = close_resources(state, now() + 1_000)
    :ok
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp remaining(deadline), do: max(deadline - now(), 0)
end
