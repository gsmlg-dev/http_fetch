defmodule HTTP.SocketClient do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request
  alias HTTP.Response

  @max_redirects 5

  @spec request(Request.t(), pid() | nil, String.t() | nil) :: Response.t() | {:error, term()}
  def request(%Request{} = request, abort_controller_pid \\ nil, unix_socket_path \\ nil) do
    ref = make_ref()
    parent = self()
    timeout = request_timeout(request)
    deadline_at = System.monotonic_time(:millisecond) + timeout

    case Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
           owner(parent, ref, request, unix_socket_path, 0, false, deadline_at)
         end) do
      {:ok, owner_pid} ->
        set_abort_owner(abort_controller_pid, owner_pid)
        await_owner(ref, owner_pid, timeout)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp owner(parent, ref, request, unix_socket_path, redirects, redirected?, deadline_at) do
    case remaining_timeout(deadline_at) do
      0 ->
        send_error(parent, ref, :request_timeout)

      timeout ->
        timer_ref = Process.send_after(self(), :deadline, timeout)

        with {:ok, transport, host, port} <- select_transport(request, unix_socket_path),
             {:ok, wire_request} <- serialize_request(request),
             {:ok, socket} <- connect(transport, host, port, request, timeout),
             :ok <- send_request(transport, socket, wire_request, timeout),
             :ok <- activate_socket(transport, socket) do
          state = %{
            parent: parent,
            ref: ref,
            request: request,
            unix_socket_path: unix_socket_path,
            redirects: redirects,
            redirected?: redirected?,
            deadline_at: deadline_at,
            timer_ref: timer_ref,
            transport: transport,
            socket: socket,
            protocol: HTTP.HTTP1.new(request.method),
            mode: nil,
            response_sent?: false
          }

          owner_loop(state)
        else
          {:error, reason} ->
            _ = Process.cancel_timer(timer_ref)
            send_error(parent, ref, reason)
        end
    end
  end

  defp serialize_request(%Request{} = request) do
    {:ok, HTTP.HTTP1.serialize_request(request)}
  rescue
    error -> {:error, error}
  end

  defp owner_loop(state) do
    receive do
      :abort ->
        fail(state, :aborted)

      :deadline ->
        fail(state, :request_timeout)

      message ->
        case state.transport.normalize_message(message, state.socket) do
          {:data, data} -> handle_data(state, data)
          :closed -> handle_closed(state)
          {:error, reason} -> fail(state, reason)
          :unknown -> owner_loop(state)
        end
    end
  end

  defp handle_data(state, data) do
    case HTTP.HTTP1.stream(state.protocol, data) do
      {:ok, protocol, events} ->
        %{state | protocol: protocol}
        |> handle_events(events)

      {:error, reason} ->
        fail(state, reason)
    end
  end

  defp handle_closed(state) do
    case HTTP.HTTP1.close(state.protocol) do
      {:ok, protocol, events} ->
        %{state | protocol: protocol}
        |> handle_events(events)

      {:error, reason} ->
        fail(state, reason)
    end
  end

  defp handle_events(state, events) do
    Enum.reduce_while(events, {:continue, state}, fn event, {:continue, acc} ->
      case handle_event(acc, event) do
        {:continue, next} -> {:cont, {:continue, next}}
        :done -> {:halt, :done}
      end
    end)
    |> case do
      {:continue, next} -> rearm(next)
      :done -> :ok
    end
  end

  defp handle_event(state, {:headers, status, headers}) do
    response =
      Response.new(
        status: status,
        headers: headers,
        body: nil,
        url: state.request.url,
        redirected: state.redirected?
      )

    cond do
      follow_redirect?(state, response) ->
        redirect(state, response)

      stream_response?(state.request, status, headers) ->
        content_length = stream_content_length(headers)
        {:ok, stream_pid} = HTTP.Stream.start_link(content_length)
        response = %{response | stream: stream_pid}
        send_response(state.parent, state.ref, response)

        {:continue, %{state | mode: {:stream, stream_pid}, response_sent?: true}}

      true ->
        {:continue, %{state | mode: {:buffer, response, []}}}
    end
  end

  defp handle_event(%{mode: {:stream, stream_pid}} = state, {:body, chunk}) do
    case HTTP.Stream.chunk(stream_pid, chunk, stream_chunk_timeout(state.deadline_at)) do
      :ok -> {:continue, state}
      {:error, reason} -> fail(state, reason)
    end
  end

  defp handle_event(%{mode: {:buffer, response, chunks}} = state, {:body, chunk}) do
    {:continue, %{state | mode: {:buffer, response, [chunk | chunks]}}}
  end

  defp handle_event(%{mode: {:stream, stream_pid}} = state, :done) do
    HTTP.Stream.finish(stream_pid)
    finish(state)
  end

  defp handle_event(%{mode: {:buffer, response, chunks}} = state, :done) do
    body =
      chunks
      |> Enum.reverse()
      |> IO.iodata_to_binary()

    response = %{response | body: body, stream: nil}

    if follow_redirect?(state, response) do
      redirect(state, response)
    else
      send_response(state.parent, state.ref, response)
      finish(state)
    end
  end

  defp handle_event(state, :done) do
    send_error(state.parent, state.ref, :invalid_http_response)
    finish(state)
  end

  defp rearm(state) do
    case state.transport.setopts(state.socket, active: :once) do
      :ok -> owner_loop(state)
      {:error, reason} -> fail(state, reason)
    end
  end

  defp redirect(state, response) do
    case redirect_request(state.request, response) do
      {:ok, request} ->
        cleanup(state)

        owner(
          state.parent,
          state.ref,
          request,
          state.unix_socket_path,
          state.redirects + 1,
          true,
          state.deadline_at
        )

        :done

      {:error, _reason} ->
        send_response(state.parent, state.ref, response)
        finish(state)
    end
  end

  defp fail(state, reason) do
    if state.response_sent? do
      case state.mode do
        {:stream, stream_pid} -> HTTP.Stream.error(stream_pid, reason)
        _ -> :ok
      end
    else
      send_error(state.parent, state.ref, reason)
    end

    finish(state)
  end

  defp finish(state) do
    cleanup(state)
    :done
  end

  defp cleanup(state) do
    _ = Process.cancel_timer(state.timer_ref)
    state.transport.close(state.socket)
  end

  defp await_owner(ref, owner_pid, timeout) do
    monitor_ref = Process.monitor(owner_pid)

    receive do
      {:http_fetch_response, ^ref, response} ->
        Process.demonitor(monitor_ref, [:flush])
        response

      {:http_fetch_error, ^ref, reason} ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, reason}

      {:DOWN, ^monitor_ref, :process, ^owner_pid, reason} ->
        {:error, {:request_process_down, reason}}
    after
      timeout + 1_000 ->
        send(owner_pid, :abort)
        Process.demonitor(monitor_ref, [:flush])
        {:error, :request_timeout}
    end
  end

  defp send_response(parent, ref, response),
    do: send(parent, {:http_fetch_response, ref, response})

  defp send_error(parent, ref, reason), do: send(parent, {:http_fetch_error, ref, reason})

  defp set_abort_owner(nil, _owner_pid), do: :ok

  defp set_abort_owner(pid, owner_pid) when is_pid(pid),
    do: HTTP.AbortController.set_request_id(pid, owner_pid)

  defp set_abort_owner(_other, _owner_pid), do: :ok

  defp connect(transport, host, port, request, timeout) do
    connect_timeout = min(connect_timeout(request), timeout)

    interruptible_connect(
      transport,
      host,
      port,
      transport_opts(request, timeout),
      connect_timeout
    )
  end

  defp interruptible_connect(transport, host, port, opts, timeout) do
    parent = self()
    ref = make_ref()
    deadline_at = System.monotonic_time(:millisecond) + timeout

    case Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
           result = connect_in_worker(transport, host, port, opts, timeout, parent, ref)
           send(parent, {:connect_result, ref, result})
         end) do
      {:ok, pid} ->
        await_connect_result(transport, pid, ref, nil, deadline_at)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp await_connect_result(transport, pid, ref, socket, deadline_at) do
    receive do
      {:connect_socket, ^ref, connected_socket} ->
        send(pid, {:transfer_socket, ref})
        await_connect_result(transport, pid, ref, connected_socket, deadline_at)

      {:connect_result, ^ref, result} ->
        result

      :abort ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        Process.exit(pid, :kill)
        {:error, :aborted}

      :deadline ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        Process.exit(pid, :kill)
        {:error, :request_timeout}
    after
      remaining_timeout(deadline_at) ->
        send(pid, {:close_socket, ref})
        close_connect_socket(transport, socket)
        Process.exit(pid, :kill)
        {:error, :connect_timeout}
    end
  end

  defp close_connect_socket(_transport, nil), do: :ok
  defp close_connect_socket(transport, socket), do: transport.close(socket)

  defp connect_in_worker(transport, host, port, opts, timeout, owner, ref) do
    case transport.connect(host, port, opts, timeout) do
      {:ok, socket} ->
        send(owner, {:connect_socket, ref, socket})
        transfer_connected_socket(transport, socket, owner, ref, timeout)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp transfer_connected_socket(transport, socket, owner, ref, timeout) do
    receive do
      {:transfer_socket, ^ref} ->
        case transport.controlling_process(socket, owner) do
          :ok ->
            {:ok, socket}

          {:error, reason} ->
            transport.close(socket)
            {:error, reason}
        end

      {:close_socket, ^ref} ->
        transport.close(socket)
        {:error, :aborted}
    after
      timeout ->
        transport.close(socket)
        {:error, :connect_timeout}
    end
  end

  defp send_request(transport, socket, iodata, timeout) do
    parent = self()
    ref = make_ref()

    case Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
           send(parent, {:send_result, ref, transport.send(socket, iodata)})
         end) do
      {:ok, pid} ->
        receive do
          {:send_result, ^ref, result} ->
            close_on_error(transport, socket, result)

          :abort ->
            transport.close(socket)
            Process.exit(pid, :kill)
            {:error, :aborted}

          :deadline ->
            transport.close(socket)
            Process.exit(pid, :kill)
            {:error, :request_timeout}
        after
          timeout ->
            transport.close(socket)
            Process.exit(pid, :kill)
            {:error, :request_timeout}
        end

      {:error, reason} ->
        transport.close(socket)
        {:error, reason}
    end
  end

  defp close_on_error(_transport, _socket, :ok), do: :ok

  defp close_on_error(transport, socket, {:error, reason}) do
    transport.close(socket)
    {:error, reason}
  end

  defp activate_socket(transport, socket) do
    case transport.setopts(socket, active: :once) do
      :ok ->
        :ok

      {:error, reason} ->
        transport.close(socket)
        {:error, reason}
    end
  end

  defp select_transport(_request, socket_path) when is_binary(socket_path) do
    {:ok, HTTP.Transport.Unix, socket_path, 0}
  end

  defp select_transport(%Request{url: %URI{scheme: "http", host: host} = uri}, _socket_path)
       when is_binary(host) do
    {:ok, HTTP.Transport.TCP, host, uri.port || 80}
  end

  defp select_transport(%Request{url: %URI{scheme: "https", host: host} = uri}, _socket_path)
       when is_binary(host) do
    {:ok, HTTP.Transport.SSL, host, uri.port || 443}
  end

  defp select_transport(%Request{url: %URI{scheme: scheme}}, _socket_path) do
    {:error, {:unsupported_scheme, scheme}}
  end

  defp request_timeout(%Request{} = request) do
    Keyword.get(request.http_options, :timeout, HTTP.Config.default_request_timeout())
  end

  defp connect_timeout(%Request{} = request) do
    Keyword.get(request.http_options, :connect_timeout, min(request_timeout(request), 30_000))
  end

  defp transport_opts(%Request{} = request, timeout) do
    socket_opts =
      request.options
      |> Keyword.get(:socket_opts, [])
      |> Keyword.put_new(:send_timeout, max(timeout, 1))
      |> Keyword.put_new(:send_timeout_close, true)

    [
      ssl: Keyword.get(request.http_options, :ssl, []),
      socket_opts: socket_opts
    ]
  end

  defp remaining_timeout(deadline_at) do
    max(deadline_at - System.monotonic_time(:millisecond), 0)
  end

  defp stream_chunk_timeout(deadline_at) do
    min(remaining_timeout(deadline_at), HTTP.Config.streaming_timeout())
  end

  defp stream_response?(request, status, headers) do
    !HTTP.HTTP1.body_forbidden?(request.method, status) &&
      should_use_streaming?(headers)
  end

  defp should_use_streaming?(headers) do
    threshold = HTTP.Config.streaming_threshold()
    content_length = Headers.get(headers, "content-length")

    case HTTP.HTTP1.response_body_framing(headers) do
      :chunked ->
        true

      :identity ->
        case Integer.parse(content_length || "") do
          {size, ""} -> size > threshold
          _ -> is_nil(content_length)
        end

      {:error, _reason} ->
        false
    end
  end

  defp stream_content_length(headers) do
    case HTTP.HTTP1.response_body_framing(headers) do
      :chunked -> 0
      _ -> headers |> Headers.get("content-length") |> parse_content_length()
    end
  end

  defp parse_content_length(content_length) do
    case Integer.parse(content_length || "") do
      {size, ""} -> size
      _ -> 0
    end
  end

  defp follow_redirect?(state, response) do
    Keyword.get(state.request.http_options, :autoredirect, true) &&
      state.redirects < @max_redirects &&
      redirect_candidate?(state.request, response.status, response.headers)
  end

  defp redirect_candidate?(_request, status, headers) when status in [301, 302, 303, 307, 308] do
    is_binary(Headers.get(headers, "location"))
  end

  defp redirect_candidate?(_request, _status, _headers), do: false

  defp redirect_request(request, response) do
    with location when is_binary(location) <- Headers.get(response.headers, "location"),
         %URI{} = uri <- URI.merge(request.url, location) do
      request =
        request
        |> rewrite_redirect_method(response.status)
        |> strip_redirect_headers(cross_origin?(request.url, uri))

      {:ok, %{request | url: uri}}
    else
      _ -> {:error, :invalid_redirect}
    end
  end

  defp rewrite_redirect_method(%{method: :post} = request, status) when status in [301, 302],
    do: drop_redirect_body(request)

  defp rewrite_redirect_method(request, 303) when request.method not in [:get, :head],
    do: drop_redirect_body(request)

  defp rewrite_redirect_method(request, _status), do: request

  defp drop_redirect_body(request) do
    %{
      request
      | method: :get,
        body: nil,
        content_type: nil,
        headers: delete_entity_headers(request.headers)
    }
  end

  defp delete_entity_headers(headers) do
    headers
    |> Headers.delete("Content-Encoding")
    |> Headers.delete("Content-Language")
    |> Headers.delete("Content-Location")
    |> Headers.delete("Content-Length")
    |> Headers.delete("Content-Type")
    |> Headers.delete("Transfer-Encoding")
    |> Headers.delete("Trailer")
  end

  defp strip_redirect_headers(request, cross_origin?) do
    headers = Headers.delete(request.headers, "Host")

    headers =
      if cross_origin? do
        headers
        |> Headers.delete("Authorization")
        |> Headers.delete("Proxy-Authorization")
        |> Headers.delete("Cookie")
      else
        headers
      end

    %{request | headers: headers}
  end

  defp cross_origin?(%URI{} = left, %URI{} = right) do
    {left.scheme, left.host, left.port || HTTP.HTTP1.default_port(left.scheme)} !=
      {right.scheme, right.host, right.port || HTTP.HTTP1.default_port(right.scheme)}
  end
end
