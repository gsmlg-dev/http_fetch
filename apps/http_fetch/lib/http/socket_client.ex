defmodule HTTP.SocketClient do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.HTTP2.Frame
  alias HTTP.Request
  alias HTTP.Response

  @max_redirects 5

  @spec request(Request.t(), pid() | nil, String.t() | nil) :: Response.t() | {:error, term()}
  def request(%Request{} = request, abort_controller_pid \\ nil, unix_socket_path \\ nil) do
    cond do
      http_version(request) == :http3 and tls_backend(request) != nil ->
        {:error, :tls_backend_not_supported_for_quic}

      http_version(request) == :http3 and Request.streaming_body?(request) ->
        {:error, :streaming_request_body_unsupported_for_http3}

      http_version(request) == :http3 ->
        request_http3(request, abort_controller_pid, unix_socket_path)

      true ->
        with {:ok, request} <- pin_tls_backend(request) do
          request_socket(request, abort_controller_pid, unix_socket_path)
        end
    end
  end

  @doc false
  def connect_http2(%Request{} = request, unix_socket_path, timeout) do
    with {:ok, transport, host, port} <- select_transport(request, unix_socket_path),
         {:ok, selection} <- protocol_selection(request, transport),
         {:ok, socket} <- connect(transport, host, port, request, selection, timeout) do
      {:ok, transport, socket, selection}
    end
  end

  defp request_socket(%Request{} = request, abort_controller_pid, unix_socket_path) do
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

  defp request_http3(_request, _abort_controller_pid, unix_socket_path)
       when is_binary(unix_socket_path) do
    {:error, {:unsupported_http_version_for_unix_socket, :http3}}
  end

  defp request_http3(%Request{} = request, abort_controller_pid, _unix_socket_path) do
    ref = make_ref()
    parent = self()
    timeout = request_timeout(request)
    deadline_at = System.monotonic_time(:millisecond) + timeout

    case Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
           http3_owner(parent, ref, request, 0, false, deadline_at)
         end) do
      {:ok, owner_pid} ->
        set_abort_owner(abort_controller_pid, owner_pid)
        await_owner(ref, owner_pid, timeout)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp http3_owner(parent, ref, request, redirects, redirected?, deadline_at) do
    case remaining_timeout(deadline_at) do
      0 ->
        send_error(parent, ref, :request_timeout)

      timeout ->
        request = put_request_timeout(request, timeout)

        state = %{
          parent: parent,
          ref: ref,
          request: request,
          redirects: redirects,
          redirected?: redirected?,
          deadline_at: deadline_at,
          mode: nil,
          response_sent?: false,
          action: nil
        }

        case HTTP.HTTP3.request(request, state, &handle_http3_event/2) do
          {:ok, %{action: {:redirect, response}}} ->
            follow_http3_redirect(response, parent, ref, request, redirects, deadline_at)

          {:ok, _state} ->
            :ok

          {:error, reason, state} ->
            fail_http3(state, reason)
        end
    end
  end

  defp handle_http3_event(state, {:headers, status, headers}) do
    response =
      Response.new(
        status: status,
        headers: headers,
        body: nil,
        url: state.request.url,
        redirected: state.redirected?
      )

    cond do
      redirect_error?(state, response) ->
        {:error, :redirect, state}

      redirect_mode(state.request) == :follow and state.redirects >= @max_redirects and
          redirect_candidate?(state.request, response.status, response.headers) ->
        {:error, :too_many_redirects, state}

      follow_redirect?(state, response) ->
        {:halt, %{state | action: {:redirect, response}}}

      stream_response?(state.request, status, headers) ->
        content_length = stream_content_length(headers)
        {:ok, stream_pid} = HTTP.Stream.start_link(content_length)
        response = Response.with_stream_body(response, stream_pid)
        send_response(state.parent, state.ref, response)

        {:cont, %{state | mode: {:stream, stream_pid}, response_sent?: true}}

      true ->
        {:cont, %{state | mode: {:buffer, response, []}}}
    end
  end

  defp handle_http3_event(%{mode: {:stream, stream_pid}} = state, {:body, chunk}) do
    case HTTP.Stream.chunk(stream_pid, chunk, stream_chunk_timeout(state.deadline_at)) do
      :ok -> {:cont, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp handle_http3_event(%{mode: {:buffer, response, chunks}} = state, {:body, chunk}) do
    {:cont, %{state | mode: {:buffer, response, [chunk | chunks]}}}
  end

  defp handle_http3_event(%{mode: {:stream, stream_pid}} = state, :done) do
    HTTP.Stream.finish(stream_pid)
    {:halt, state}
  end

  defp handle_http3_event(%{mode: {:buffer, response, chunks}} = state, :done) do
    body =
      chunks
      |> Enum.reverse()
      |> IO.iodata_to_binary()

    response = Response.with_buffered_body(response, body)
    send_response(state.parent, state.ref, response)

    {:halt, state}
  end

  defp handle_http3_event(state, :done), do: {:error, :invalid_http_response, state}

  defp follow_http3_redirect(response, parent, ref, request, redirects, deadline_at) do
    case redirect_request(request, response) do
      {:ok, redirected_request} ->
        http3_owner(parent, ref, redirected_request, redirects + 1, true, deadline_at)

      {:error, _reason} ->
        send_response(parent, ref, response)
    end
  end

  defp fail_http3(state, reason) do
    if state.response_sent? do
      case state.mode do
        {:stream, stream_pid} -> HTTP.Stream.error(stream_pid, reason)
        _mode -> :ok
      end
    else
      send_error(state.parent, state.ref, reason)
    end
  end

  defp owner(parent, ref, request, unix_socket_path, redirects, redirected?, deadline_at) do
    case remaining_timeout(deadline_at) do
      0 ->
        send_error(parent, ref, :request_timeout)

      timeout ->
        timer_ref = Process.send_after(self(), :deadline, timeout)

        with {:ok, transport, host, port} <- select_transport(request, unix_socket_path),
             {:ok, selection} <- protocol_selection(request, transport),
             {:ok, socket} <-
               maybe_reused_http2_owner(parent, ref, request, selection, deadline_at) do
          case socket do
            {:reused, owner, reservation, key} ->
              _ = Process.cancel_timer(timer_ref)
              run_http2_reused_owner(parent, ref, request, owner, reservation, key, deadline_at)

            :connect ->
              with {:ok, socket} <- connect(transport, host, port, request, selection, timeout) do
                case maybe_http2_owner(
                       parent,
                       ref,
                       request,
                       selection,
                       transport,
                       socket,
                       deadline_at
                     ) do
                  {:handled, result} ->
                    _ = Process.cancel_timer(timer_ref)
                    result

                  :legacy ->
                    initialize_legacy_owner(
                      parent,
                      ref,
                      request,
                      unix_socket_path,
                      redirects,
                      redirected?,
                      deadline_at,
                      timer_ref,
                      transport,
                      socket,
                      selection
                    )
                end
              else
                {:error, reason} -> send_error(parent, ref, reason)
              end
          end
        else
          {:error, reason} ->
            _ = Process.cancel_timer(timer_ref)
            send_error(parent, ref, reason)
        end
    end
  end

  defp maybe_reused_http2_owner(_parent, _ref, request, selection, _deadline_at) do
    if selection.mode == :h2c and http2_profile?(request) and
         Keyword.get(request.transport_options, :http2_reuse, true) != false do
      profile = Keyword.fetch!(request.transport_options, :http2_profile)
      pool = Process.whereis(:http_fetch_http2_pool)

      with pool when is_pid(pool) <- pool,
           {:ok, key} <- HTTP.HTTP2.PoolKey.build(request, profile, :h2c),
           {:ok, owner, reservation} <- HTTP.HTTP2.Pool.try_reserve(pool, key) do
        {:ok, {:reused, owner, {pool, reservation}, key}}
      else
        _ -> {:ok, :connect}
      end
    else
      {:ok, :connect}
    end
  end

  defp initialize_legacy_owner(
         parent,
         ref,
         request,
         unix_socket_path,
         redirects,
         redirected?,
         deadline_at,
         timer_ref,
         transport,
         socket,
         selection
       ) do
    case initialize_protocol(transport, socket, request, selection) do
      {:ok, protocol_module, protocol, prepared_request} ->
        with :ok <-
               send_prepared_request(
                 transport,
                 socket,
                 prepared_request,
                 deadline_at
               ),
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
            protocol_module: protocol_module,
            protocol: protocol,
            mode: nil,
            response_sent?: false
          }

          owner_loop(state)
        else
          {:error, reason} ->
            transport.close(socket)
            _ = Process.cancel_timer(timer_ref)
            send_error(parent, ref, reason)
        end

      {:error, reason} ->
        transport.close(socket)
        _ = Process.cancel_timer(timer_ref)
        send_error(parent, ref, reason)
    end
  end

  defp maybe_http2_owner(
         parent,
         ref,
         %Request{} = request,
         selection,
         transport,
         socket,
         deadline_at
       ) do
    if not Keyword.has_key?(request.transport_options, :http2_profile) do
      :legacy
    else
      case connected_protocol(transport, socket, selection) do
        {:ok, :http2} ->
          {:handled, run_http2_owner(parent, ref, request, transport, socket, deadline_at)}

        _ ->
          :legacy
      end
    end
  end

  defp run_http2_owner(parent, ref, request, transport, socket, deadline_at) do
    profile = Keyword.get(request.transport_options, :http2_profile, :native_v1)

    with {:ok, headers, body} <- HTTP.HTTP2.request_headers(request, profile),
         {:ok, owner} <-
           HTTP.HTTP2.ConnectionOwner.start_link(
             transport: transport,
             socket: socket,
             profile: profile,
             activate?: false
           ),
         :ok <- transfer_http2_socket(transport, socket, owner),
         :ok <- HTTP.HTTP2.ConnectionOwner.activate(owner),
         {:ok, pool, reservation, key} <- register_http2_owner(request, profile, owner),
         {:ok, bridge} <- maybe_start_http2_bridge(body, owner),
         {:ok, %{id: id}} <-
           HTTP.HTTP2.ConnectionOwner.open_stream(owner, headers,
             subscriber: self(),
             body_bridge: bridge,
             end_stream: body == ""
           ),
         :ok <- send_http2_body(owner, id, body, bridge) do
      monitor = Process.monitor(owner)

      await_http2_response(%{
        parent: parent,
        ref: ref,
        request: request,
        owner: owner,
        monitor: monitor,
        stream_id: id,
        deadline_at: deadline_at,
        redirects: 0,
        redirected?: false,
        mode: nil,
        response_sent?: false,
        body_bridge: bridge,
        pool: pool,
        reservation: reservation,
        pool_key: key
      })
    else
      {:error, reason} ->
        transport.close(socket)
        send_error(parent, ref, reason)
    end
  end

  defp run_http2_reused_owner(parent, ref, request, owner, {pool, reservation}, key, deadline_at) do
    profile = Keyword.get(request.transport_options, :http2_profile, :native_v1)

    with {:ok, headers, body} <- HTTP.HTTP2.request_headers(request, profile),
         {:ok, bridge} <- maybe_start_http2_bridge(body, owner),
         {:ok, %{id: id}} <-
           HTTP.HTTP2.ConnectionOwner.open_stream(owner, headers,
             subscriber: self(),
             body_bridge: bridge,
             end_stream: body == ""
           ),
         :ok <- send_http2_body(owner, id, body, bridge) do
      monitor = Process.monitor(owner)

      await_http2_response(%{
        parent: parent,
        ref: ref,
        request: request,
        owner: owner,
        monitor: monitor,
        stream_id: id,
        deadline_at: deadline_at,
        redirects: 0,
        redirected?: false,
        mode: nil,
        response_sent?: false,
        body_bridge: bridge,
        pool: pool,
        reservation: reservation,
        pool_key: key
      })
    else
      {:error, reason} ->
        _ = HTTP.HTTP2.Pool.release(pool, key, reservation)
        send_error(parent, ref, reason)
    end
  end

  defp register_http2_owner(request, profile, owner) do
    if request.url.scheme != "http" or
         Keyword.get(request.transport_options, :http2_reuse, true) == false do
      {:ok, nil, nil, nil}
    else
      pool = Process.whereis(:http_fetch_http2_pool)

      with pool when is_pid(pool) <- pool,
           {:ok, key} <- HTTP.HTTP2.PoolKey.build(request, profile, :h2c),
           :ok <- HTTP.HTTP2.Pool.register(pool, key, owner),
           {:ok, ^owner, reservation} <- HTTP.HTTP2.Pool.reserve(pool, key) do
        {:ok, pool, reservation, key}
      else
        _ -> {:ok, nil, nil, nil}
      end
    end
  end

  defp transfer_http2_socket(transport, socket, owner) when is_atom(transport),
    do: transport.controlling_process(socket, owner)

  defp transfer_http2_socket(transport, socket, owner) when is_map(transport) do
    if is_function(transport[:controlling_process], 2),
      do: transport.controlling_process.(socket, owner),
      else: :ok
  end

  defp maybe_start_http2_bridge({:stream, stream}, owner),
    do: HTTP.HTTP2.BodyBridge.start_link(stream, owner)

  defp maybe_start_http2_bridge(_body, _owner), do: {:ok, nil}

  defp send_http2_body(_owner, _id, "", _bridge), do: :ok

  defp send_http2_body(owner, id, body, nil) when is_binary(body),
    do: HTTP.HTTP2.ConnectionOwner.send_data(owner, id, body, true)

  defp send_http2_body(_owner, _id, {:stream, _stream}, bridge) when is_pid(bridge),
    do: HTTP.HTTP2.BodyBridge.credit(bridge, 65_536)

  defp await_http2_response(state) do
    monitor = state.monitor
    stream_id = state.stream_id

    receive do
      :abort ->
        _ = HTTP.HTTP2.ConnectionOwner.cancel(state.owner, state.stream_id)
        finish_http2(state, :aborted)

      {:DOWN, ^monitor, :process, _owner, reason} ->
        fail_http2(state, {:request_process_down, reason})

      {:http2, ^stream_id, {:http2, :headers, headers, flags}} ->
        handle_http2_headers(state, headers, flags)

      {:http2, ^stream_id, {:http2, :data, chunk, flags}} ->
        handle_http2_data(state, chunk, flags)

      _message ->
        await_http2_response(state)
    after
      remaining_timeout(state.deadline_at) ->
        _ = HTTP.HTTP2.ConnectionOwner.cancel(state.owner, state.stream_id)
        finish_http2(state, :request_timeout)
    end
  end

  defp handle_http2_headers(state, headers, flags) do
    status =
      headers
      |> Enum.find_value(fn {name, value} -> if name == ":status", do: parse_status(value) end)

    regular = Enum.reject(headers, fn {name, _value} -> String.starts_with?(name, ":") end)

    if is_integer(status) do
      maybe_cancel_http2_bridge(state)

      response =
        Response.new(
          status: status,
          headers: Headers.new(regular),
          body: nil,
          url: state.request.url,
          redirected: state.redirected?
        )

      if Frame.flag?(flags, 0x1) do
        send_response(state.parent, state.ref, Response.with_buffered_body(response, ""))
        finish_http2(state, :ok)
      else
        if stream_response?(state.request, status, Headers.new(regular)) do
          {:ok, stream_pid} = HTTP.Stream.start_link(stream_content_length(Headers.new(regular)))
          send_response(state.parent, state.ref, Response.with_stream_body(response, stream_pid))
          await_http2_response(%{state | mode: {:stream, stream_pid}, response_sent?: true})
        else
          await_http2_response(%{state | mode: {:buffer, response, []}})
        end
      end
    else
      fail_http2(state, :invalid_http_response)
    end
  end

  defp handle_http2_data(%{mode: {:stream, stream_pid}} = state, chunk, flags) do
    case HTTP.Stream.chunk(stream_pid, chunk, stream_chunk_timeout(state.deadline_at)) do
      :ok ->
        if Frame.flag?(flags, 0x1) do
          HTTP.Stream.finish(stream_pid)
          finish_http2(state, :ok)
        else
          await_http2_response(state)
        end

      {:error, reason} ->
        fail_http2(state, reason)
    end
  end

  defp handle_http2_data(%{mode: {:buffer, response, chunks}} = state, chunk, flags) do
    chunks = [chunk | chunks]

    if Frame.flag?(flags, 0x1) do
      send_response(
        state.parent,
        state.ref,
        Response.with_buffered_body(response, chunks |> Enum.reverse() |> IO.iodata_to_binary())
      )

      finish_http2(state, :ok)
    else
      await_http2_response(%{state | mode: {:buffer, response, chunks}})
    end
  end

  defp handle_http2_data(state, _chunk, _flags), do: fail_http2(state, :invalid_http_response)

  defp maybe_cancel_http2_bridge(%{body_bridge: bridge}) when is_pid(bridge),
    do: HTTP.HTTP2.BodyBridge.early_response(bridge)

  defp maybe_cancel_http2_bridge(_state), do: :ok

  defp parse_status(value) when is_binary(value), do: String.to_integer(value)
  defp parse_status(value) when is_integer(value), do: value
  defp parse_status(_), do: nil

  defp fail_http2(state, reason) do
    if state.response_sent? do
      case state.mode do
        {:stream, stream_pid} -> HTTP.Stream.error(stream_pid, reason)
        _ -> :ok
      end
    else
      send_error(state.parent, state.ref, reason)
    end

    finish_http2(state, reason)
  end

  defp finish_http2(state, _reason) do
    Process.demonitor(state.monitor, [:flush])
    _ = HTTP.HTTP2.ConnectionOwner.release_stream(state.owner, state.stream_id)

    if is_pid(state.pool) and is_reference(state.reservation) do
      _ = HTTP.HTTP2.Pool.release(state.pool, state.pool_key, state.reservation)
    else
      _ = GenServer.stop(state.owner, :normal)
    end

    :ok
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
    case state.protocol_module.stream(state.protocol, data) do
      {:ok, protocol, events} ->
        state = %{state | protocol: protocol}
        discard_closed_controls? = discard_closed_control_writes?(state, events)

        case flush_protocol_writes(state, discard_closed_controls?) do
          {:ok, state} ->
            handle_events(state, events)

          {:error, reason} ->
            fail(state, reason)
        end

      {:error, reason} ->
        fail(state, reason)
    end
  end

  defp handle_closed(state) do
    case state.protocol_module.close(state.protocol) do
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
      redirect_error?(state, response) ->
        fail(state, :redirect)

      follow_redirect?(state, response) ->
        redirect(state, response)

      stream_response?(state.request, status, headers) ->
        content_length = stream_content_length(headers)
        {:ok, stream_pid} = HTTP.Stream.start_link(content_length)
        response = Response.with_stream_body(response, stream_pid)
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

    response = Response.with_buffered_body(response, body)

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
      {:error, :closed} -> handle_closed(state)
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

      {:error, :client_identity_cross_origin_redirect = reason} ->
        fail(state, reason)

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

  defp initialize_protocol(transport, socket, %Request{} = request, selection) do
    with {:ok, protocol} <- connected_protocol(transport, socket, selection) do
      serialize_request(protocol, request)
    end
  end

  defp serialize_request(:http1, %Request{} = request) do
    {head, body} = HTTP.HTTP1.prepare_request(request)

    prepared_request =
      case body do
        {:stream, stream} -> {:http1_stream, head, stream}
        body -> {:buffer, [head, body]}
      end

    {:ok, HTTP.HTTP1, HTTP.HTTP1.new(request.method), prepared_request}
  rescue
    error -> {:error, error}
  end

  defp serialize_request(:http2, %Request{} = request) do
    if Request.streaming_body?(request) do
      {:error, :streaming_request_body_unsupported_for_http2}
    else
      {protocol, wire_request} = prepare_http2_request(request)

      {:ok, HTTP.HTTP2, protocol, {:buffer, wire_request}}
    end
  rescue
    error -> {:error, error}
  end

  defp prepare_http2_request(%Request{} = request) do
    conn = HTTP.HTTP2.new(request.method)
    profile = Keyword.get(request.transport_options, :http2_profile)

    if profile != nil and function_exported?(HTTP.HTTP2, :prepare_request, 3) do
      apply(HTTP.HTTP2, :prepare_request, [conn, request, profile])
    else
      HTTP.HTTP2.prepare_request(conn, request)
    end
  end

  defp connected_protocol(_transport, _socket, %{mode: :http1}), do: {:ok, :http1}
  defp connected_protocol(_transport, _socket, %{mode: :h2c}), do: {:ok, :http2}

  defp connected_protocol(transport, socket, %{mode: :force_h2})
       when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    with {:ok, protocol} <- transport.negotiated_protocol(socket) do
      case normalize_alpn_protocol(protocol) do
        "h2" -> {:ok, :http2}
        other -> {:error, {:http2_not_negotiated, other}}
      end
    end
  end

  defp connected_protocol(transport, socket, %{mode: :auto_https})
       when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    with {:ok, protocol} <- transport.negotiated_protocol(socket) do
      case normalize_alpn_protocol(protocol) do
        "h2" -> {:ok, :http2}
        _other -> {:ok, :http1}
      end
    end
  end

  defp normalize_alpn_protocol(nil), do: nil
  defp normalize_alpn_protocol(protocol) when is_binary(protocol), do: protocol

  defp connect(transport, host, port, request, selection, timeout) do
    connect_timeout = min(connect_timeout(request), timeout)

    with :ok <- validate_transport_option_lists(transport, request) do
      interruptible_connect(
        transport,
        host,
        port,
        transport_opts(request, selection, timeout),
        connect_timeout
      )
    end
  end

  defp validate_transport_option_lists(HTTP.Transport.ExSSL, request) do
    valid? =
      Enum.all?([:ssl, :socket_opts], fn key ->
        opts = Keyword.get(request.transport_options, key, [])

        Keyword.keyword?(opts) and
          length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts)))
      end)

    if valid? do
      :ok
    else
      {:error, {:options, :invalid_options}}
    end
  end

  defp validate_transport_option_lists(_transport, _request), do: :ok

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
            # The caller owns cleanup. A failed control write can leave readable
            # TLS data behind, so sending must not destroy the receive side.
            result

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

  defp send_prepared_request(transport, socket, {:buffer, iodata}, deadline_at) do
    send_request(transport, socket, iodata, remaining_timeout(deadline_at))
  end

  defp send_prepared_request(transport, socket, {:http1_stream, head, stream}, deadline_at) do
    with :ok <- send_request(transport, socket, head, remaining_timeout(deadline_at)) do
      send_http1_stream_body(transport, socket, stream, deadline_at)
    end
  end

  defp send_http1_stream_body(transport, socket, stream, deadline_at) do
    send(stream, {:read_chunk, self(), :ack})
    read_http1_stream_body(transport, socket, stream, deadline_at)
  end

  defp read_http1_stream_body(transport, socket, stream, deadline_at) do
    receive do
      {:stream_chunk, ^stream, chunk, ack_ref} ->
        send_http1_stream_chunk(transport, socket, stream, chunk, ack_ref, deadline_at)

      {:stream_chunk, ^stream, chunk} ->
        send_http1_stream_chunk(transport, socket, stream, chunk, nil, deadline_at)

      {:stream_end, ^stream} ->
        send_request(transport, socket, "0\r\n\r\n", remaining_timeout(deadline_at))

      {:stream_error, ^stream, reason} ->
        transport.close(socket)
        {:error, reason}

      :abort ->
        transport.close(socket)
        {:error, :aborted}

      :deadline ->
        transport.close(socket)
        {:error, :request_timeout}
    after
      remaining_timeout(deadline_at) ->
        transport.close(socket)
        {:error, :request_timeout}
    end
  end

  defp send_http1_stream_chunk(transport, socket, stream, chunk, ack_ref, deadline_at) do
    request_chunk = [
      Integer.to_string(byte_size(chunk), 16),
      "\r\n",
      chunk,
      "\r\n"
    ]

    case send_request(transport, socket, request_chunk, remaining_timeout(deadline_at)) do
      :ok ->
        ack_stream_chunk(stream, ack_ref)
        read_http1_stream_body(transport, socket, stream, deadline_at)

      {:error, reason} ->
        ack_stream_chunk(stream, ack_ref)
        HTTP.Stream.error(stream, reason)
        {:error, reason}
    end
  end

  defp ack_stream_chunk(_stream, nil), do: :ok
  defp ack_stream_chunk(stream, ack_ref), do: send(stream, {:stream_chunk_ack, ack_ref})

  defp flush_protocol_writes(
         %{protocol_module: HTTP.HTTP2, protocol: protocol} = state,
         discard_closed_controls?
       ) do
    {protocol, iodata} = HTTP.HTTP2.take_outbound(protocol)
    state = %{state | protocol: protocol}

    case IO.iodata_to_binary(iodata) do
      "" -> {:ok, state}
      data -> flush_protocol_write(state, data, discard_closed_controls?)
    end
  end

  defp flush_protocol_writes(state, _discard_closed_controls?), do: {:ok, state}

  defp discard_closed_control_writes?(
         %{protocol_module: HTTP.HTTP2, protocol: protocol, transport: transport},
         events
       ) do
    # Classify queued frames independently from any upload waiting for credit.
    # A complete early response stops that upload in the protocol layer.
    # In ex_ssl 0.3.0 an established socket's peer close_notify rejects writes
    # with :closed while retaining
    # unread plaintext; abnormal TCP closure returns :econnreset instead.
    # This owner has not closed the socket locally. Rearming it drains that
    # plaintext (or reports EOF); only the HTTP parser can complete a response.
    HTTP.HTTP2.outbound_control_only?(protocol) and
      (transport == HTTP.Transport.ExSSL or
         (HTTP.HTTP2.complete_response?(protocol) and :done in events))
  end

  defp discard_closed_control_writes?(_state, _events), do: false

  defp flush_protocol_write(state, data, discard_closed_controls?) do
    timeout = remaining_timeout(state.deadline_at)

    case send_request(state.transport, state.socket, data, timeout) do
      :ok ->
        {:ok, state}

      {:error, :closed} when discard_closed_controls? ->
        # Sending is over, but receiving is not necessarily over. In particular,
        # buffered WINDOW_UPDATE frames must not restart the abandoned upload
        # while we drain the response through the original receive/deadline loop.
        {:ok, %{state | protocol: HTTP.HTTP2.stop_request(state.protocol)}}

      {:error, reason} ->
        {:error, reason}
    end
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

  defp select_transport(
         %Request{url: %URI{scheme: "https", host: host} = uri} = request,
         _socket_path
       )
       when is_binary(host) do
    {:ok, HTTP.TLSBackend.transport(tls_backend(request)), host, uri.port || 443}
  end

  defp select_transport(%Request{url: %URI{scheme: scheme}}, _socket_path) do
    {:error, {:unsupported_scheme, scheme}}
  end

  defp protocol_selection(%Request{} = request, HTTP.Transport.Unix) do
    case http_version(request) do
      version when version in [:http1, :auto] ->
        {:ok, %{mode: :http1, alpn_protocols: []}}

      version ->
        {:error, {:unsupported_http_version_for_unix_socket, version}}
    end
  end

  defp protocol_selection(%Request{url: %URI{scheme: "http"}} = request, HTTP.Transport.TCP) do
    case http_version(request) do
      version when version in [:http1, :auto] ->
        if http2_options?(request),
          do: {:error, :http2_options_require_http2},
          else: {:ok, %{mode: :http1, alpn_protocols: []}}

      :h2c ->
        {:ok, %{mode: :h2c, alpn_protocols: []}}

      :http2 ->
        {:error, :http2_requires_tls}
    end
  end

  defp protocol_selection(%Request{url: %URI{scheme: "https"}} = request, transport)
       when transport in [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    case http_version(request) do
      :http1 ->
        if http2_options?(request),
          do: {:error, :http2_options_require_http2},
          else: {:ok, %{mode: :http1, alpn_protocols: []}}

      :http2 ->
        {:ok, %{mode: :force_h2, alpn_protocols: [<<"h2">>]}}

      :auto ->
        if http2_profile?(request) do
          {:ok, %{mode: :force_h2, alpn_protocols: [<<"h2">>]}}
        else
          if http2_options?(request) do
            {:error, :http2_options_require_http2}
          else
            {:ok, %{mode: :auto_https, alpn_protocols: [<<"h2">>, <<"http/1.1">>]}}
          end
        end

      :h2c ->
        {:error, :h2c_requires_cleartext}
    end
  end

  defp http_version(%Request{} = request) do
    Keyword.get(request.transport_options, :http_version, :http1)
  end

  defp http2_profile?(%Request{} = request),
    do: Keyword.get(request.transport_options, :http2_profile) != nil

  defp http2_options?(%Request{} = request) do
    http2_profile?(request) or
      Keyword.has_key?(request.transport_options, :http2_scope) or
      Keyword.has_key?(request.transport_options, :http2_priority) or
      Keyword.get(request.transport_options, :http2_reuse) == false
  end

  defp tls_backend(%Request{} = request), do: Keyword.get(request.transport_options, :tls_backend)

  defp pin_tls_backend(%Request{} = request) do
    with {:ok, backend} <- HTTP.TLSBackend.resolve(tls_backend(request)) do
      {:ok,
       %{
         request
         | transport_options: Keyword.put(request.transport_options, :tls_backend, backend)
       }}
    end
  end

  defp request_timeout(%Request{} = request),
    do: Keyword.get(request.transport_options, :timeout, HTTP.Config.default_request_timeout())

  defp put_request_timeout(%Request{} = request, timeout) do
    %{request | transport_options: Keyword.put(request.transport_options, :timeout, timeout)}
  end

  defp connect_timeout(%Request{} = request),
    do:
      Keyword.get(
        request.transport_options,
        :connect_timeout,
        min(request_timeout(request), 30_000)
      )

  defp transport_opts(%Request{} = request, selection, timeout) do
    socket_opts =
      request.transport_options
      |> Keyword.get(:socket_opts, [])
      |> Keyword.put_new(:send_timeout, max(timeout, 1))
      |> Keyword.put_new(:send_timeout_close, true)

    [
      ssl:
        request.transport_options
        |> Keyword.get(:ssl, [])
        |> put_alpn(selection.alpn_protocols),
      socket_opts: socket_opts
    ]
  end

  defp put_alpn(ssl_opts, []), do: ssl_opts

  defp put_alpn(ssl_opts, protocols),
    do: Keyword.put_new(ssl_opts, :alpn_advertised_protocols, protocols)

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

  defp redirect_error?(state, response) do
    redirect_mode(state.request) == :error &&
      redirect_candidate?(state.request, response.status, response.headers)
  end

  defp follow_redirect?(state, response) do
    redirect_mode(state.request) == :follow &&
      state.redirects < @max_redirects &&
      redirect_candidate?(state.request, response.status, response.headers)
  end

  defp redirect_mode(%Request{} = request),
    do: Keyword.get(request.transport_options, :redirect, :follow)

  defp redirect_candidate?(_request, status, headers) when status in [301, 302, 303, 307, 308] do
    is_binary(Headers.get(headers, "location"))
  end

  defp redirect_candidate?(_request, _status, _headers), do: false

  defp redirect_request(request, response) do
    with location when is_binary(location) <- Headers.get(response.headers, "location"),
         %URI{} = uri <- URI.merge(request.url, location),
         :ok <- validate_client_identity_redirect(request, uri) do
      request =
        request
        |> rewrite_redirect_method(response.status)
        |> strip_redirect_headers(cross_origin?(request.url, uri))

      {:ok, %{request | url: uri}}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_redirect}
    end
  end

  defp validate_client_identity_redirect(request, uri) do
    ssl_options = Keyword.get(request.transport_options, :ssl, [])

    if tls_backend(request) == :ex_ssl and
         Enum.any?([:cert, :certfile, :key, :keyfile], &Keyword.has_key?(ssl_options, &1)) and
         client_identity_origin(request.url) != client_identity_origin(uri) do
      {:error, :client_identity_cross_origin_redirect}
    else
      :ok
    end
  end

  defp client_identity_origin(uri) do
    scheme = String.downcase(uri.scheme || "")

    {scheme, String.downcase(uri.host || ""), uri.port || HTTP.HTTP1.default_port(scheme)}
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
