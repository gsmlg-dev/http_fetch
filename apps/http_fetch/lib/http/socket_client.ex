defmodule HTTP.SocketClient do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.HTTP2.{BodyBridge, ConnectionOwner, ConnectionSupervisor, Frame, Pool, PoolKey}
  alias HTTP.Request
  alias HTTP.Response

  @max_redirects 5

  @spec request(Request.t(), pid() | nil, String.t() | nil) :: Response.t() | {:error, term()}
  def request(%Request{} = request, abort_controller_pid \\ nil, unix_socket_path \\ nil) do
    cond do
      http_version(request) == :http3 and tls_backend(request) != nil ->
        {:error, :tls_backend_not_supported_for_quic}

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
          informational: [],
          informational_bytes: 0,
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

  defp handle_http3_event(state, {:informational, status, headers}) do
    bytes =
      Enum.reduce(headers, 0, fn {name, value}, sum ->
        sum + byte_size(name) + byte_size(value) + 32
      end)

    if length(state.informational) < 128 and state.informational_bytes + bytes <= 65_536 do
      {:cont,
       %{
         state
         | informational: state.informational ++ [{status, Headers.new(headers)}],
           informational_bytes: state.informational_bytes + bytes
       }}
    else
      {:error, :http3_informational_limit, state}
    end
  end

  defp handle_http3_event(state, {:headers, status, headers}) do
    headers = Headers.new(headers)

    response =
      Response.new(
        status: status,
        headers: headers,
        body: nil,
        url: state.request.url,
        redirected: state.redirected?,
        http_version: :http3,
        informational: state.informational
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

        {:ok, stream_pid} =
          HTTP.Stream.start_link(content_length, response_encodings(state.request, headers))

        response = Response.with_stream_body(response, stream_pid)
        send_response(state.parent, state.ref, response, state.request)

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

  defp handle_http3_event(%{mode: {:stream, stream_pid}} = state, {:trailers, fields}) do
    HTTP.Stream.trailers(stream_pid, Headers.new(fields))
    {:cont, state}
  end

  defp handle_http3_event(%{mode: {:buffer, response, chunks}} = state, {:trailers, fields}) do
    {:cont, %{state | mode: {:buffer, %{response | trailers: Headers.new(fields)}, chunks}}}
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
    send_response(state.parent, state.ref, response, state.request)

    {:halt, state}
  end

  defp handle_http3_event(state, :done), do: {:error, :invalid_http_response, state}

  defp follow_http3_redirect(response, parent, ref, request, redirects, deadline_at) do
    case redirect_request(request, response) do
      {:ok, redirected_request} ->
        http3_owner(parent, ref, redirected_request, redirects + 1, true, deadline_at)

      {:error, reason} ->
        send_error(parent, ref, reason)
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
    parent_monitor = Process.monitor(parent)

    try do
      owner_request(
        parent,
        ref,
        request,
        unix_socket_path,
        redirects,
        redirected?,
        deadline_at,
        parent_monitor
      )
    after
      Process.demonitor(parent_monitor, [:flush])
    end
  end

  defp owner_request(
         parent,
         ref,
         request,
         unix_socket_path,
         redirects,
         redirected?,
         deadline_at,
         parent_monitor
       ) do
    case remaining_timeout(deadline_at) do
      0 ->
        send_error(parent, ref, :request_timeout)

      timeout ->
        timer_ref = Process.send_after(self(), :deadline, timeout)

        context = %{
          parent: parent,
          parent_monitor: parent_monitor,
          ref: ref,
          request: request,
          unix_socket_path: unix_socket_path,
          redirects: redirects,
          redirected?: redirected?,
          deadline_at: deadline_at,
          timer_ref: timer_ref
        }

        with {:ok, transport, host, port} <- select_transport(request, unix_socket_path),
             {:ok, selection} <- protocol_selection(request, transport),
             {:ok, socket} <-
               maybe_reused_http2_owner(parent_monitor, request, selection, deadline_at) do
          case socket do
            {:reused, owner, reservation, key} ->
              _ = Process.cancel_timer(timer_ref)

              run_http2_reused_owner(context, owner, reservation, key)

            {:connect, claim} ->
              handle_new_connection(
                context,
                transport,
                host,
                port,
                selection,
                remaining_timeout(deadline_at),
                claim
              )
          end
        else
          {:error, reason} ->
            _ = Process.cancel_timer(timer_ref)
            send_error(parent, ref, reason)
        end
    end
  end

  defp handle_new_connection(context, transport, host, port, selection, timeout, claim) do
    %{parent: parent, ref: ref, request: request} = context

    case HTTP.Runtime.Dialer.connect(
           transport,
           host,
           port,
           request,
           selection,
           timeout,
           context.parent_monitor
         ) do
      {:ok, socket} ->
        case maybe_http2_owner(context, selection, transport, socket, claim) do
          {:handled, result} ->
            _ = Process.cancel_timer(context.timer_ref)
            result

          :legacy ->
            complete_http2_connect(claim)
            initialize_legacy_owner(context, transport, socket, selection)
        end

      {:error, reason} ->
        fail_http2_connect(claim, reason)
        send_error(parent, ref, reason)
    end
  end

  defp maybe_reused_http2_owner(parent_monitor, request, selection, deadline_at) do
    if selection.mode in [:h2c, :force_h2, :auto_https] and
         Keyword.get(request.transport_options, :http2_reuse, true) != false do
      profile = Keyword.get(request.transport_options, :http2_profile, :native_v1)
      protocol = if selection.mode == :h2c, do: :h2c, else: :h2
      pool = Process.whereis(:http_fetch_http2_pool)

      with pool when is_pid(pool) <- pool,
           {:ok, key} <- PoolKey.build(request, profile, protocol) do
        case Pool.try_reserve(pool, key) do
          {:ok, owner, reservation} ->
            {:ok, {:reused, owner, {pool, reservation}, key}}

          :none ->
            reserve_or_claim_http2_owner(pool, key, deadline_at, parent_monitor)
        end
      else
        _ -> {:ok, {:connect, nil}}
      end
    else
      {:ok, {:connect, nil}}
    end
  end

  defp reserve_or_claim_http2_owner(pool, key, deadline_at, parent_monitor) do
    case Pool.claim_connect(pool, key) do
      :start ->
        {:ok, {:connect, {pool, key}}}

      :wait ->
        case await_http2_reservation(pool, key, deadline_at, nil, parent_monitor) do
          {:ok, owner, reservation} ->
            {:ok, {:reused, owner, {pool, reservation}, key}}

          {:connect, _token} ->
            {:ok, {:connect, {pool, key}}}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp await_http2_reservation(pool, key, deadline_at, registered_owner, parent_monitor) do
    token = make_ref()

    options = [
      deadline_at: deadline_at,
      token: token,
      connect?: is_nil(registered_owner),
      registered_owner: registered_owner
    ]

    request_id = :gen_server.send_request(pool, {:reserve, key, options})
    await_http2_reservation_reply(pool, token, request_id, deadline_at, parent_monitor)
  end

  defp await_http2_reservation_reply(pool, token, request_id, deadline_at, parent_monitor) do
    receive do
      {:DOWN, ^parent_monitor, :process, _parent, _reason} when is_reference(parent_monitor) ->
        _ = Pool.cancel(pool, token)
        {:error, :subscriber_down}

      :abort ->
        _ = Pool.cancel(pool, token)
        {:error, :aborted}

      :deadline ->
        _ = Pool.cancel(pool, token)
        {:error, :request_timeout}

      message ->
        case :gen_server.check_response(message, request_id) do
          {:reply, result} ->
            result

          {:error, {reason, _server}} ->
            {:error, reason}

          :no_reply ->
            await_http2_reservation_reply(pool, token, request_id, deadline_at, parent_monitor)
        end
    after
      remaining_timeout(deadline_at) ->
        _ = Pool.cancel(pool, token)
        {:error, :request_timeout}
    end
  end

  defp initialize_legacy_owner(context, transport, socket, selection) do
    %{parent: parent, ref: ref, request: request, deadline_at: deadline_at, timer_ref: timer_ref} =
      context

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
          state =
            Map.merge(context, %{
              transport: transport,
              socket: socket,
              protocol_module: protocol_module,
              protocol: protocol,
              mode: nil,
              response_sent?: false
            })

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

  defp maybe_http2_owner(context, selection, transport, socket, claim) do
    case connected_protocol(transport, socket, selection) do
      {:ok, :http2} -> {:handled, run_http2_owner(context, transport, socket, claim)}
      _ -> :legacy
    end
  end

  defp run_http2_owner(context, transport, socket, claim) do
    %{
      parent: parent,
      ref: ref,
      request: request,
      deadline_at: deadline_at,
      redirects: redirects,
      redirected?: redirected?,
      unix_socket_path: unix_socket_path
    } = context

    profile = Keyword.get(request.transport_options, :http2_profile, :native_v1)

    with {:ok, headers, body} <- HTTP.HTTP2.request_headers(request, profile, order?: false),
         {:ok, owner} <-
           ConnectionSupervisor.start_connection(
             transport: transport,
             socket: socket,
             profile: profile,
             activate?: false,
             limit_initial_capacity?: http_version(request) == :auto
           ),
         :ok <- transfer_http2_socket(transport, socket, owner),
         :ok <- ConnectionOwner.activate(owner),
         {:ok, pool, reservation, key} <-
           register_http2_owner(
             request,
             profile,
             owner,
             claim,
             deadline_at,
             context.parent_monitor
           ) do
      case start_http2_stream(owner, headers, body) do
        {:ok, id, bridge} ->
          monitor = Process.monitor(owner)

          await_http2_response(%{
            parent: parent,
            ref: ref,
            request: request,
            owner: owner,
            monitor: monitor,
            stream_id: id,
            deadline_at: deadline_at,
            redirects: redirects,
            redirected?: redirected?,
            unix_socket_path: unix_socket_path,
            mode: nil,
            informational: [],
            informational_bytes: 0,
            delivery: nil,
            response_sent?: false,
            body_bridge: bridge,
            pool: pool,
            reservation: reservation,
            pool_key: key
          })

        {:error, reason} ->
          if is_pid(pool) and is_reference(reservation),
            do: safe_http2_cleanup(fn -> Pool.release(pool, key, reservation) end)

          if not is_pid(pool),
            do: safe_http2_cleanup(fn -> GenServer.stop(owner, :normal) end)

          send_error(parent, ref, reason)
      end
    else
      {:error, reason, :registered} ->
        send_error(parent, ref, reason)

      {:error, reason} ->
        fail_http2_connect(claim, reason)
        transport.close(socket)
        send_error(parent, ref, reason)
    end
  end

  defp run_http2_reused_owner(context, owner, {pool, reservation}, key) do
    %{
      parent: parent,
      ref: ref,
      request: request,
      deadline_at: deadline_at,
      redirects: redirects,
      redirected?: redirected?,
      unix_socket_path: unix_socket_path
    } = context

    profile = Keyword.get(request.transport_options, :http2_profile, :native_v1)

    {:ok, headers, body} = HTTP.HTTP2.request_headers(request, profile, order?: false)

    case start_http2_stream(owner, headers, body) do
      {:ok, id, bridge} ->
        monitor = Process.monitor(owner)

        await_http2_response(%{
          parent: parent,
          ref: ref,
          request: request,
          owner: owner,
          monitor: monitor,
          stream_id: id,
          deadline_at: deadline_at,
          redirects: redirects,
          redirected?: redirected?,
          unix_socket_path: unix_socket_path,
          mode: nil,
          informational: [],
          informational_bytes: 0,
          delivery: nil,
          response_sent?: false,
          body_bridge: bridge,
          pool: pool,
          reservation: reservation,
          pool_key: key
        })

      {:error, reason} ->
        _ = Pool.release(pool, key, reservation)
        send_error(parent, ref, reason)
    end
  end

  defp register_http2_owner(request, profile, owner, claim, deadline_at, parent_monitor) do
    if request.url.scheme not in ["http", "https"] or
         Keyword.get(request.transport_options, :http2_reuse, true) == false do
      {:ok, nil, nil, nil}
    else
      pool = Process.whereis(:http_fetch_http2_pool)

      with pool when is_pid(pool) <- pool,
           {:ok, key} <- pool_key_for_registration(request, profile, claim),
           :ok <- Pool.register(pool, key, owner, connecting?: is_tuple(claim), max_streams: 0) do
        case await_http2_reservation(pool, key, deadline_at, owner, parent_monitor) do
          {:ok, ^owner, reservation} ->
            {:ok, pool, reservation, key}

          {:ok, _other_owner, reservation} ->
            _ = Pool.release(pool, key, reservation)
            {:error, :owner_mismatch, :registered}

          {:error, reason} ->
            {:error, reason, :registered}
        end
      else
        {:error, reason} -> {:error, reason}
        _ -> {:ok, nil, nil, nil}
      end
    end
  end

  defp pool_key_for_registration(_request, _profile, {_pool, key}), do: {:ok, key}

  defp pool_key_for_registration(request, profile, _claim),
    do: PoolKey.build(request, profile, http2_protocol(request))

  defp http2_protocol(%Request{url: %URI{scheme: "http"}}), do: :h2c
  defp http2_protocol(%Request{url: %URI{scheme: "https"}}), do: :h2

  defp complete_http2_connect({pool, key}), do: Pool.complete_connect(pool, key)
  defp complete_http2_connect(_claim), do: :ok

  defp fail_http2_connect({pool, key}, reason),
    do: Pool.fail_connect(pool, key, reason)

  defp fail_http2_connect(_claim, _reason), do: :ok

  defp transfer_http2_socket(transport, socket, owner) when is_atom(transport),
    do: transport.controlling_process(socket, owner)

  defp maybe_start_http2_bridge({:stream, stream}, owner, headers) do
    length =
      headers |> Enum.find_value(fn {name, value} -> if name == "content-length", do: value end)

    opts = [content_length: if(length, do: String.to_integer(length))]
    with {:ok, bridge} <- BodyBridge.start_link(stream, owner, opts), do: {:ok, bridge, nil}
  end

  defp maybe_start_http2_bridge(body, owner, _headers)
       when is_binary(body) and byte_size(body) > 0 do
    chunks =
      Stream.unfold(body, fn
        "" ->
          nil

        remaining ->
          size = min(byte_size(remaining), 16_384)
          <<chunk::binary-size(^size), rest::binary>> = remaining
          {:binary.copy(chunk), rest}
      end)

    with {:ok, stream} <- HTTP.Stream.from_enumerable(chunks) do
      case BodyBridge.start_link(stream, owner) do
        {:ok, bridge} ->
          {:ok, bridge, stream}

        {:error, reason} ->
          stop_internal_http2_stream(stream)
          {:error, reason}
      end
    end
  end

  defp maybe_start_http2_bridge(_body, _owner, _headers), do: {:ok, nil, nil}

  defp start_http2_stream(owner, headers, body) do
    with {:ok, bridge, internal_stream} <- maybe_start_http2_bridge(body, owner, headers) do
      opened =
        try do
          ConnectionOwner.open_stream(owner, headers,
            subscriber: self(),
            body_bridge: bridge,
            end_stream: body == ""
          )
        catch
          :exit, _ -> {:error, :owner_closed}
        end

      case opened do
        {:ok, %{id: id}} ->
          sent =
            try do
              send_http2_body(owner, id, body, bridge)
            catch
              :exit, _ -> {:error, :body_bridge_down}
            end

          case sent do
            :ok ->
              {:ok, id, bridge}

            {:error, reason} ->
              discard_http2_bridge(bridge, internal_stream)
              safe_http2_cleanup(fn -> ConnectionOwner.release_stream(owner, id) end)
              {:error, reason}
          end

        {:error, reason} ->
          discard_http2_bridge(bridge, internal_stream)
          {:error, reason}
      end
    end
  end

  defp discard_http2_bridge(bridge, internal_stream) do
    if is_pid(bridge), do: safe_http2_cleanup(fn -> BodyBridge.discard(bridge) end)
    if is_pid(internal_stream), do: stop_internal_http2_stream(internal_stream)
    :ok
  end

  defp stop_internal_http2_stream(stream) do
    Process.unlink(stream)
    Process.exit(stream, :shutdown)
  end

  defp send_http2_body(_owner, _id, "", _bridge), do: :ok

  defp send_http2_body(owner, id, body, nil) when is_binary(body),
    do: ConnectionOwner.send_data(owner, id, body, true)

  defp send_http2_body(_owner, _id, _body, bridge) when is_pid(bridge),
    do: BodyBridge.credit(bridge, 65_536)

  defp await_http2_response(state) do
    monitor = state.monitor
    stream_id = state.stream_id
    delivery = state.delivery

    receive do
      :abort ->
        cancel_http2_stream(state)
        fail_http2(state, :aborted)

      {:DOWN, ^monitor, :process, _owner, reason} ->
        if reason in [:normal, :closed] do
          await_http2_response(
            Map.put_new(state, :pending_close, {:request_process_down, reason})
          )
        else
          fail_http2(state, {:request_process_down, reason})
        end

      {:DOWN, delivery_monitor, :process, _worker, reason} ->
        if delivery != nil and delivery.monitor == delivery_monitor do
          fail_http2(state, {:body_delivery_down, reason})
        else
          await_http2_response(state)
        end

      {:http2_delivery, token, result} ->
        if delivery != nil and delivery.token == token do
          Process.demonitor(delivery.monitor, [:flush])
          handle_http2_delivery(%{state | delivery: nil}, result, delivery.end_stream?)
        else
          await_http2_response(state)
        end

      {:http2, ^stream_id, {:http2, :goaway, _last_stream_id}} ->
        mark_http2_draining(state)
        await_http2_response(state)

      {:http2, ^stream_id, {:http2, :goaway, _last_stream_id, _error}} ->
        mark_http2_draining(state)
        await_http2_response(state)

      {:http2, ^stream_id, {:http2, :headers, headers, flags}} when is_nil(delivery) ->
        handle_http2_headers(state, headers, flags)

      {:http2, ^stream_id, {:http2, :data, chunk, flags}} when is_nil(delivery) ->
        handle_http2_data(state, chunk, flags)

      {:http2, ^stream_id, {:http2, :reset, code}} ->
        fail_http2(state, {:stream_reset, http2_error_code(code)})

      {:http2, ^stream_id, {:http2, :stream_error, reason}} ->
        fail_http2(state, reason)

      {:http2, ^stream_id, {:http2, :body_error, reason}} ->
        fail_http2(state, {:body_error, reason})

      {:http2, ^stream_id, {:http2, :transport_closed}} ->
        await_http2_response(Map.put(state, :pending_close, :closed))

      {:http2, ^stream_id, {:http2, :transport_error, reason}} ->
        if reason == :closed do
          await_http2_response(Map.put(state, :pending_close, :closed))
        else
          fail_http2(state, {:transport_error, reason})
        end

      {:http2, ^stream_id, {:http2, :drain_timeout}} ->
        fail_http2(state, :drain_timeout)

      :deadline ->
        cancel_http2_stream(state)
        fail_http2(state, :request_timeout)
    after
      http2_receive_timeout(state) ->
        if is_nil(delivery) and Map.has_key?(state, :pending_close) do
          fail_http2(state, state.pending_close)
        else
          cancel_http2_stream(state)
          fail_http2(state, :request_timeout)
        end
    end
  end

  # A delivery worker can leave already validated DATA queued ahead of EOF.
  # Drain those messages before deciding truncation, without extending deadlines
  # or delaying reset, abort, or non-close transport errors.
  defp http2_error_code(0), do: :no_error
  defp http2_error_code(1), do: :protocol_error
  defp http2_error_code(2), do: :internal_error
  defp http2_error_code(3), do: :flow_control_error
  defp http2_error_code(4), do: :settings_timeout
  defp http2_error_code(5), do: :stream_closed
  defp http2_error_code(6), do: :frame_size_error
  defp http2_error_code(7), do: :refused_stream
  defp http2_error_code(8), do: :cancel
  defp http2_error_code(9), do: :compression_error
  defp http2_error_code(10), do: :connect_error
  defp http2_error_code(11), do: :enhance_your_calm
  defp http2_error_code(12), do: :inadequate_security
  defp http2_error_code(13), do: :http_1_1_required
  defp http2_error_code(code), do: code

  defp http2_receive_timeout(%{delivery: nil, pending_close: _}), do: 0
  defp http2_receive_timeout(state), do: remaining_timeout(state.deadline_at)

  defp handle_http2_headers(state, headers, flags) do
    status =
      headers
      |> Enum.find_value(fn {name, value} -> if name == ":status", do: parse_status(value) end)

    regular = Enum.reject(headers, fn {name, _value} -> String.starts_with?(name, ":") end)

    case state.mode do
      mode when not is_nil(mode) and is_nil(status) and regular == headers ->
        cond do
          not Frame.flag?(flags, 0x1) ->
            fail_http2(state, :invalid_http_response)

          length(regular) > 256 or http2_metadata_bytes(regular) > 65_536 ->
            cancel_http2_stream(state)
            fail_http2(state, :http2_trailers_limit)

          true ->
            finish_http2_trailers(state, Headers.new(regular))
        end

      nil when is_integer(status) and status in 100..199 ->
        bytes = http2_metadata_bytes(regular)

        if length(state.informational) < 128 and state.informational_bytes + bytes <= 65_536 do
          await_http2_response(%{
            state
            | informational: state.informational ++ [{status, Headers.new(regular)}],
              informational_bytes: state.informational_bytes + bytes
          })
        else
          cancel_http2_stream(state)
          fail_http2(state, :http2_informational_limit)
        end

      nil when is_integer(status) ->
        handle_http2_final_headers(state, status, Headers.new(regular), flags)

      _ ->
        fail_http2(state, :invalid_http_response)
    end
  end

  defp http2_metadata_bytes(headers) do
    Enum.reduce(headers, 0, fn {name, value}, sum ->
      sum + byte_size(name) + byte_size(value) + 32
    end)
  end

  defp finish_http2_trailers(%{mode: {:stream, stream_pid}} = state, trailers) do
    HTTP.Stream.trailers(stream_pid, trailers)
    HTTP.Stream.finish(stream_pid)
    finish_http2(state, :ok)
  end

  defp finish_http2_trailers(%{mode: {:buffer, response, chunks}} = state, trailers) do
    response = %{response | trailers: trailers}

    send_response(
      state.parent,
      state.ref,
      Response.with_buffered_body(response, chunks |> Enum.reverse() |> IO.iodata_to_binary()),
      state.request
    )

    finish_http2(state, :ok)
  end

  defp handle_http2_final_headers(state, status, headers, flags) do
    maybe_cancel_http2_bridge(state)

    response =
      Response.new(
        status: status,
        headers: headers,
        body: nil,
        url: state.request.url,
        redirected: state.redirected?,
        http_version: :http2,
        informational: state.informational
      )

    cond do
      redirect_error?(state, response) ->
        cancel_http2_stream(state)
        fail_http2(state, :redirect)

      redirect_mode(state.request) == :follow and state.redirects >= @max_redirects and
          redirect_candidate?(state.request, status, headers) ->
        cancel_http2_stream(state)
        fail_http2(state, :too_many_redirects)

      follow_redirect?(state, response) ->
        follow_http2_redirect(state, response)

      Frame.flag?(flags, 0x1) ->
        send_response(
          state.parent,
          state.ref,
          Response.with_buffered_body(response, ""),
          state.request
        )

        finish_http2(state, :ok)

      stream_response?(state.request, status, headers) ->
        {:ok, stream_pid} =
          HTTP.Stream.start_link(
            stream_content_length(headers),
            response_encodings(state.request, headers)
          )

        send_response(
          state.parent,
          state.ref,
          Response.with_stream_body(response, stream_pid),
          state.request
        )

        await_http2_response(%{state | mode: {:stream, stream_pid}, response_sent?: true})

      true ->
        await_http2_response(%{state | mode: {:buffer, response, []}})
    end
  end

  defp follow_http2_redirect(state, response) do
    case redirect_request(state.request, response) do
      {:ok, request} ->
        cancel_http2_stream(state)
        finish_http2(state, :redirect)

        owner(
          state.parent,
          state.ref,
          request,
          state.unix_socket_path,
          state.redirects + 1,
          true,
          state.deadline_at
        )

      {:error, reason} ->
        cancel_http2_stream(state)
        fail_http2(state, reason)
    end
  end

  defp handle_http2_data(%{mode: {:stream, stream_pid}} = state, chunk, flags) do
    end_stream? = Frame.flag?(flags, 0x1)

    coordinator = self()
    token = make_ref()

    case Task.Supervisor.start_child(:http_fetch_task_supervisor, fn ->
           result = HTTP.Stream.chunk(stream_pid, chunk, stream_chunk_timeout(state.deadline_at))
           send(coordinator, {:http2_delivery, token, result})
         end) do
      {:ok, worker} ->
        monitor = Process.monitor(worker)

        await_http2_response(%{
          state
          | delivery: %{token: token, pid: worker, monitor: monitor, end_stream?: end_stream?}
        })

      {:error, reason} ->
        fail_http2(state, {:body_delivery_start, reason})
    end
  end

  defp handle_http2_data(%{mode: {:buffer, response, chunks}} = state, chunk, flags) do
    chunks = [chunk | chunks]
    end_stream? = Frame.flag?(flags, 0x1)

    case acknowledge_http2_data(state, end_stream?) do
      :ok ->
        if end_stream? do
          send_response(
            state.parent,
            state.ref,
            Response.with_buffered_body(
              response,
              chunks |> Enum.reverse() |> IO.iodata_to_binary()
            ),
            state.request
          )

          finish_http2(state, :ok)
        else
          await_http2_response(%{state | mode: {:buffer, response, chunks}})
        end

      {:error, reason} ->
        fail_http2(state, reason)
    end
  end

  defp handle_http2_data(state, _chunk, _flags), do: fail_http2(state, :invalid_http_response)

  defp handle_http2_delivery(%{mode: {:stream, stream_pid}} = state, :ok, end_stream?) do
    case acknowledge_http2_data(state, end_stream?) do
      :ok ->
        if end_stream? do
          HTTP.Stream.finish(stream_pid)
          finish_http2(state, :ok)
        else
          await_http2_response(state)
        end

      {:error, reason} ->
        fail_http2(state, reason)
    end
  end

  defp handle_http2_delivery(state, {:error, reason}, _end_stream?), do: fail_http2(state, reason)

  defp maybe_cancel_http2_bridge(%{body_bridge: bridge}) when is_pid(bridge),
    do: safe_http2_cleanup(fn -> BodyBridge.early_response(bridge) end)

  defp maybe_cancel_http2_bridge(_state), do: :ok

  defp cancel_http2_stream(state),
    do:
      safe_http2_cleanup(fn ->
        ConnectionOwner.cancel(state.owner, state.stream_id)
      end)

  defp acknowledge_http2_data(state, end_stream?) do
    result =
      try do
        ConnectionOwner.acknowledge(state.owner, state.stream_id)
      catch
        :exit, reason -> {:error, {:connection_owner_down, reason}}
      end

    case result do
      :ok ->
        :ok

      {:error, :closed} when end_stream? ->
        :ok

      {:error, {:connection_owner_down, {reason, {GenServer, :call, _}}}}
      when reason in [:normal, :noproc, :closed] ->
        # The owner monitor/terminal message settles EOF after queued DATA.
        :ok

      other ->
        other
    end
  end

  defp mark_http2_draining(%{pool: pool, pool_key: key, owner: owner})
       when is_pid(pool) and is_pid(owner),
       do: Pool.mark_draining(pool, key, owner)

  defp mark_http2_draining(_state), do: :ok

  defp parse_status(<<a, b, c>>)
       when a in ?0..?9 and b in ?0..?9 and c in ?0..?9 do
    status = (a - ?0) * 100 + (b - ?0) * 10 + c - ?0
    if status in 100..599 and status != 101, do: status
  end

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
    stop_http2_delivery(state)
    maybe_cancel_http2_bridge(state)
    stop_http2_bridge(state)

    safe_http2_cleanup(fn ->
      ConnectionOwner.release_stream(state.owner, state.stream_id)
    end)

    if is_pid(state.pool) and is_reference(state.reservation) do
      safe_http2_cleanup(fn ->
        Pool.release(state.pool, state.pool_key, state.reservation)
      end)
    else
      safe_http2_cleanup(fn -> GenServer.stop(state.owner, :normal) end)
    end

    :ok
  end

  defp stop_http2_bridge(%{body_bridge: bridge}) when is_pid(bridge),
    do: safe_http2_cleanup(fn -> GenServer.stop(bridge, :normal) end)

  defp stop_http2_bridge(_state), do: :ok

  defp stop_http2_delivery(%{delivery: %{pid: worker, monitor: monitor}}) do
    Process.demonitor(monitor, [:flush])
    Process.exit(worker, :kill)
  end

  defp stop_http2_delivery(_state), do: :ok

  defp safe_http2_cleanup(fun) do
    fun.()
  catch
    :exit, _reason -> :ok
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
        redirected: state.redirected?,
        http_version: :http1
      )

    cond do
      redirect_error?(state, response) ->
        fail(state, :redirect)

      follow_redirect?(state, response) ->
        redirect(state, response)

      stream_response?(state.request, status, headers) ->
        content_length = stream_content_length(headers)

        {:ok, stream_pid} =
          HTTP.Stream.start_link(content_length, response_encodings(state.request, headers))

        response = Response.with_stream_body(response, stream_pid)
        send_response(state.parent, state.ref, response, state.request)

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
      send_response(state.parent, state.ref, response, state.request)
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
        send_response(state.parent, state.ref, response, state.request)
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

  defp response_encodings(request, headers) do
    if Keyword.get(request.transport_options, :decode_body, true),
      do: HTTP.ContentDecoder.encodings(headers),
      else: []
  end

  defp send_response(parent, ref, response, request) do
    if Response.stream_body?(response) or
         HTTP.HTTP1.body_forbidden?(request.method, response.status) or
         not Keyword.get(request.transport_options, :decode_body, true) do
      send(parent, {:http_fetch_response, ref, response})
    else
      case HTTP.ContentDecoder.buffered(response.headers, response.body || "") do
        {:ok, body} ->
          send(parent, {:http_fetch_response, ref, Response.with_buffered_body(response, body)})

        {:error, reason} ->
          send_error(parent, ref, reason)
      end
    end
  end

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
        {:stream, stream} ->
          length = Headers.get(request.headers, "content-length")
          {:http1_stream, head, stream, if(length, do: String.to_integer(length))}

        body ->
          {:buffer, [head, body]}
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

  defp connected_protocol(transport, socket, selection),
    do: HTTP.Runtime.Dialer.connected_protocol(transport, socket, selection)

  defp connect(transport, host, port, request, selection, timeout),
    do: HTTP.Runtime.Dialer.connect(transport, host, port, request, selection, timeout)

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

  defp send_prepared_request(
         transport,
         socket,
         {:http1_stream, head, stream, length},
         deadline_at
       ) do
    with :ok <- send_request(transport, socket, head, remaining_timeout(deadline_at)) do
      send_http1_stream_body(transport, socket, stream, deadline_at, length)
    end
  end

  defp send_http1_stream_body(transport, socket, stream, deadline_at, remaining) do
    send(stream, {:read_chunk, self(), :ack})
    read_http1_stream_body(transport, socket, stream, deadline_at, remaining)
  end

  defp read_http1_stream_body(transport, socket, stream, deadline_at, remaining) do
    receive do
      {:stream_chunk, ^stream, chunk, ack_ref} ->
        send_http1_stream_chunk(transport, socket, stream, chunk, ack_ref, deadline_at, remaining)

      {:stream_chunk, ^stream, chunk} ->
        send_http1_stream_chunk(transport, socket, stream, chunk, nil, deadline_at, remaining)

      {:stream_end, ^stream} ->
        case remaining do
          nil -> send_request(transport, socket, "0\r\n\r\n", remaining_timeout(deadline_at))
          0 -> :ok
          _ -> fail_http1_upload(transport, socket, stream, :content_length_mismatch)
        end

      {:stream_error, ^stream, reason} ->
        transport.close(socket)
        {:error, reason}

      :abort ->
        fail_http1_upload(transport, socket, stream, :aborted)

      :deadline ->
        fail_http1_upload(transport, socket, stream, :request_timeout)
    after
      remaining_timeout(deadline_at) ->
        fail_http1_upload(transport, socket, stream, :request_timeout)
    end
  end

  defp send_http1_stream_chunk(transport, socket, stream, chunk, ack_ref, deadline_at, remaining) do
    if remaining != nil and byte_size(chunk) > remaining do
      fail_http1_upload(transport, socket, stream, :content_length_mismatch)
    else
      request_chunk =
        if remaining == nil and chunk != "",
          do: [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"],
          else: chunk

      case send_request(transport, socket, request_chunk, remaining_timeout(deadline_at)) do
        :ok ->
          ack_stream_chunk(stream, ack_ref)
          remaining = if remaining != nil, do: remaining - byte_size(chunk)
          read_http1_stream_body(transport, socket, stream, deadline_at, remaining)

        {:error, reason} ->
          HTTP.Stream.error(stream, reason)
          {:error, reason}
      end
    end
  end

  defp fail_http1_upload(transport, socket, stream, reason) do
    HTTP.Stream.error(stream, reason)
    transport.close(socket)
    {:error, reason}
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

  defp select_transport(request, path), do: HTTP.Runtime.Dialer.select_transport(request, path)

  defp protocol_selection(request, transport),
    do: HTTP.Runtime.Dialer.protocol_selection(request, transport)

  defp http_version(%Request{} = request) do
    Keyword.get(request.transport_options, :http_version, :http1)
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
         :ok <- validate_client_identity_redirect(request, uri),
         :ok <- validate_redirect_body(request, response.status) do
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

    if (tls_backend(request) == :ex_ssl or http_version(request) == :http3) and
         Enum.any?([:cert, :certfile, :key, :keyfile], &Keyword.has_key?(ssl_options, &1)) and
         client_identity_origin(request.url) != client_identity_origin(uri) do
      {:error, :client_identity_cross_origin_redirect}
    else
      :ok
    end
  end

  defp validate_redirect_body(request, status) do
    if Request.streaming_body?(rewrite_redirect_method(request, status)),
      do: {:error, :streaming_body_redirect_not_replayable},
      else: :ok
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
