defmodule HTTP.HTTP3.Stream do
  @moduledoc """
  Supervised per-request H3 relay; application acknowledgements gate native reads.

  With `connection_ready_event: true` the subscriber receives
  `{:http_runtime, generation, pid, :connection_ready}` once a QUIC connection is
  established or leased, before request stream admission. Earlier failures
  prove that no request stream was admitted.
  """
  alias HTTP.HTTP3.{BodyBridge, ConnectionOwner, ConnectionSupervisor, Pool, PoolKey}
  alias HTTP.RequestLifecycle
  alias HTTP.Runtime.Delivery
  @max_open_attempts 3

  def start(%HTTP.Request{} = request, subscriber, opts \\ []) when is_pid(subscriber) do
    with :ok <- validate_tunnel_options(opts), do: start_stream(request, subscriber, opts)
  end

  defp validate_tunnel_options(opts) do
    cond do
      opts[:purpose] not in [nil, :request, :extended_connect] ->
        {:error, :invalid_stream_purpose}

      opts[:purpose] != :extended_connect ->
        :ok

      opts[:protocol] == "webtransport-h3" ->
        {:error, :webtransport_network_not_ready}

      opts[:protocol] != "websocket" ->
        {:error, :unsupported_connect_protocol}

      not is_integer(Keyword.get(opts, :opening_timeout, 5_000)) or
          Keyword.get(opts, :opening_timeout, 5_000) <= 0 ->
        {:error, :invalid_opening_timeout}

      not is_integer(Keyword.get(opts, :write_timeout, 5_000)) or
          Keyword.get(opts, :write_timeout, 5_000) <= 0 ->
        {:error, :invalid_write_timeout}

      not is_integer(Keyword.get(opts, :max_write_bytes, 16_777_230)) or
          Keyword.get(opts, :max_write_bytes, 16_777_230) <= 0 ->
        {:error, :invalid_max_write_bytes}

      true ->
        :ok
    end
  end

  defp start_stream(request, subscriber, opts) do
    generation = Keyword.get(opts, :generation, make_ref())

    tunnel? = opts[:purpose] == :extended_connect

    request_deadline =
      Keyword.get_lazy(opts, :deadline_at, fn ->
        if tunnel?,
          do: :infinity,
          else: deadline(Keyword.get(request.transport_options, :timeout, 30_000))
      end)

    opening_deadline =
      min_deadline(
        request_deadline,
        Keyword.get_lazy(opts, :opening_deadline_at, fn ->
          deadline(Keyword.get(opts, :opening_timeout, 5_000))
        end)
      )

    opts =
      Keyword.merge(opts, deadline_at: request_deadline, opening_deadline_at: opening_deadline)

    case RequestLifecycle.start_worker(
           opts[:request_lifecycle],
           :http3_relay,
           opening_deadline,
           fn ->
             run(request, subscriber, generation, opts)
           end
         ) do
      {:ok, pid} -> {:ok, pid, generation}
      {:error, reason} -> {:error, reason}
    end
  end

  def acknowledge(pid, ref), do: send(pid, {:acknowledge, ref})
  def close(pid), do: send(pid, :abort)

  defp run(request, subscriber, generation, opts) do
    tunnel? = opts[:purpose] == :extended_connect
    monitor = Process.monitor(subscriber)
    tracker_monitor = if opts[:request_lifecycle], do: Process.monitor(opts[:request_lifecycle])
    Process.put({__MODULE__, :tracker_monitor}, tracker_monitor)
    pool = Keyword.get(opts, :pool, :http_fetch_http3_pool)
    deadline = opts[:deadline_at]
    opening_deadline = opts[:opening_deadline_at]

    with {:ok, key, connect} <- PoolKey.build(request, opts),
         connect =
           Keyword.merge(
             connect,
             Keyword.take(opts, [
               :deadline_at,
               :opening_deadline_at,
               :request_lifecycle,
               :quic_cleanup,
               :cleanup
             ])
           ),
         {:ok, fields, body} <- headers(request, opts),
         {:ok, owner, lease, ref} <-
           open_request(
             pool,
             key,
             connect,
             {fields, body, generation, deadline, ready_notice(opts, subscriber, generation)},
             {opening_deadline, monitor, if(tunnel?, do: 1, else: @max_open_attempts)}
           ) do
      try do
        state = %{
          subscriber: subscriber,
          generation: generation,
          monitor: monitor,
          owner: owner,
          owner_monitor: Process.monitor(owner),
          lease: lease,
          pool: pool,
          ref: ref,
          bridge: nil,
          upload: body,
          write: nil,
          tunnel?: tunnel?,
          local_end?: false,
          remote_end?: false,
          write_timeout: Keyword.get(opts, :write_timeout, 5_000),
          max_write_bytes: Keyword.get(opts, :max_write_bytes, 16_777_230),
          terminal?: false,
          terminal_event: nil,
          native_settled?: false,
          indeterminate: nil,
          delivery:
            Delivery.new(
              delivery: :ack,
              max_queue_bytes: Keyword.get(opts, :max_queue_bytes, 65_536),
              max_queue_events: Keyword.get(opts, :max_queue_events, 128)
            ),
          deadline: deadline,
          tracker: opts[:request_lifecycle],
          tracker_monitor: tracker_monitor
        }

        if tunnel?,
          do: notify(subscriber, generation, {:opened, %{owner: owner, ref: ref, protocol: :h3}})

        try do
          uploaded = if request_expired?(state), do: state, else: start_upload(state)

          try do
            relay(uploaded)
          after
            if uploaded.bridge && Process.alive?(uploaded.bridge) do
              safe(fn -> BodyBridge.cancel(uploaded.bridge) end)
              safe(fn -> GenServer.stop(uploaded.bridge) end)
            end
          end
        after
          if Process.alive?(owner), do: safe(fn -> ConnectionOwner.cancel(owner, ref) end)
        end
      after
        safe(fn -> Pool.release(pool, lease) end)
      end
    else
      {:error, reason} -> notify(subscriber, generation, {:error, reason})
    end
  catch
    :exit, reason ->
      failure =
        receive do
          {:http3_indeterminate, operation} -> {:indeterminate_operation, operation}
        after
          0 -> {:runtime_down, reason}
        end

      notify(subscriber, generation, {:error, failure})
  end

  defp open_request(pool, key, connect, request, {deadline, monitor, attempts} = context) do
    with {:ok, owner, lease} <- acquire(pool, key, connect, deadline, monitor) do
      notify_ready(elem(request, 4))
      result = open_leased(pool, owner, lease, request, context)

      case result do
        {:ok, ref} ->
          {:ok, owner, lease, ref}

        {:error, {:not_sent, :goaway}} ->
          Pool.drain(pool, owner)
          Pool.release(pool, lease)

          if attempts > 1,
            do: open_request(pool, key, connect, request, {deadline, monitor, attempts - 1}),
            else: {:error, :goaway}

        {:error, reason} ->
          ConnectionOwner.cancel_open(owner, self(), elem(request, 2))
          Pool.release(pool, lease)
          {:error, reason}
      end
    end
  end

  defp open_leased(
         pool,
         owner,
         lease,
         {fields, body, generation, request_deadline, opts},
         {deadline, monitor, _attempts}
       ) do
    opening_call(
      owner,
      {:open, fields,
       if(body == "" and opts[:purpose] != :extended_connect, do: "", else: :stream), self(),
       generation,
       [
         purpose: opts[:purpose],
         protocol: opts[:protocol],
         timeout: remaining(deadline),
         deadline_at: deadline,
         request_deadline_at: request_deadline,
         deadline: {:abs_ms, deadline}
       ]},
      deadline,
      monitor
    )
  catch
    kind, reason ->
      safe(fn -> Pool.release(pool, lease) end)
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp acquire(pool, key, connect, deadline, monitor) do
    token = make_ref()

    case opening_call(
           pool,
           {:reserve, key,
            [
              timeout: remaining(deadline),
              token: token,
              deadline_at: deadline,
              exclusive?: connect[:exclusive?]
            ]},
           deadline,
           monitor
         ) do
      {:ok, owner, lease} ->
        {:ok, owner, lease}

      {:connect, lease} ->
        try do
          case cleanup_descriptor(connect, deadline, monitor) do
            {:ok, cleanup} ->
              launch_owner(pool, key, lease, connect, cleanup, deadline, monitor)

            error ->
              Pool.release(pool, lease)
              error
          end
        catch
          kind, reason ->
            safe(fn -> Pool.release(pool, lease) end)
            :erlang.raise(kind, reason, __STACKTRACE__)
        end

      error ->
        safe(fn -> Pool.release(pool, token) end)
        error
    end
  end

  defp launch_owner(pool, key, lease, connect, cleanup, deadline, monitor) do
    activation = make_ref()
    tracker = if connect[:exclusive?], do: connect[:request_lifecycle]

    opts =
      connect
      |> Keyword.drop([:quic_cleanup])
      |> Keyword.merge(
        inert: true,
        creator: self(),
        activation: activation,
        cleanup: cleanup,
        request_lifecycle: tracker
      )

    case ConnectionSupervisor.start_connection(opts) do
      {:ok, owner} ->
        result =
          with :ok <- RequestLifecycle.register(tracker, owner, :http3_owner, deadline),
               :ok <- opening_active(deadline, monitor),
               :ok <-
                 opening_call(
                   pool,
                   {:register, key, owner, lease, Keyword.get(connect, :max_streams, 32),
                    [cleanup: cleanup, ready?: false]},
                   deadline,
                   monitor
                 ),
               :ok <- opening_call(owner, {:activate, activation}, deadline, monitor),
               :ok <- ready(owner, deadline, monitor),
               :ok <- opening_call(pool, {:ready, owner, lease}, deadline, monitor),
               do: {:ok, owner, lease}

        case result do
          {:ok, _, _} ->
            result

          failure ->
            _ = retire(cleanup)
            safe(fn -> Pool.release(pool, lease) end)
            Process.exit(owner, :kill)
            failure
        end

      failure ->
        _ = retire(cleanup)
        safe(fn -> Pool.release(pool, lease) end)
        failure
    end
  end

  defp cleanup_descriptor(connect, deadline, monitor) do
    case {connect[:exclusive?], connect[:quic_cleanup], connect[:cleanup]} do
      {false, nil, nil} ->
        {:ok, nil}

      {false, _, _} ->
        {:error, :cleanup_requires_exclusive_owner}

      {true, nil, nil} ->
        {:ok, nil}

      {true, nil, descriptor} ->
        validate_descriptor(descriptor)

      {true, callback, nil} when is_function(callback, 1) ->
        callback_descriptor(callback, connect[:request_lifecycle], deadline, monitor)

      _ ->
        {:error, :invalid_cleanup_descriptor}
    end
  end

  defp validate_descriptor(descriptor) do
    with {:ok, cleanup} <- Quic.Cleanup.descriptor(descriptor),
         {:ok, _} <- QuicHttp3.Session.new(cleanup: cleanup),
         do: {:ok, cleanup}
  end

  # Both workers are retained before callback invocation. The callback retains
  # its native descriptor in the external tracker before returning it; no
  # native work is admitted here until that retained descriptor is validated.
  defp callback_descriptor(callback, tracker, deadline, subscriber_monitor) do
    relay = self()
    tag = make_ref()

    with {:ok, guard} <-
           RequestLifecycle.start_worker(tracker, :http3_connector_watchdog, deadline, fn ->
             connector_guard(relay, tracker, tag, deadline)
           end) do
      try do
        case RequestLifecycle.start_worker(tracker, :http3_connector, deadline, fn ->
               connector_wait(relay, guard, tag, deadline, callback)
             end) do
          {:ok, connector} ->
            send(guard, {:bind, tag, connector})
            await_descriptor(connector, guard, tag, deadline, subscriber_monitor)

          error ->
            error
        end
      after
        send(guard, :stop)
      end
    end
  end

  defp connector_wait(relay, guard, tag, deadline, callback) do
    relay_monitor = Process.monitor(relay)
    guard_monitor = Process.monitor(guard)

    receive do
      {:invoke, ^tag} -> send(relay, {tag, callback.(deadline)})
      {:DOWN, ^relay_monitor, :process, _, _} -> :ok
      {:DOWN, ^guard_monitor, :process, _, _} -> :ok
    after
      remaining(deadline) -> :ok
    end
  end

  defp connector_guard(relay, tracker, tag, deadline) do
    relay_monitor = Process.monitor(relay)
    tracker_monitor = if tracker, do: Process.monitor(tracker)

    receive do
      {:bind, ^tag, connector} ->
        connector_monitor = Process.monitor(connector)
        send(relay, {:armed, tag})

        receive do
          {:DOWN, ^connector_monitor, :process, _, _} ->
            receive do
              :stop -> :ok
              {:DOWN, ^relay_monitor, :process, _, _} -> :ok
            after
              remaining(deadline) -> :ok
            end

          {:DOWN, ^relay_monitor, :process, _, _} ->
            Process.exit(connector, :kill)

          {:DOWN, ^tracker_monitor, :process, _, _} ->
            Process.exit(connector, :kill)

          :stop ->
            Process.exit(connector, :kill)
        after
          remaining(deadline) -> Process.exit(connector, :kill)
        end

      {:DOWN, ^relay_monitor, :process, _, _} ->
        :ok

      {:DOWN, ^tracker_monitor, :process, _, _} ->
        :ok

      :stop ->
        :ok
    after
      remaining(deadline) -> :ok
    end
  end

  defp await_descriptor(connector, guard, tag, deadline, subscriber_monitor) do
    connector_monitor = Process.monitor(connector)
    guard_monitor = Process.monitor(guard)

    try do
      receive do
        {:armed, ^tag} ->
          send(connector, {:invoke, tag})

          await_descriptor_reply(
            connector_monitor,
            guard_monitor,
            tag,
            deadline,
            subscriber_monitor
          )

        {:DOWN, ^guard_monitor, :process, _, _} ->
          {:error, :cleanup_connector_down}

        {:DOWN, ^connector_monitor, :process, _, _} ->
          {:error, :cleanup_connector_down}

        {:DOWN, ^subscriber_monitor, :process, _, _} ->
          {:error, :subscriber_down}

        :abort ->
          {:error, :aborted}
      after
        remaining(deadline) -> {:error, :opening_timeout}
      end
    after
      send(guard, :stop)
      Process.exit(connector, :kill)
      Process.demonitor(connector_monitor, [:flush])
      Process.demonitor(guard_monitor, [:flush])
    end
  end

  defp await_descriptor_reply(connector_monitor, guard_monitor, tag, deadline, subscriber_monitor) do
    receive do
      {^tag, {:ok, descriptor}} ->
        case validate_descriptor(descriptor) do
          {:ok, _} = result ->
            result

          error ->
            _ = retire(descriptor)
            error
        end

      {^tag, {:error, _} = error} ->
        error

      {^tag, _} ->
        {:error, :invalid_cleanup_descriptor}

      {:DOWN, ^connector_monitor, :process, _, _} ->
        {:error, :cleanup_connector_down}

      {:DOWN, ^guard_monitor, :process, _, _} ->
        {:error, :cleanup_connector_down}

      {:DOWN, ^subscriber_monitor, :process, _, _} ->
        {:error, :subscriber_down}

      :abort ->
        {:error, :aborted}
    after
      remaining(deadline) -> {:error, :opening_timeout}
    end
  end

  defp retire(descriptor), do: Quic.Cleanup.retire_descriptor(descriptor, {:abs_ms, now()})

  defp ready(owner, deadline, monitor) do
    case opening_call(owner, :await_ready, deadline, monitor) do
      :ok ->
        :ok

      {:error, reason} when reason in [:aborted, :subscriber_down, :opening_timeout] ->
        {:error, reason}

      {:error, reason} ->
        {:error, {:http3_not_established, reason}}
    end
  catch
    :exit, reason -> {:error, {:http3_not_established, reason}}
  end

  defp opening_call(server, message, deadline, monitor) do
    with :ok <- opening_active(deadline, monitor) do
      request_id = :gen_server.send_request(server, message)
      await_opening(request_id, deadline, monitor)
    end
  end

  defp opening_active(deadline, monitor) do
    tracker_monitor = Process.get({__MODULE__, :tracker_monitor})

    receive do
      {:DOWN, ^tracker_monitor, :process, _, _} -> {:error, :cleanup_unconfirmed}
      :abort -> {:error, :aborted}
      {:DOWN, ^monitor, :process, _pid, _reason} -> {:error, :subscriber_down}
    after
      0 ->
        if deadline != :infinity and now() >= deadline,
          do: {:error, :opening_timeout},
          else: :ok
    end
  end

  defp await_opening(request_id, deadline, monitor) do
    tracker_monitor = Process.get({__MODULE__, :tracker_monitor})

    receive do
      {:DOWN, ^tracker_monitor, :process, _, _} ->
        abandon_opening(request_id, :cleanup_unconfirmed)

      :abort ->
        abandon_opening(request_id, :aborted)

      {:DOWN, ^monitor, :process, _pid, _reason} ->
        abandon_opening(request_id, :subscriber_down)

      {:http3_indeterminate, operation} ->
        {:error, {:indeterminate_operation, operation}}

      message ->
        case :gen_server.check_response(message, request_id) do
          {:reply, result} -> result
          {:error, {reason, _server}} -> {:error, {:runtime_down, reason}}
          :no_reply -> await_opening(request_id, deadline, monitor)
        end
    after
      remaining(deadline) -> abandon_opening(request_id, :opening_timeout)
    end
  end

  defp abandon_opening(request_id, reason) do
    _ = :gen_server.receive_response(request_id, 0)
    {:error, reason}
  end

  defp headers(request, opts) do
    original = request.headers.headers
    forbidden = ~w(connection proxy-connection keep-alive transfer-encoding upgrade)

    if Enum.any?(original, fn {name, value} ->
         String.downcase(name) in forbidden or
           (opts[:purpose] == :extended_connect and String.downcase(name) == "content-length") or
           (String.downcase(name) == "te" and value != "trailers")
       end) do
      {:error, :invalid_http3_headers}
    else
      with {:ok, _names} <- HTTP.Trailers.declaration(request.headers) do
        # H2's builder rejects H1 framing; H3 validates declarations independently.
        headers = HTTP.Headers.delete(request.headers, "trailer")

        {:ok, fields, body} =
          HTTP.HTTP2.request_headers(%{request | headers: headers}, :native_v1, order?: false)

        declarations =
          for {name, value} <- original,
              String.downcase(name) == "trailer",
              do: {"trailer", value}

        fields = fields ++ declarations

        fields =
          if opts[:purpose] == :extended_connect,
            do: List.keydelete(fields, "content-length", 0),
            else: fields

        {:ok, fields, body}
      end
    end
  end

  defp start_upload(%{upload: {:stream, source}} = state) do
    {:ok, bridge} = BodyBridge.start_link(source, self())
    :ok = RequestLifecycle.register(state.tracker, bridge, :http3_body_bridge, state.deadline)
    :ok = BodyBridge.credit(bridge, 16_384)
    %{state | bridge: bridge}
  end

  defp start_upload(%{upload: <<>>} = state), do: state
  defp start_upload(%{upload: body} = state) when is_binary(body), do: write_binary(state)
  defp write_binary(%{upload: <<>>} = state), do: state

  defp write_binary(state) do
    if request_expired?(state), do: state, else: send_binary(state)
  end

  defp send_binary(state) do
    size = min(byte_size(state.upload), 16_384)
    <<bytes::binary-size(^size), rest::binary>> = state.upload
    ref = make_ref()
    ConnectionOwner.send_data(state.owner, state.ref, bytes, rest == <<>>, self(), ref)
    %{state | upload: rest, write: {ref, :binary}}
  end

  defp relay(%{terminal?: true}), do: :ok

  defp relay(%{tunnel?: true, write: {_, :tunnel, write}} = state) do
    cond do
      request_expired?(state) -> expire_request(state)
      now() >= write.deadline -> relay(expire_tunnel_write(state))
      true -> receive_messages(state)
    end
  end

  defp relay(%{deadline: deadline} = state) when is_integer(deadline) do
    if now() >= deadline, do: expire_request(state), else: receive_messages(state)
  end

  defp relay(state), do: receive_messages(state)

  defp receive_messages(state) do
    receive do
      {:http3, generation, ref, event} when generation == state.generation and ref == state.ref ->
        state =
          if not state.tunnel? and match?({:headers, _, _}, event),
            do: stop_upload(state),
            else: state

        relay(queue(state, event))

      {:acknowledge, ref} ->
        {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
        next = dispatch(%{state | delivery: delivery}, emitted)

        if Delivery.status(next.delivery).queued_events == 0 and not next.native_settled?,
          do: ConnectionOwner.acknowledge(state.owner, state.ref)

        relay(next)

      {:write, ref, bytes, fin} when state.tunnel? ->
        relay(admit_tunnel_write(state, ref, bytes, fin))

      {:body_chunk, bridge, bytes, ref} when bridge == state.bridge ->
        if request_expired?(state) do
          expire_request(state)
        else
          ConnectionOwner.send_data(state.owner, state.ref, bytes, false, self(), ref)
          relay(%{state | write: {ref, :producer}})
        end

      {:body_trailers, bridge, fields} when bridge == state.bridge ->
        ref = make_ref()
        ConnectionOwner.send_trailers(state.owner, state.ref, fields, self(), ref)
        relay(%{state | write: {ref, :fin}})

      {:body_eof, bridge} when bridge == state.bridge ->
        ref = make_ref()
        ConnectionOwner.send_data(state.owner, state.ref, <<>>, true, self(), ref)
        relay(%{state | write: {ref, :fin}})

      {:body_error, bridge, reason} when bridge == state.bridge ->
        relay(queue(state, {:error, reason}))

      {:http3_write, ref, :done} when state.write != nil and elem(state.write, 0) == ref ->
        next = complete_write(state, ref)

        relay(settle_terminal(next))

      {:http3_write, _ref, {:error, :upload_closed}} ->
        relay(state)

      {:http3_write, _ref, {:error, reason}} ->
        relay(queue(state, {:error, reason}))

      {:http3_indeterminate, operation} ->
        relay(%{state | indeterminate: operation})

      {:DOWN, monitor, :process, _pid, reason} when monitor == state.owner_monitor ->
        failure =
          if state.indeterminate,
            do: {:indeterminate_operation, state.indeterminate},
            else: {:owner_down, reason}

        relay(queue(state, {:error, failure}))

      {:DOWN, monitor, :process, _pid, _reason} when monitor == state.monitor ->
        :ok

      {:DOWN, monitor, :process, _pid, _reason} when monitor == state.tracker_monitor ->
        relay(queue(state, {:error, :cleanup_unconfirmed}))

      :abort ->
        :ok

      _message ->
        relay(state)
    after
      receive_timeout(state) ->
        if state.tunnel? and state.write != nil do
          relay(expire_tunnel_write(state))
        else
          expire_request(state)
        end
    end
  end

  defp complete_write(%{write: {_, :producer}} = state, ref) do
    BodyBridge.ack(state.bridge, ref)
    %{state | write: nil}
  end

  defp complete_write(%{write: {_, :binary}} = state, _ref),
    do: write_binary(%{state | write: nil})

  defp complete_write(%{write: {_, :fin}} = state, _ref), do: %{state | write: nil}

  defp complete_write(%{write: {_, :tunnel, write}} = state, _ref) do
    if write.rest == <<>> do
      tunnel_notify(state, {:write, write.ref, {:progress, write.total}})
      tunnel_notify(state, {:write, write.ref, :done})
      %{state | write: nil, local_end?: write.fin or state.local_end?}
    else
      tunnel_write(state)
    end
  end

  defp admit_tunnel_write(state, ref, bytes, fin)
       when is_reference(ref) and is_binary(bytes) and is_boolean(fin) do
    cond do
      state.write != nil ->
        tunnel_notify(state, {:write, ref, {:error, :write_busy}})
        state

      state.local_end? or byte_size(bytes) > state.max_write_bytes ->
        tunnel_notify(state, {:write, ref, {:error, :invalid_tunnel_write}})
        state

      true ->
        write = %{
          ref: ref,
          rest: bytes,
          fin: fin,
          total: byte_size(bytes),
          deadline: now() + state.write_timeout
        }

        tunnel_write(%{state | write: {nil, :tunnel, write}})
    end
  end

  defp admit_tunnel_write(state, ref, _, _) do
    tunnel_notify(state, {:write, ref, {:error, :invalid_tunnel_write}})
    state
  end

  defp tunnel_write(state) do
    write = elem(state.write, 2)

    if now() >= write.deadline,
      do: expire_tunnel_write(state),
      else: send_tunnel_chunk(state, write)
  end

  defp expire_tunnel_write(state) do
    write = elem(state.write, 2)
    failure = {:indeterminate_operation, write.ref}
    tunnel_notify(state, {:write, write.ref, {:error, failure}})

    if Process.alive?(state.owner),
      do: safe(fn -> ConnectionOwner.cancel(state.owner, state.ref) end)

    queue(%{state | write: nil, native_settled?: true}, {:error, failure})
  end

  defp send_tunnel_chunk(state, write) do
    size = min(byte_size(write.rest), 16_384)
    <<bytes::binary-size(^size), rest::binary>> = write.rest
    native_ref = make_ref()

    ConnectionOwner.send_data(
      state.owner,
      state.ref,
      bytes,
      write.fin and rest == <<>>,
      self(),
      native_ref
    )

    %{state | write: {native_ref, :tunnel, %{write | rest: rest}}}
  end

  defp tunnel_notify(state, event), do: notify(state.subscriber, state.generation, event)

  defp receive_timeout(%{tunnel?: true, write: {_, :tunnel, write}} = state),
    do: min(remaining(state.deadline), remaining(write.deadline))

  defp receive_timeout(state), do: remaining(state.deadline)

  defp expire_request(state) do
    if state.bridge && Process.alive?(state.bridge),
      do: safe(fn -> BodyBridge.cancel(state.bridge) end)

    if Process.alive?(state.owner),
      do: safe(fn -> ConnectionOwner.cancel(state.owner, state.ref) end)

    safe(fn -> Pool.release(state.pool, state.lease) end)
    Process.demonitor(state.owner_monitor, [:flush])

    state = %{
      state
      | deadline: :infinity,
        native_settled?: true,
        upload: <<>>,
        write: nil
    }

    relay(queue(state, {:error, :request_timeout}))
  end

  defp stop_upload(state) do
    if state.bridge && Process.alive?(state.bridge), do: BodyBridge.early_response(state.bridge)
    %{state | upload: <<>>, write: nil}
  end

  defp queue(%{tunnel?: true, terminal_event: :done} = state, {:error, _} = event),
    do: queue(%{state | terminal_event: nil}, event)

  defp queue(%{terminal_event: terminal} = state, _event) when terminal != nil, do: state

  defp queue(state, event) do
    event =
      case event do
        {:error, {:owner_down, {:shutdown, :deadline_expired}}} ->
          if request_expired?(state), do: {:error, :request_timeout}, else: event

        _ ->
          event
      end

    bytes =
      case event do
        {:data, data} -> byte_size(data)
        _ -> 0
      end

    case Delivery.push(state.delivery, event, bytes, state.subscriber) do
      {:ok, delivery, emitted} ->
        terminal = if event == :done or match?({:error, _}, event), do: event, else: nil
        dispatch(%{state | delivery: delivery, terminal_event: terminal}, emitted)

      {:error, reason} ->
        settle_terminal(%{state | terminal_event: {:error, reason}})
    end
  end

  defp dispatch(%{terminal?: true} = state, _events), do: state
  defp dispatch(state, []), do: settle_terminal(state)

  defp dispatch(state, [{{:data, bytes}, ref}]) do
    if state.tunnel?,
      do: tunnel_notify(state, {:data, bytes, [], ref}),
      else: notify(state.subscriber, state.generation, {:data, bytes, ref})

    state
  end

  defp dispatch(%{tunnel?: true} = state, [{:done, ref}]) do
    tunnel_notify(state, :remote_end)
    {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
    dispatch(%{state | delivery: delivery, remote_end?: true}, emitted)
  end

  defp dispatch(%{tunnel?: true} = state, [{{:headers, status, fields}, ref}]) do
    tunnel_notify(state, {:headers, [{":status", Integer.to_string(status)} | fields], []})
    {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
    dispatch(%{state | delivery: delivery}, emitted)
  end

  defp dispatch(%{tunnel?: true} = state, [{{:informational, status, fields}, ref}]) do
    tunnel_notify(state, {:headers, [{":status", Integer.to_string(status)} | fields], []})
    {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
    dispatch(%{state | delivery: delivery}, emitted)
  end

  defp dispatch(state, [{event, ref}]) do
    notify(state.subscriber, state.generation, event)
    {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
    next = %{state | delivery: delivery, terminal?: event == :done or match?({:error, _}, event)}
    dispatch(next, emitted)
  end

  defp settle_terminal(%{tunnel?: true, remote_end?: true, terminal_event: :done} = state) do
    %{
      state
      | terminal?:
          state.local_end? and state.write == nil and
            Delivery.status(state.delivery).queued_events == 0
    }
  end

  defp settle_terminal(%{terminal_event: nil} = state), do: state

  defp settle_terminal(state) do
    if Delivery.status(state.delivery).queued_events == 0 do
      notify(state.subscriber, state.generation, state.terminal_event)
      %{state | terminal?: true}
    else
      state
    end
  end

  defp notify(subscriber, generation, event),
    do: send(subscriber, {:http_runtime, generation, self(), event})

  defp ready_notice(opts, subscriber, generation) do
    if opts[:connection_ready_event] == true,
      do: Keyword.put(opts, :ready_notice, {subscriber, generation}),
      else: opts
  end

  defp notify_ready(opts) do
    case opts[:ready_notice] do
      {subscriber, generation} -> notify(subscriber, generation, :connection_ready)
      nil -> :ok
    end
  end

  defp deadline(:infinity), do: :infinity
  defp deadline(timeout) when is_integer(timeout) and timeout >= 0, do: now() + timeout
  defp min_deadline(:infinity, right), do: right
  defp min_deadline(left, :infinity), do: left
  defp min_deadline(left, right), do: min(left, right)
  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - now(), 0)

  defp request_expired?(%{deadline: deadline}), do: is_integer(deadline) and now() >= deadline

  defp safe(fun) do
    fun.()
  catch
    :exit, _ -> :ok
  end

  defp now, do: System.monotonic_time(:millisecond)
end
