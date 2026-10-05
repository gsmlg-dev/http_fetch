defmodule HTTP.HTTP3.Stream do
  @moduledoc "Supervised per-request H3 relay; application acknowledgements gate native reads."
  alias HTTP.HTTP3.{BodyBridge, ConnectionOwner, ConnectionSupervisor, Pool, PoolKey}
  alias HTTP.Runtime.Delivery
  @max_open_attempts 3

  def start(%HTTP.Request{} = request, subscriber, opts \\ []) when is_pid(subscriber) do
    generation = Keyword.get(opts, :generation, make_ref())

    case Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
           run(request, subscriber, generation, opts)
         end) do
      {:ok, pid} -> {:ok, pid, generation}
      {:error, reason} -> {:error, reason}
    end
  end

  def acknowledge(pid, ref), do: send(pid, {:acknowledge, ref})
  def close(pid), do: send(pid, :abort)

  defp run(request, subscriber, generation, opts) do
    monitor = Process.monitor(subscriber)
    pool = Keyword.get(opts, :pool, :http_fetch_http3_pool)
    deadline = deadline(Keyword.get(request.transport_options, :timeout, 30_000))
    opening = Keyword.get(opts, :opening_timeout, 5_000)
    opening_deadline = min_deadline(deadline, deadline(opening))

    with {:ok, key, connect} <- PoolKey.build(request, opts),
         {:ok, fields, body} <- headers(request),
         {:ok, owner, lease, ref} <-
           open_request(
             pool,
             key,
             connect,
             {fields, body, generation},
             {opening_deadline, monitor, @max_open_attempts}
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
          deadline: deadline
        }

        try do
          uploaded = start_upload(state)

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

  defp open_leased(pool, owner, lease, {fields, body, generation}, {deadline, monitor, _attempts}) do
    opening_call(
      owner,
      {:open, fields, if(body == "", do: "", else: :stream), self(), generation,
       [timeout: remaining(deadline), deadline_at: deadline]},
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
           {:reserve, key, [timeout: remaining(deadline), token: token]},
           deadline,
           monitor
         ) do
      {:ok, owner, lease} ->
        {:ok, owner, lease}

      {:connect, lease} ->
        try do
          timeout = remaining(deadline)
          connect_timeout = min(Keyword.get(connect, :connect_timeout, timeout), timeout)

          case ConnectionSupervisor.start_connection(
                 Keyword.put(connect, :connect_timeout, connect_timeout)
               ) do
            {:ok, owner} ->
              try do
                with :ok <- ready(owner, deadline, monitor),
                     :ok <-
                       Pool.register(
                         pool,
                         key,
                         owner,
                         lease,
                         Keyword.get(connect, :max_streams, 32)
                       ),
                     do: {:ok, owner, lease}
              else
                {:ok, _, _} = result ->
                  result

                failure ->
                  safe(fn -> GenServer.stop(owner) end)
                  Pool.release(pool, lease)
                  failure
              catch
                kind, reason ->
                  safe(fn -> GenServer.stop(owner) end)
                  :erlang.raise(kind, reason, __STACKTRACE__)
              end

            failure ->
              Pool.release(pool, lease)
              failure
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
    receive do
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
    receive do
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

  defp headers(request) do
    original = request.headers.headers
    forbidden = ~w(connection proxy-connection keep-alive transfer-encoding upgrade)

    if Enum.any?(original, fn {name, value} ->
         String.downcase(name) in forbidden or
           (String.downcase(name) == "te" and value != "trailers")
       end) do
      {:error, :invalid_http3_headers}
    else
      {:ok, fields, body} = HTTP.HTTP2.request_headers(request, :native_v1, order?: false)
      fields = Enum.reject(fields, fn {name, _} -> name == "transfer-encoding" end)
      {:ok, fields, body}
    end
  end

  defp start_upload(%{upload: {:stream, source}} = state) do
    {:ok, bridge} = BodyBridge.start_link(source, self())
    :ok = BodyBridge.credit(bridge, 16_384)
    %{state | bridge: bridge}
  end

  defp start_upload(%{upload: <<>>} = state), do: state
  defp start_upload(%{upload: body} = state) when is_binary(body), do: write_binary(state)
  defp write_binary(%{upload: <<>>} = state), do: state

  defp write_binary(state) do
    size = min(byte_size(state.upload), 16_384)
    <<bytes::binary-size(^size), rest::binary>> = state.upload
    ref = make_ref()
    ConnectionOwner.send_data(state.owner, state.ref, bytes, rest == <<>>, self(), ref)
    %{state | upload: rest, write: {ref, :binary}}
  end

  defp relay(%{terminal?: true}), do: :ok

  defp relay(%{deadline: deadline} = state) when is_integer(deadline) do
    if now() >= deadline, do: expire_request(state), else: receive_messages(state)
  end

  defp relay(state), do: receive_messages(state)

  defp receive_messages(state) do
    receive do
      {:http3, generation, ref, event} when generation == state.generation and ref == state.ref ->
        state = if match?({:headers, _, _}, event), do: stop_upload(state), else: state
        relay(queue(state, event))

      {:acknowledge, ref} ->
        {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
        next = dispatch(%{state | delivery: delivery}, emitted)

        if Delivery.status(next.delivery).queued_events == 0 and not next.native_settled?,
          do: ConnectionOwner.acknowledge(state.owner, state.ref)

        relay(next)

      {:body_chunk, bridge, bytes, ref} when bridge == state.bridge ->
        ConnectionOwner.send_data(state.owner, state.ref, bytes, false, self(), ref)
        relay(%{state | write: {ref, :producer}})

      {:body_eof, bridge} when bridge == state.bridge ->
        ref = make_ref()
        ConnectionOwner.send_data(state.owner, state.ref, <<>>, true, self(), ref)
        relay(%{state | write: {ref, :fin}})

      {:body_error, bridge, reason} when bridge == state.bridge ->
        relay(queue(state, {:error, reason}))

      {:http3_write, ref, :done} when state.write != nil and elem(state.write, 0) == ref ->
        next =
          case elem(state.write, 1) do
            :producer ->
              BodyBridge.ack(state.bridge, ref)
              %{state | write: nil}

            :binary ->
              write_binary(%{state | write: nil})

            :fin ->
              %{state | write: nil}
          end

        relay(next)

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

      :abort ->
        :ok

      _message ->
        relay(state)
    after
      remaining(state.deadline) ->
        expire_request(state)
    end
  end

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

  defp queue(%{terminal_event: terminal} = state, _event) when terminal != nil, do: state

  defp queue(state, event) do
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
    notify(state.subscriber, state.generation, {:data, bytes, ref})
    state
  end

  defp dispatch(state, [{event, ref}]) do
    notify(state.subscriber, state.generation, event)
    {:ok, delivery, emitted} = Delivery.acknowledge(state.delivery, ref)
    next = %{state | delivery: delivery, terminal?: event == :done or match?({:error, _}, event)}
    dispatch(next, emitted)
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

  defp deadline(:infinity), do: :infinity
  defp deadline(timeout) when is_integer(timeout) and timeout > 0, do: now() + timeout
  defp min_deadline(:infinity, right), do: right
  defp min_deadline(left, :infinity), do: left
  defp min_deadline(left, right), do: min(left, right)
  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - now(), 1)

  defp safe(fun) do
    fun.()
  catch
    :exit, _ -> :ok
  end

  defp now, do: System.monotonic_time(:millisecond)
end
