defmodule HTTP.Runtime.Stream do
  @moduledoc """
  Internal logical HTTP/2 byte stream. The supervised stream task owns admission
  and its reservation for its entire lifetime; the connection owner alone owns
  the transport. Notifications are qualified by an opaque attempt generation.
  DATA acknowledgements settle transport credit after bounded parser admission.
  They are independent from application delivery acknowledgements. Subscribers
  must monitor the returned task PID: a shared-runtime restart terminates tasks,
  and its DOWN notification is the terminal signal when forwarding is unavailable.
  Ordinary remote end releases after all DATA transport references are settled.
  """
  alias HTTP.HTTP2.{ConnectionOwner, ConnectionSupervisor, Pool, PoolKey}
  alias HTTP.Request
  alias HTTP.Runtime.Dialer

  @type handle :: %{owner: pid(), id: pos_integer(), ref: reference(), protocol: :h2 | :h2c}

  @spec start(Request.t(), pid(), keyword()) :: {:ok, pid(), reference()} | {:error, term()}
  def start(%Request{} = request, subscriber, opts \\ []) when is_pid(subscriber) do
    generation = Keyword.get(opts, :generation, make_ref())

    case Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
           run(request, subscriber, generation, opts)
         end) do
      {:ok, pid} -> {:ok, pid, generation}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Settles the oldest DATA notification after bounded parser admission."
  def acknowledge(stream, delivery_ref) when is_reference(delivery_ref),
    do: send(stream, {:acknowledge, delivery_ref})

  @doc "Cancels only this stream; repeated cancellation is harmless."
  def close(stream), do: send(stream, :abort)

  defp run(request, subscriber, generation, opts) do
    monitor = Process.monitor(subscriber)
    deadline = opening_deadline(Keyword.get(opts, :opening_timeout, 30_000))

    with {:ok, backend} <- HTTP.TLSBackend.resolve(request.transport_options[:tls_backend]),
         request = %{
           request
           | transport_options: Keyword.put(request.transport_options, :tls_backend, backend)
         },
         {:ok, transport, host, port} <-
           Dialer.select_transport(request, request.transport_options[:unix_socket]),
         {:ok, selection} <- Dialer.protocol_selection(request, transport),
         {:ok, headers, ""} <-
           HTTP.HTTP2.request_headers(request, profile(request), order?: false),
         {:ok, lease} <- acquire(request, selection, transport, host, port, deadline, monitor) do
      open(lease, headers, subscriber, generation, monitor, deadline)
    else
      {:error, reason} ->
        notify(subscriber, generation, {:error, reason})

      {:ok, _headers, _body} ->
        notify(subscriber, generation, {:error, :stream_body_requires_writer})
    end
  end

  defp acquire(_request, %{mode: :http1}, _transport, _host, _port, _deadline, _monitor),
    do: {:error, :http1_negotiated}

  defp acquire(request, selection, transport, host, port, deadline, monitor) do
    protocol = if selection.mode == :h2c, do: :h2c, else: :h2
    pool = Process.whereis(:http_fetch_http2_pool)

    case PoolKey.build(request, profile(request), protocol) do
      {:ok, key} ->
        case reserve(pool, key, deadline, monitor) do
          {:ok, owner, reservation} ->
            {:ok,
             %{owner: owner, pool: pool, key: key, reservation: reservation, protocol: protocol}}

          {:connect, _token} ->
            connect(
              request,
              selection,
              {transport, host, port},
              deadline,
              monitor,
              pool,
              key,
              protocol
            )

          {:error, reason} ->
            {:error, reason}
        end

      {:ok, :non_reusable, _key} ->
        connect(
          request,
          selection,
          {transport, host, port},
          deadline,
          monitor,
          nil,
          nil,
          protocol
        )

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp reserve(pool, key, deadline, monitor, registered_owner \\ nil) do
    token = make_ref()

    request_id =
      :gen_server.send_request(
        pool,
        {:reserve, key,
         [
           deadline_at: pool_deadline(deadline),
           token: token,
           connect?: is_nil(registered_owner),
           registered_owner: registered_owner
         ]}
      )

    await_reservation(pool, token, request_id, deadline, monitor)
  end

  defp await_reservation(pool, token, request_id, deadline, monitor) do
    receive do
      :abort ->
        _ = Pool.cancel(pool, token)
        {:error, :aborted}

      {:DOWN, ^monitor, :process, _pid, _reason} ->
        _ = Pool.cancel(pool, token)
        {:error, :subscriber_down}

      message ->
        case :gen_server.check_response(message, request_id) do
          {:reply, result} -> result
          {:error, {reason, _server}} -> {:error, reason}
          :no_reply -> await_reservation(pool, token, request_id, deadline, monitor)
        end
    after
      remaining(deadline) ->
        _ = Pool.cancel(pool, token)
        {:error, :opening_timeout}
    end
  end

  defp connect(
         request,
         selection,
         {transport, host, port},
         deadline,
         monitor,
         pool,
         key,
         protocol
       ) do
    result =
      with {:ok, socket} <-
             Dialer.connect(
               transport,
               host,
               port,
               request,
               selection,
               remaining(deadline),
               monitor
             ) do
        case Dialer.connected_protocol(transport, socket, selection) do
          {:ok, :http2} ->
            initialize(request, transport, socket, deadline, monitor, pool, key, protocol)

          {:ok, :http1} ->
            transport.close(socket)
            {:error, :http1_negotiated}

          {:error, reason} ->
            transport.close(socket)
            {:error, reason}
        end
      end

    if match?({:error, _}, result) and is_pid(pool),
      do: Pool.fail_connect(pool, key, elem(result, 1))

    result
  end

  defp initialize(request, transport, socket, deadline, monitor, pool, key, protocol) do
    case ConnectionSupervisor.start_connection(
           transport: transport,
           socket: socket,
           profile: profile(request),
           activate?: false
         ) do
      {:ok, owner} ->
        with :ok <- transport.controlling_process(socket, owner),
             :ok <- ConnectionOwner.activate(owner) do
          register(pool, key, owner, deadline, monitor, protocol)
        else
          {:error, reason} ->
            stop_owner(owner)
            {:error, reason}
        end

      {:error, reason} ->
        transport.close(socket)
        {:error, reason}
    end
  end

  defp register(nil, key, owner, _deadline, _monitor, protocol),
    do: {:ok, %{owner: owner, pool: nil, key: key, reservation: nil, protocol: protocol}}

  defp register(pool, key, owner, deadline, monitor, protocol) do
    case Pool.register(pool, key, owner, connecting?: true, max_streams: 0) do
      :ok ->
        case reserve(pool, key, deadline, monitor, owner) do
          {:ok, selected_owner, reservation} ->
            {:ok,
             %{
               owner: selected_owner,
               pool: pool,
               key: key,
               reservation: reservation,
               protocol: protocol
             }}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        stop_owner(owner)
        {:error, reason}
    end
  end

  defp open(lease, headers, subscriber, generation, subscriber_monitor, deadline) do
    owner_monitor = Process.monitor(lease.owner)

    request_id =
      :gen_server.send_request(
        lease.owner,
        {:open_stream, headers,
         [
           subscriber: self(),
           end_stream: true,
           request_ref: generation,
           deadline_at: deadline,
           byte_stream: true
         ]}
      )

    try do
      case await_open(request_id, deadline, subscriber_monitor, owner_monitor) do
        {:ok, handle} ->
          notify(
            subscriber,
            generation,
            {:opened, Map.merge(handle, Map.take(lease, [:owner, :protocol]))}
          )

          relay(
            Map.merge(lease, handle),
            subscriber,
            generation,
            subscriber_monitor,
            owner_monitor,
            %{order: :queue.new(), pending: %{}, remote_end?: false}
          )

        {:error, reason} ->
          notify(subscriber, generation, {:error, reason})
      end
    after
      cleanup_stream(Map.put(lease, :id, generation))
      Process.demonitor(owner_monitor, [:flush])
      release(lease)
    end
  end

  defp await_open(request_id, deadline, subscriber_monitor, owner_monitor) do
    receive do
      :abort ->
        {:error, :aborted}

      {:DOWN, ^subscriber_monitor, :process, _pid, _reason} ->
        {:error, :subscriber_down}

      {:DOWN, ^owner_monitor, :process, _pid, reason} ->
        {:error, {:owner_down, reason}}

      message ->
        case :gen_server.check_response(message, request_id) do
          {:reply, result} -> result
          {:error, {reason, _server}} -> {:error, {:owner_down, reason}}
          :no_reply -> await_open(request_id, deadline, subscriber_monitor, owner_monitor)
        end
    after
      remaining(deadline) -> {:error, :opening_timeout}
    end
  end

  defp relay(lease, _subscriber, _generation, _subscriber_monitor, _owner_monitor, %{
         remote_end?: true,
         pending: pending
       })
       when map_size(pending) == 0 do
    send(lease.owner, {:http2_release_completed, lease.id})
  end

  defp relay(lease, subscriber, generation, subscriber_monitor, owner_monitor, deliveries) do
    receive do
      {:http2, id, {:http2, :headers, headers, flags}} when id == lease.id ->
        notify(subscriber, generation, {:headers, headers, flags})
        deliveries = remote_end(deliveries, subscriber, generation, flags)
        relay(lease, subscriber, generation, subscriber_monitor, owner_monitor, deliveries)

      {:http2, id, {:http2, :data, data, flags}} when id == lease.id ->
        delivery_ref = make_ref()

        deliveries = %{
          deliveries
          | order: :queue.in(delivery_ref, deliveries.order),
            pending: Map.put(deliveries.pending, delivery_ref, false)
        }

        notify(subscriber, generation, {:data, data, flags, delivery_ref})
        deliveries = remote_end(deliveries, subscriber, generation, flags)
        relay(lease, subscriber, generation, subscriber_monitor, owner_monitor, deliveries)

      {:http2, id, {:http2, :goaway, last, error}} when id == lease.id ->
        notify(subscriber, generation, {:goaway, last, error})
        relay(lease, subscriber, generation, subscriber_monitor, owner_monitor, deliveries)

      {:http2, id, event} when id == lease.id ->
        notify(subscriber, generation, {:terminal, event})
        cleanup_stream(lease)

      {:http2, :transport_closed} ->
        notify(subscriber, generation, {:error, :closed})
        cleanup_stream(lease)

      {:http2, :transport_error, reason} ->
        notify(subscriber, generation, {:error, reason})
        cleanup_stream(lease)

      {:http2, :drain_timeout} ->
        notify(subscriber, generation, {:error, :drain_timeout})
        cleanup_stream(lease)

      {:acknowledge, delivery_ref} ->
        deliveries = settle(lease, deliveries, delivery_ref)
        relay(lease, subscriber, generation, subscriber_monitor, owner_monitor, deliveries)

      :abort ->
        cleanup_stream(lease)

      {:DOWN, ^subscriber_monitor, :process, _pid, _reason} ->
        cleanup_stream(lease)

      {:DOWN, ^owner_monitor, :process, _pid, reason} ->
        notify(subscriber, generation, {:error, {:owner_down, reason}})

      _message ->
        relay(lease, subscriber, generation, subscriber_monitor, owner_monitor, deliveries)
    end
  end

  defp remote_end(deliveries, subscriber, generation, flags) do
    if Bitwise.band(flags, 1) == 1 and not deliveries.remote_end? do
      notify(subscriber, generation, :remote_end)
      %{deliveries | remote_end?: true}
    else
      deliveries
    end
  end

  defp settle(lease, deliveries, ref) do
    if Map.has_key?(deliveries.pending, ref) do
      drain_settled(lease, %{deliveries | pending: Map.put(deliveries.pending, ref, true)})
    else
      deliveries
    end
  end

  defp drain_settled(lease, deliveries) do
    case :queue.out(deliveries.order) do
      {{:value, ref}, rest} ->
        if deliveries.pending[ref] do
          send(lease.owner, {:http2_acknowledge_data, lease.id})

          drain_settled(lease, %{
            deliveries
            | order: rest,
              pending: Map.delete(deliveries.pending, ref)
          })
        else
          deliveries
        end

      {:empty, _} ->
        deliveries
    end
  end

  defp cleanup_stream(lease) do
    # Do not keep the subscriber task alive behind a stalled owner. The owner
    # serializes this cleanup and also monitors the stream task. Queued opening
    # calls reject a subscriber that has already terminated.
    send(lease.owner, {:http2_release_request, lease.id})
  end

  defp release(%{pool: nil, owner: owner}), do: stop_owner(owner)

  defp release(lease),
    do: send(lease.pool, {:http2_release_reservation, lease.key, lease.reservation})

  defp stop_owner(owner), do: send(owner, :http2_shutdown_exclusive)

  defp notify(subscriber, generation, event),
    do: send(subscriber, {:http_runtime, generation, self(), event})

  defp profile(request), do: request.transport_options[:http2_profile] || :native_v1
  defp opening_deadline(:infinity), do: :infinity
  defp opening_deadline(timeout), do: System.monotonic_time(:millisecond) + timeout
  defp pool_deadline(:infinity), do: nil
  defp pool_deadline(deadline), do: deadline
  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
