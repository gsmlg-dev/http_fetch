defmodule HTTP.HTTP1.Pool do
  @moduledoc false
  use GenServer

  alias HTTP.HTTP2.PoolKey
  alias HTTP.RequestLifecycle

  @max_idle 256
  @expiry_interval 1_000

  def start_link(opts) do
    name =
      if Keyword.has_key?(opts, :name), do: Keyword.take(opts, [:name]), else: [name: __MODULE__]

    GenServer.start_link(__MODULE__, opts, Enum.reject(name, fn {_, value} -> value == nil end))
  end

  def checkout(request) do
    case key(request) do
      {:ok, key} -> GenServer.call(pool(request), {:checkout, key})
      _ -> :none
    end
  end

  def checkout(request, deadline) do
    if request.transport_options[:tls_backend] == :ex_ssl and
         is_pid(RequestLifecycle.current()),
       do: checkout_provider(request, deadline),
       else: checkout(request)
  end

  defp checkout_provider(request, deadline) do
    case key(request) do
      {:ok, key} ->
        deadline = control_deadline(deadline, now() + 1_000)
        tracker = RequestLifecycle.current()
        result = provider_pool_call(pool(request), {:checkout, key, tracker, deadline}, deadline)
        if match?({:error, _}, result), do: RequestLifecycle.abort(tracker)
        result

      _ ->
        :none
    end
  end

  def checkin(request, transport, socket), do: checkin(request, transport, socket, :infinity)

  def checkin(request, transport, socket, deadline) do
    tracker = RequestLifecycle.current()

    if transport == HTTP.Transport.ExSSL and is_pid(tracker) do
      checkin_provider(request, transport, socket, tracker, deadline)
    else
      with {:ok, key} <- key(request),
           :ok <- transport.setopts(socket, active: false),
           {:ok, token} <- GenServer.call(pool(request), {:prepare, key, transport, socket}) do
        case transport.controlling_process(socket, pool(request)) do
          :ok -> GenServer.call(pool(request), {:activate, token, tracker})
          _ -> transport.close(socket)
        end
      else
        _ -> transport.close(socket)
      end
    end
  end

  defp checkin_provider(request, transport, socket, tracker, deadline) do
    deadline = control_deadline(deadline, now() + 1_000)
    server = pool(request)

    with {:ok, key} <- key(request),
         true <- now() < deadline,
         :ok <- transport.setopts(socket, active: false),
         {:ok, token} <-
           provider_pool_call(
             server,
             {:prepare, key, transport, socket, tracker, deadline},
             deadline
           ),
         :ok <-
           provider_pool_call(server, {:activate_provider, token, tracker, deadline}, deadline) do
      :ok
    else
      _ ->
        RequestLifecycle.provider_failed(tracker)
        {:error, :handoff_unconfirmed}
    end
  end

  # A lost reply is unknown acceptance. The original tracker/pool keeps authority;
  # the caller must not close the opaque socket or try another connection.
  defp provider_pool_call(server, message, deadline) do
    timeout = deadline - now()
    if timeout > 0, do: GenServer.call(server, message, timeout), else: {:error, :handoff_expired}
  catch
    :exit, _ -> {:error, :handoff_unconfirmed}
  end

  defp pool(request),
    do: Keyword.get(request.transport_options, :http1_pool, Process.whereis(__MODULE__))

  defp key(request) do
    opts = request.transport_options
    protocol = if request.url.scheme == "https", do: :h2, else: :h2c

    cond do
      opts[:managed_pool_key] != nil ->
        {:ok, opts[:managed_pool_key]}

      Keyword.get(opts, :http1_reuse, false) ->
        identity_request = %{
          request
          | transport_options: Keyword.put(opts, :http2_scope, Keyword.get(opts, :http1_scope))
        }

        with {:ok, key} <- PoolKey.build(identity_request, :native_v1, protocol) do
          {:ok,
           Map.merge(key, %{
             protocol: :http1,
             http1_policy:
               {Keyword.get(opts, :http1_pool_size, 2),
                Keyword.get(opts, :http1_idle_timeout, 30_000)}
           })}
        end

      true ->
        :disabled
    end
  end

  @impl true
  def init(_opts), do: {:ok, %{entries: %{}, retiring?: false, expiry_timer: nil}}

  @impl true
  def handle_call({:prepare, key, transport, socket}, {owner, _}, state),
    do: prepare_entry(state, key, transport, socket, owner, nil, now() + 1_000)

  def handle_call({:prepare, key, transport, socket, tracker, deadline}, {owner, _}, state),
    do: prepare_entry(state, key, transport, socket, owner, tracker, deadline)

  def handle_call({:activate, token}, from, state),
    do: handle_call({:activate, token, nil}, from, state)

  def handle_call({:activate, token, tracker}, {owner, _}, state) do
    current_time = now()

    case Map.fetch(state.entries, token) do
      {:ok, %{status: :pending} = entry} when entry.expires_at <= current_time ->
        {:reply, :expired, discard(state, token)}

      {:ok, %{status: :pending, owner: ^owner} = entry} ->
        with :ok <- entry.transport.setopts(entry.socket, active: :once),
             true <- entry.expires_at > now(),
             true <- Process.alive?(owner),
             :ok <- HTTP.RequestLifecycle.handoff_socket(tracker, entry.socket, entry.expires_at) do
          Process.demonitor(entry.monitor, [:flush])

          entry = %{
            entry
            | status: :idle,
              owner: nil,
              monitor: nil,
              expires_at: now() + entry.idle_timeout
          }

          {:reply, :ok, put_in(state.entries[token], entry)}
        else
          false -> {:reply, :expired, discard(state, token)}
          {:error, _} -> {:reply, :closed, discard(state, token)}
        end

      _ ->
        {:reply, :expired, state}
    end
  end

  def handle_call({:activate_provider, token, tracker, deadline}, {owner, _}, state) do
    case Map.get(state.entries, token) do
      %{status: :pending, owner: ^owner} = entry ->
        deadline = control_deadline(deadline, entry.expires_at)
        activate_provider(state, token, entry, tracker, deadline)

      _ ->
        RequestLifecycle.provider_failed(tracker)
        {:reply, :expired, state}
    end
  end

  def handle_call({:checkout, key, tracker, deadline}, {owner, _}, state) do
    if now() < deadline and Process.alive?(owner),
      do: checkout_entry(state, key, tracker, owner, deadline),
      else: {:reply, {:error, :handoff_expired}, state}
  end

  def handle_call({:checkout, key}, {owner, _}, state) do
    case Enum.find(state.entries, fn {_, entry} -> entry.status == :idle and entry.key == key end) do
      nil ->
        {:reply, :none, state}

      {token, entry} ->
        if entry.provider do
          {:reply, :none, discard(state, token)}
        else
          case lease(entry, owner) do
            :ok -> {:reply, {:ok, entry.socket}, remove(state, token)}
            _ -> handle_call({:checkout, key}, {owner, nil}, discard(state, token))
          end
        end
    end
  end

  defp activate_provider(state, token, entry, tracker, deadline) do
    if now() < deadline and Process.alive?(entry.owner) do
      target = %{controller: self(), owner: self()}

      case RequestLifecycle.offer_provider(tracker, entry.socket, target, deadline) do
        {:ok, carrier} ->
          provider = Map.merge(carrier, %{lease: nil, outgoing: nil})
          entry = %{entry | provider: provider, status: :accepting}
          state = put_in(state.entries[token], entry)
          accept_checkin(state, token, tracker, deadline)

        {:error, reason} ->
          RequestLifecycle.provider_failed(tracker)

          if reason in [:handoff_unconfirmed, :acceptance_unconfirmed] do
            # No ticket was returned: it cannot be reconstructed from a nonce.
            # Retain bounded capacity and the request's original obligation.
            provider = %{handle: nil, lease: nil, outgoing: nil}
            entry = %{entry | provider: provider, status: :retiring}
            {:reply, :closed, put_in(state.entries[token], entry)}
          else
            {:reply, :closed, remove(state, token)}
          end
      end
    else
      RequestLifecycle.provider_failed(tracker)
      {:reply, :expired, remove(state, token)}
    end
  end

  defp checkout_entry(state, key, tracker, owner, deadline) do
    case Enum.find(state.entries, fn {_, entry} -> entry.status == :idle and entry.key == key end) do
      {_token, %{provider: nil}} ->
        handle_call({:checkout, key}, {owner, nil}, state)

      {token, entry} when is_pid(tracker) ->
        checkout_provider(state, token, entry, tracker, owner, deadline)

      {token, _entry} ->
        {:reply, :none, discard(state, token)}

      nil ->
        if Enum.any?(state.entries, fn {_, entry} ->
             entry.key == key and entry.status in [:accepting, :checkout, :retiring]
           end) do
          {:reply, {:error, :handoff_unconfirmed}, state}
        else
          {:reply, :none, state}
        end
    end
  end

  defp prepare_entry(state, key, transport, socket, owner, tracker, deadline) do
    {limit, idle_timeout} = key.http1_policy
    count = Enum.count(state.entries, fn {_, entry} -> entry.key == key end)

    if now() < deadline and Process.alive?(owner) and not state.retiring? and count < limit and
         map_size(state.entries) < @max_idle do
      token = make_ref()

      entry = %{
        key: key,
        transport: transport,
        socket: socket,
        provider: nil,
        tracker: tracker,
        status: :pending,
        owner: owner,
        monitor: Process.monitor(owner),
        idle_timeout: idle_timeout,
        expires_at: deadline
      }

      {:reply, {:ok, token}, schedule_expiry(put_in(state.entries[token], entry))}
    else
      {:reply, :full, state}
    end
  end

  defp lease(entry, owner) do
    with :ok <- ready_to_lease(entry, owner),
         :ok <- entry.transport.controlling_process(entry.socket, owner),
         true <- entry.expires_at > now(),
         do: :ok
  end

  defp ready_to_lease(entry, owner) do
    with false <- entry.expires_at <= now(),
         :ok <- entry.transport.setopts(entry.socket, active: false),
         {:error, :timeout} <- entry.transport.recv(entry.socket, 0, 0),
         false <- queued_socket_event?(entry),
         true <- entry.expires_at > now() and Process.alive?(owner),
         true <- entry.expires_at > now() do
      :ok
    end
  end

  @impl true
  def handle_cast(:close_idle, state) do
    tokens = Map.keys(state.entries)
    {:noreply, %{Enum.reduce(tokens, state, &discard(&2, &1)) | retiring?: true}}
  end

  @impl true
  def terminate(_, state) do
    Enum.each(state.entries, fn {_, entry} -> retire_entry(entry) end)
    :ok
  end

  @impl true
  def handle_info({:expire, token}, state) do
    current_time = now()

    case Map.fetch(state.entries, token) do
      {:ok, entry} when entry.expires_at <= current_time -> {:noreply, discard(state, token)}
      _ -> {:noreply, state}
    end
  end

  def handle_info({:timeout, timer, :expire}, %{expiry_timer: timer} = state)
      when is_reference(timer) do
    current_time = now()
    tokens = for {token, entry} <- state.entries, entry.expires_at <= current_time, do: token
    state = Enum.reduce(tokens, %{state | expiry_timer: nil}, &discard(&2, &1))
    state = Enum.reduce(Map.keys(state.entries), state, &reconcile_provider/2)
    {:noreply, schedule_expiry(state)}
  end

  def handle_info({:timeout, _timer, :expire}, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, _, _}, state) do
    tokens = for {token, entry} <- state.entries, entry.monitor == monitor, do: token
    {:noreply, Enum.reduce(tokens, state, &discard(&2, &1))}
  end

  def handle_info(message, state) do
    tokens =
      for {token, entry} <- state.entries,
          entry.transport.normalize_message(message, entry.socket) != :unknown,
          do: token

    {:noreply, Enum.reduce(tokens, state, &discard(&2, &1))}
  end

  defp queued_socket_event?(entry) do
    {:messages, messages} = Process.info(self(), :messages)
    Enum.any?(messages, &(entry.transport.normalize_message(&1, entry.socket) != :unknown))
  end

  defp now, do: System.monotonic_time(:millisecond)

  # Removing/replacing an entry never cancels this timer. The pool consumes its
  # tick before scheduling another; checkout/activation enforce their own deadlines.
  # This bounds logical tick state, not retired ERTS timer allocations.
  defp schedule_expiry(%{expiry_timer: nil, entries: entries} = state)
       when map_size(entries) > 0,
       do: %{state | expiry_timer: :erlang.start_timer(@expiry_interval, self(), :expire)}

  defp schedule_expiry(state), do: state

  defp discard(state, token) do
    case Map.fetch(state.entries, token) do
      {:ok, %{provider: nil} = entry} ->
        retire_entry(entry)
        remove(state, token)

      {:ok, entry} ->
        retire_entry(entry)
        entry = %{entry | status: :retiring}
        state = put_in(state.entries[token], entry)
        reconcile_provider(token, state)

      :error ->
        state
    end
  end

  defp accept_checkin(state, token, tracker, deadline) do
    entry = state.entries[token]

    case SSL.Lifecycle.accept(entry.provider.transfer, {:abs_ms, deadline}) do
      {:ok, lease} ->
        state = put_in(state.entries[token].provider.lease, lease)
        publish_checkin(state, token, tracker, deadline)

      {:error, _} ->
        RequestLifecycle.provider_failed(tracker)
        {:reply, :closed, state}
    end
  end

  defp publish_checkin(state, token, tracker, deadline) do
    entry = state.entries[token]
    carrier = Map.take(entry.provider, [:handle, :transfer, :epoch, :nonce])

    with true <- now() < deadline and Process.alive?(entry.owner),
         :ok <- RequestLifecycle.release_provider(tracker, carrier, deadline),
         :ok <- entry.transport.setopts(entry.socket, active: :once),
         true <- now() < deadline do
      Process.demonitor(entry.monitor, [:flush])
      provider = Map.take(entry.provider, [:handle, :lease, :outgoing])

      entry = %{
        entry
        | provider: provider,
          status: :idle,
          owner: nil,
          monitor: nil,
          expires_at: now() + entry.idle_timeout
      }

      {:reply, :ok, put_in(state.entries[token], entry)}
    else
      _ -> {:reply, :closed, discard(state, token)}
    end
  end

  defp checkout_provider(state, token, entry, tracker, owner, deadline) do
    deadline = control_deadline(deadline, entry.expires_at)

    with :ok <- ready_to_lease(entry, owner),
         true <- now() < deadline,
         {:ok, carrier} <-
           RequestLifecycle.offer_transfer(
             entry.provider.handle,
             entry.provider.lease,
             %{controller: tracker, owner: owner},
             deadline
           ) do
      entry = %{entry | status: :checkout, owner: owner, monitor: Process.monitor(owner)}
      entry = put_in(entry.provider.outgoing, carrier)
      state = put_in(state.entries[token], entry)

      case RequestLifecycle.accept_provider(tracker, carrier, entry.socket, deadline) do
        :ok ->
          if RequestLifecycle.transfer_state(carrier) == :accepted and now() < deadline do
            {:reply, {:ok, entry.socket}, remove(state, token)}
          else
            RequestLifecycle.abort(tracker)
            {:reply, {:error, :handoff_unconfirmed}, discard(state, token)}
          end

        {:error, _} = error ->
          RequestLifecycle.abort(tracker)
          {:reply, error, discard(state, token)}
      end
    else
      _ -> {:reply, {:error, :handoff_unconfirmed}, discard(state, token)}
    end
  end

  defp reconcile_provider(token, state) do
    case Map.get(state.entries, token) do
      %{provider: nil} -> state
      nil -> state
      entry -> reconcile_entry(state, token, entry)
    end
  end

  defp reconcile_entry(state, token, %{provider: %{outgoing: carrier}} = entry)
       when carrier != nil do
    if RequestLifecycle.transfer_state(carrier) == :accepted do
      remove(state, token)
    else
      cleanup_entry(state, token, entry)
    end
  end

  defp reconcile_entry(state, _token, %{provider: %{handle: nil}}), do: state

  defp reconcile_entry(state, token, %{status: status, provider: %{lease: nil}} = entry)
       when status in [:accepting, :retiring] do
    if RequestLifecycle.transfer_state(entry.provider) == :accepted do
      case SSL.Lifecycle.accept(entry.provider.transfer, {:abs_ms, now() + 250}) do
        {:ok, lease} ->
          entry = put_in(entry.provider.lease, lease)
          retire_entry(entry)
          cleanup_entry(put_in(state.entries[token], entry), token, entry)

        _ ->
          state
      end
    else
      cleanup_entry(state, token, entry)
    end
  end

  defp reconcile_entry(state, token, %{status: :retiring} = entry),
    do: cleanup_entry(state, token, entry)

  defp reconcile_entry(state, _token, _entry), do: state

  defp cleanup_entry(state, token, entry) do
    case SSL.Lifecycle.await(entry.provider.handle, {:abs_ms, now()}) do
      {:ok, %{cleanup: :confirmed}} -> remove(state, token)
      _ -> state
    end
  end

  defp retire_entry(%{provider: nil, tracker: tracker}) when is_pid(tracker),
    do: RequestLifecycle.provider_failed(tracker)

  defp retire_entry(%{provider: nil} = entry), do: entry.transport.close(entry.socket)

  defp retire_entry(%{provider: %{lease: lease}}) when lease != nil,
    do: SSL.Lifecycle.cancel(lease, {:abs_ms, now() + 250})

  defp retire_entry(_entry), do: :ok

  defp control_deadline(:infinity, expiry), do: min(now() + 1_000, expiry)
  defp control_deadline(deadline, expiry), do: min(deadline, min(now() + 1_000, expiry))

  defp remove(state, token) do
    case Map.fetch(state.entries, token) do
      {:ok, entry} ->
        if entry.monitor, do: Process.demonitor(entry.monitor, [:flush])

      :error ->
        :ok
    end

    %{state | entries: Map.delete(state.entries, token)}
  end
end
