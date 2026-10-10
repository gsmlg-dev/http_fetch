defmodule HTTP.HTTP1.Pool do
  @moduledoc false
  use GenServer

  alias HTTP.HTTP2.PoolKey

  @max_idle 256

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def checkout(request) do
    case key(request) do
      {:ok, key} -> GenServer.call(__MODULE__, {:checkout, key})
      _ -> :none
    end
  end

  def checkin(request, transport, socket) do
    with {:ok, key} <- key(request),
         :ok <- transport.setopts(socket, active: false),
         {:ok, token} <- GenServer.call(__MODULE__, {:prepare, key, transport, socket}),
         :ok <- transport.controlling_process(socket, Process.whereis(__MODULE__)) do
      GenServer.call(__MODULE__, {:activate, token, HTTP.RequestLifecycle.current()})
    else
      _ -> transport.close(socket)
    end
  end

  defp key(request) do
    opts = request.transport_options
    protocol = if request.url.scheme == "https", do: :h2, else: :h2c

    if Keyword.get(opts, :http1_reuse, false) do
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
    else
      :disabled
    end
  end

  @impl true
  def init(_opts), do: {:ok, %{entries: %{}}}

  @impl true
  def handle_call({:prepare, key, transport, socket}, {owner, _}, state) do
    {limit, idle_timeout} = key.http1_policy
    count = Enum.count(state.entries, fn {_, entry} -> entry.key == key end)

    if count < limit and map_size(state.entries) < @max_idle do
      token = make_ref()

      entry = %{
        key: key,
        transport: transport,
        socket: socket,
        status: :pending,
        monitor: Process.monitor(owner),
        idle_timeout: idle_timeout,
        expires_at: now() + 1_000,
        timer: Process.send_after(self(), {:expire, token}, 1_000)
      }

      {:reply, {:ok, token}, put_in(state.entries[token], entry)}
    else
      {:reply, :full, state}
    end
  end

  def handle_call({:activate, token}, from, state),
    do: handle_call({:activate, token, nil}, from, state)

  def handle_call({:activate, token, tracker}, _from, state) do
    current_time = now()

    case Map.fetch(state.entries, token) do
      {:ok, entry} when entry.expires_at <= current_time ->
        {:reply, :expired, discard(state, token)}

      {:ok, entry} ->
        Process.demonitor(entry.monitor, [:flush])
        _ = Process.cancel_timer(entry.timer)

        case entry.transport.setopts(entry.socket, active: :once) do
          :ok ->
            HTTP.RequestLifecycle.handoff_socket(tracker, entry.socket)

            entry = %{
              entry
              | status: :idle,
                monitor: nil,
                expires_at: now() + entry.idle_timeout,
                timer: Process.send_after(self(), {:expire, token}, entry.idle_timeout)
            }

            {:reply, :ok, put_in(state.entries[token], entry)}

          {:error, _} ->
            {:reply, :closed, discard(state, token)}
        end

      :error ->
        {:reply, :expired, state}
    end
  end

  def handle_call({:checkout, key}, {owner, _}, state) do
    case Enum.find(state.entries, fn {_, entry} -> entry.status == :idle and entry.key == key end) do
      nil ->
        {:reply, :none, state}

      {token, entry} ->
        case lease(entry, owner) do
          :ok -> {:reply, {:ok, entry.socket}, remove(state, token)}
          _ -> handle_call({:checkout, key}, {owner, nil}, discard(state, token))
        end
    end
  end

  defp lease(entry, owner) do
    with false <- entry.expires_at <= now(),
         :ok <- entry.transport.setopts(entry.socket, active: false),
         {:error, :timeout} <- entry.transport.recv(entry.socket, 0, 0),
         false <- queued_socket_event?(entry) do
      entry.transport.controlling_process(entry.socket, owner)
    end
  end

  @impl true
  def handle_info({:expire, token}, state) do
    current_time = now()

    case Map.fetch(state.entries, token) do
      {:ok, entry} when entry.expires_at <= current_time -> {:noreply, discard(state, token)}
      _ -> {:noreply, state}
    end
  end

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

  defp discard(state, token) do
    case Map.fetch(state.entries, token) do
      {:ok, entry} -> entry.transport.close(entry.socket)
      :error -> :ok
    end

    remove(state, token)
  end

  defp remove(state, token) do
    case Map.fetch(state.entries, token) do
      {:ok, entry} ->
        _ = Process.cancel_timer(entry.timer)
        if entry.monitor, do: Process.demonitor(entry.monitor, [:flush])

      :error ->
        :ok
    end

    %{state | entries: Map.delete(state.entries, token)}
  end
end
