defmodule Quic.IO.GenUDP do
  @moduledoc """
  Standalone UDP socket capability with one outstanding receive credit.

  The consumer receives `{:quic_udp, generation, credit, remote, bytes, at}`
  and calls `consumed/3` after processing it. Until then the socket stays
  passive. Excess traffic remains in the bounded OS receive buffer or is
  dropped; it is not forwarded into an unbounded consumer mailbox.

  Binds must be concrete IP addresses. Ancillary destination metadata and
  multihoming are not supported. Send completion means local UDP acceptance,
  never peer acknowledgement. Times use monotonic microseconds.
  """
  use GenServer
  @behaviour Quic.IO

  defstruct [
    :socket,
    :owner,
    :owner_monitor,
    :generation,
    :local,
    :role,
    :credit,
    :cleanup,
    :cleanup_monitor
  ]

  def open(opts \\ []) do
    opts = Keyword.put_new(opts, :owner, self())
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})
    role = Keyword.get(opts, :role, :client)

    cond do
      not valid_ip?(ip) or wildcard?(ip) -> {:error, {:invalid_local_address, ip}}
      role not in [:client, :server] -> {:error, :invalid_role}
      not is_pid(opts[:owner]) -> {:error, :invalid_owner}
      true -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @impl true
  def send(pid, bytes, remote), do: GenServer.call(pid, {:send, bytes, remote})
  @impl true
  def close(pid), do: GenServer.call(pid, :close)
  def local(pid), do: GenServer.call(pid, :local)
  def consumed(pid, generation, credit), do: GenServer.call(pid, {:consumed, generation, credit})

  @impl true
  def init(opts) do
    owner = Keyword.fetch!(opts, :owner)
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})
    family = if tuple_size(ip) == 8, do: :inet6, else: :inet

    with :ok <- enroll_cleanup(opts),
         {:ok, allocation} <- reserve_port(opts),
         {:ok, socket} <- allocate_socket(opts, family, ip, allocation) do
      initialize_socket(opts, owner, socket)
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  defp initialize_socket(opts, owner, socket) do
    case :inet.setopts(socket, active: :once) do
      :ok ->
        {:ok, local} = :inet.sockname(socket)

        {:ok,
         %__MODULE__{
           socket: socket,
           owner: owner,
           owner_monitor: Process.monitor(owner),
           generation: make_ref(),
           local: local,
           role: Keyword.get(opts, :role, :client),
           cleanup: Keyword.get(opts, :cleanup),
           cleanup_monitor: Quic.Cleanup.monitor(Keyword.get(opts, :cleanup))
         }}

      {:error, reason} ->
        :gen_udp.close(socket)
        {:stop, reason}
    end
  end

  defp allocate_socket(opts, family, ip, allocation) do
    # Keep the real backend selected by the runtime. Start passive: the actual
    # native resource must be observable before receive activation/publication.
    case :gen_udp.open(Keyword.get(opts, :port, 0), [family, :binary, {:ip, ip}, {:active, false}]) do
      {:ok, socket} ->
        case enroll_port(allocation, socket) do
          :ok ->
            {:ok, socket}

          {:error, reason} ->
            :gen_udp.close(socket)
            {:error, reason}
        end

      {:error, reason} ->
        if allocation, do: Quic.Cleanup.no_birth(allocation)
        {:error, reason}
    end
  end

  defp enroll_cleanup(opts) do
    case Keyword.get(opts, :cleanup_birth) do
      nil -> :ok
      birth -> Quic.Cleanup.enroll(birth, self())
    end
  end

  defp reserve_port(opts) do
    case Keyword.get(opts, :cleanup) do
      nil -> {:ok, nil}
      lease -> Quic.Cleanup.reserve(lease, :port, Quic.Cleanup.deadline(opts))
    end
  end

  defp enroll_port(nil, _socket), do: :ok

  defp enroll_port(allocation, socket) when is_port(socket),
    do: Quic.Cleanup.enroll(allocation, socket)

  defp enroll_port(_allocation, _socket), do: {:error, :unsupported_native_socket}

  @impl true
  def handle_call({:send, bytes, remote}, _from, state) do
    result =
      cond do
        not is_binary(bytes) or byte_size(bytes) == 0 or byte_size(bytes) > 65_507 ->
          {:error, :invalid_datagram}

        not valid_remote?(remote) ->
          {:error, :invalid_remote}

        true ->
          with :ok <- Quic.Cleanup.authorize(state.cleanup) do
            {ip, port} = remote

            case :gen_udp.send(state.socket, ip, port, bytes) do
              :ok -> {:ok, monotonic_time()}
              {:error, reason} -> {:error, reason}
            end
          end
      end

    {:reply, result, state}
  end

  def handle_call(
        {:consumed, generation, credit},
        {owner, _},
        %{generation: generation, credit: credit, owner: owner} = state
      )
      when is_reference(credit) do
    case with :ok <- Quic.Cleanup.authorize(state.cleanup),
              do: :inet.setopts(state.socket, active: :once) do
      :ok -> {:reply, :ok, %{state | credit: nil}}
      {:error, reason} -> {:stop, :normal, {:error, reason}, state}
    end
  end

  def handle_call({:consumed, _, _}, _from, state), do: {:reply, {:error, :stale_credit}, state}
  def handle_call(:local, _from, state), do: {:reply, state.local, state}
  def handle_call(:close, _from, state), do: {:stop, :normal, :ok, state}

  @impl true
  def handle_info({:udp, socket, ip, port, bytes}, %{socket: socket, credit: nil} = state) do
    case Quic.Cleanup.authorize(state.cleanup) do
      :ok ->
        credit = make_ref()

        send(
          state.owner,
          {:quic_udp, state.generation, credit, {ip, port}, bytes, monotonic_time()}
        )

        {:noreply, %{state | credit: credit}}

      {:error, _} ->
        {:stop, :normal, state}
    end
  end

  def handle_info(
        {:quic_cleanup_retire, observer},
        %{cleanup: %Quic.Cleanup.Lease{handle: %{observer: observer}}} = state
      ),
      do: {:stop, :normal, state}

  def handle_info(
        {:DOWN, monitor, :process, _observer, _reason},
        %{cleanup_monitor: monitor} = state
      ),
      do: {:stop, :normal, state}

  def handle_info(
        {:DOWN, monitor, :process, owner, _reason},
        %{owner_monitor: monitor, owner: owner} = state
      ),
      do: {:stop, :normal, state}

  def handle_info({:udp_error, socket, reason}, %{socket: socket} = state) do
    send(state.owner, {:quic_udp_error, state.generation, reason})
    {:stop, :normal, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def terminate(_, state) do
    :gen_udp.close(state.socket)
    :ok
  end

  @impl true
  def monotonic_time, do: System.monotonic_time(:microsecond)

  defp valid_remote?({ip, port}), do: valid_ip?(ip) and is_integer(port) and port in 1..65_535
  defp valid_remote?(_), do: false

  defp valid_ip?(ip) when is_tuple(ip) and tuple_size(ip) in [4, 8] do
    max = if tuple_size(ip) == 4, do: 255, else: 65_535
    ip |> Tuple.to_list() |> Enum.all?(&(is_integer(&1) and &1 >= 0 and &1 <= max))
  end

  defp valid_ip?(_), do: false
  defp wildcard?(ip), do: ip |> Tuple.to_list() |> Enum.all?(&(&1 == 0))
end
