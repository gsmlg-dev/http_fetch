defmodule SSL.Lifecycle.Driver do
  @moduledoc false
  alias SSL.Lifecycle.{Carrier, Handle, Lease, Observer, Receipt, Setup}
  alias SSL.{Options, PreparedUpgrade, Socket}

  def descriptor(options) do
    options = if is_list(options), do: descriptor_options(options), else: :invalid

    if Keyword.keyword?(options) do
      case Keyword.fetch(options, :ex_ssl) do
        :error ->
          :none

        {:ok, extra} ->
          if Keyword.keyword?(extra) do
            lifecycle_descriptor(extra)
          else
            {:error, {:options, {:ex_ssl, :unsupported_or_invalid}}}
          end
      end
    else
      {:error, {:options, :invalid_options}}
    end
  end

  defp lifecycle_descriptor(extra) do
    case Keyword.fetch(extra, :lifecycle) do
      :error -> :none
      {:ok, value} -> SSL.Lifecycle.descriptor(value)
    end
  end

  defp descriptor_options([]), do: []

  defp descriptor_options([atom | rest]) when atom in [:binary, :inet, :inet6],
    do: descriptor_options(rest)

  defp descriptor_options([option | rest]), do: [option | descriptor_options(rest)]
  defp descriptor_options(_), do: :invalid

  def connect(host, port, raw, deadline, %Handle{receipt: receipt}, %Lease{authority: lease}) do
    with :ok <- Observer.bind(receipt, lease, :dial, deadline, budget(deadline)) do
      result =
        with {:ok, options} <- Options.normalize(host, raw),
             do: dial(receipt, lease, host, port, %{options | lifecycle: nil}, deadline)

      finish(result, receipt, lease, deadline)
    end
  end

  def upgrade(%Socket{} = carrier, source, deadline, %Handle{receipt: receipt}, %Lease{
        authority: lease
      }) do
    # A layer accounts only its own processes. The independent outer handle
    # continues to attest the physical TCP and its original allocation lineage.
    with :ok <- Carrier.owned(carrier, deadline) do
      result =
        with :ok <- Observer.bind(receipt, lease, :layer, deadline, budget(deadline)),
             {:ok, options} <- options(source),
             :ok <- Carrier.boundary(carrier, deadline),
             do: setup(receipt, lease, {:layer, carrier}, %{options | lifecycle: nil}, deadline)

      if match?({:error, _}, result), do: Carrier.request_close(carrier)
      finish(result, receipt, lease, deadline)
    end
  end

  def upgrade(tcp, source, deadline, %Handle{receipt: receipt}, %Lease{authority: lease}) do
    # A foreign Port is never adopted, mutated, consumed or closed.
    with :ok <- owned(tcp),
         :ok <- Observer.bind(receipt, lease, :upgrade, deadline, budget(deadline)),
         :use <- Observer.adopt(receipt, lease, tcp, budget(deadline)) do
      result =
        with {:ok, options} <- options(source),
             :ok <- boundary(tcp),
             do: setup(receipt, lease, {:upgrade, tcp}, %{options | lifecycle: nil}, deadline)

      if match?({:error, _}, result) and owned(tcp) == :ok, do: :gen_tcp.close(tcp)
      finish(result, receipt, lease, deadline)
    end
  end

  defp options({:options, raw}), do: Options.normalize(:upgrade, raw)
  defp options({:prepared, prepared}), do: PreparedUpgrade.fetch_options(prepared)

  defp dial(receipt, lease, host, port, options, deadline),
    do: setup(receipt, lease, {host, port}, options, deadline)

  defp setup(receipt, lease, endpoint, options, deadline) do
    with {:ok, permit} <- Observer.reserve_root(receipt, lease, :setup, budget(deadline)),
         {:ok, allocation} <- allocation(receipt, lease, endpoint, deadline) do
      nonce = make_ref()

      context = %{
        receipt: receipt,
        permit: permit,
        allocator_permit: allocation,
        endpoint: endpoint,
        classic: {self(), make_ref(), :atomics.new(1, []), options, deadline},
        control_deadline: budget(deadline),
        ready: {self(), nonce},
        public: true,
        attempt: elem(lease, 0)
      }

      start =
        case endpoint do
          {:upgrade, _} -> &Setup.start/1
          {:layer, _} -> &Setup.start_layer/1
          _ -> &Setup.start_socket/1
        end

      case start.(context) do
        {:ok, helper} -> wait(helper, nonce, receipt, endpoint, deadline)
        error -> error
      end
    end
  end

  defp allocation(_receipt, _lease, {:upgrade, _}, _deadline), do: {:ok, nil}
  defp allocation(_receipt, _lease, {:layer, _}, _deadline), do: {:ok, nil}

  defp allocation(receipt, lease, _endpoint, deadline),
    do: Observer.reserve_root(receipt, lease, :allocator, budget(deadline))

  defp wait(helper, nonce, receipt, endpoint, deadline) do
    observer = Receipt.observer(receipt)
    monitor = Process.monitor(helper)
    observer_monitor = Process.monitor(observer)

    try do
      await(
        helper,
        nonce,
        observer,
        receipt,
        monitor,
        observer_monitor,
        endpoint,
        deadline
      )
    after
      Process.demonitor(monitor, [:flush])
      Process.demonitor(observer_monitor, [:flush])
    end
  end

  defp await(helper, nonce, observer, receipt, monitor, observer_monitor, endpoint, deadline) do
    cell = Receipt.failure_tag(receipt)

    receive do
      {:lifecycle_native_owned, ^helper, ^nonce, ^observer, _socket, _tcp} ->
        case Setup.attach(helper, nonce, budget(deadline)) do
          :ok ->
            await(helper, nonce, observer, receipt, monitor, observer_monitor, endpoint, deadline)

          error ->
            error
        end

      {:lifecycle_adopt_ready, ^helper, ^nonce, ^observer, socket} ->
        {_kind, tcp} = endpoint

        with :ok <- transfer(tcp, socket.pid, deadline),
             :ok <- Setup.adopt(helper, nonce, tcp, budget(deadline)),
             :ok <- Setup.attach(helper, nonce, budget(deadline)) do
          await(helper, nonce, observer, receipt, monitor, observer_monitor, endpoint, deadline)
        end

      {:lifecycle_tls_ready, ^helper, ^nonce, ^observer, socket} ->
        {:ok, socket}

      {:lifecycle_result, ^helper, ^nonce, ^observer, {:error, _} = error} ->
        error

      {:lifecycle_failure, ^observer, ^cell, {:error, _} = error} ->
        error

      {:DOWN, ^monitor, :process, ^helper, _} ->
        await(helper, nonce, observer, receipt, nil, observer_monitor, endpoint, deadline)

      {:DOWN, ^observer_monitor, :process, ^observer, _} ->
        # Observer expiry can queue DOWN before this receive's timeout. Preserve
        # its sealed cause without treating cancellation or lost evidence as expiry.
        case Receipt.read(receipt) do
          {:sealed, %{setup_failure: :timeout}} -> {:error, :timeout}
          _ -> {:error, :closed}
        end
    after
      Options.remaining(deadline) -> {:error, :timeout}
    end
  end

  defp transfer(%Socket{} = carrier, owner, deadline),
    do: Carrier.transfer(carrier, owner, deadline)

  defp transfer(tcp, owner, _deadline), do: :gen_tcp.controlling_process(tcp, owner)

  defp finish({:error, reason} = result, receipt, lease, deadline) do
    category =
      case reason do
        {:options, _} -> :options
        :timeout -> :timeout
        :deadline_exceeded -> :timeout
        {:tls_alert, _} -> :tls
        {:peer_alert, _, _} -> :tls
        _ -> :connect
      end

    _ = Observer.failure(receipt, lease, category, budget(deadline))
    result
  end

  defp finish(result, _receipt, _lease, _deadline), do: result

  defp owned(tcp) when is_port(tcp) do
    case Port.info(tcp, :connected) do
      {:connected, owner} when owner == self() -> :ok
      {:connected, _} -> {:error, :not_owner}
      _ -> {:error, :closed}
    end
  end

  defp owned(_), do: {:error, :badarg}

  defp boundary(tcp) do
    with {:ok, opts} <- :inet.getopts(tcp, [:active, :packet, :mode]),
         true <- opts[:active] == false and opts[:packet] in [0, :raw] and opts[:mode] == :binary,
         false <- delivered?(tcp) do
      case :gen_tcp.recv(tcp, 0, 0) do
        {:error, :timeout} -> :ok
        {:ok, _} -> {:error, :pending_plaintext}
        error -> error
      end
    else
      true -> {:error, :pending_plaintext}
      false -> {:error, {:options, :unsupported_tcp_state}}
      error -> error
    end
  end

  defp delivered?(tcp) do
    {:messages, messages} = Process.info(self(), :messages)

    Enum.any?(messages, fn
      {:tcp, ^tcp, _} -> true
      {:tcp_closed, ^tcp} -> true
      {:tcp_error, ^tcp, _} -> true
      _ -> false
    end)
  end

  defp budget(:infinity), do: {:abs_ms, now() + 1_000}
  defp budget(deadline), do: {:abs_ms, min(now() + 1_000, deadline)}
  defp now, do: System.monotonic_time(:millisecond)
end
