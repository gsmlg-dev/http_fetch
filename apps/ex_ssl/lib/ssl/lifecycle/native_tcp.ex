defmodule SSL.Lifecycle.NativeTCP do
  @moduledoc false
  alias SSL.Lifecycle.{Observer, Receipt}

  # Private IPv4 constructor, called by an already-enrolled allocator. The trusted
  # caller supplies ONE absolute deadline already clipped to its setup deadline.
  # A successful return means enrolled allocation, never TLS/application readiness.
  @spec connect(Receipt.t(), :inet.ip4_address(), 1..65_535, {:abs_ms, integer()}) ::
          {:ok, port()} | {:error, term()}
  def connect(
        receipt,
        {_, _, _, _} = ip,
        port,
        {:abs_ms, deadline} = budget
      )
      when is_integer(port) and port in 1..65_535 and is_integer(deadline) do
    observer = Receipt.observer(receipt)

    with true <- node(observer) == node(),
         true <- Enum.all?(Tuple.to_list(ip), &(is_integer(&1) and &1 in 0..255)),
         {:ok, _} <- remaining(budget),
         {:ok, token} <- Observer.reserve_child(receipt, :tcp, budget),
         {:ok, milliseconds} <- remaining(budget) do
      options = [{:inet_backend, :inet}, :inet, :binary, active: false, packet: :raw]

      case :gen_tcp.connect(ip, port, options, milliseconds) do
        {:ok, tcp} -> enroll(receipt, observer, token, tcp, budget)
        {:error, _} = error -> error
      end
    else
      false -> {:error, :invalid_arguments}
      {:error, _} = error -> error
    end
  end

  def connect(_, _, _, _), do: {:error, :invalid_arguments}

  # Native errors retain the unresolved permit. No native-error/no-resource mapping.
  defp enroll(receipt, observer, token, tcp, budget) do
    try do
      with {:ok, _} <- remaining(budget),
           :use <- Observer.enroll_port(receipt, token, tcp, budget),
           {:ok, _} <- remaining(budget),
           true <- Process.alive?(observer) do
        {:ok, tcp}
      else
        :stop -> close(tcp, {:error, :admission_closed})
        false -> close(tcp, {:error, :acceptance_unconfirmed})
        {:error, _} = error -> close(tcp, error)
      end
    catch
      kind, reason ->
        :gen_tcp.close(tcp)
        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  defp close(tcp, error) do
    :gen_tcp.close(tcp)
    error
  end

  defp remaining({:abs_ms, deadline}) do
    case deadline - System.monotonic_time(:millisecond) do
      value when value > 0 -> {:ok, min(value, 0xFFFFFFFF)}
      _ -> {:error, :deadline_exceeded}
    end
  end
end
