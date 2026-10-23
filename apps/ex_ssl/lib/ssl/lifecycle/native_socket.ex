defmodule SSL.Lifecycle.NativeSocket do
  @moduledoc false
  alias SSL.Lifecycle.{Observer, Receipt}

  # Private raw IPv4 Socket constructor, not a gen_tcp backend handle or TLS readiness.
  # The original observer enrolls this exact object before the native connect call.
  @spec connect(Receipt.t(), :inet.ip4_address(), 1..65_535, {:abs_ms, integer()}) ::
          {:ok, :socket.socket()} | {:error, term()}
  def connect(receipt, {_, _, _, _} = ip, port, {:abs_ms, deadline} = budget)
      when is_integer(port) and port in 1..65_535 and is_integer(deadline) do
    with true <- Enum.all?(Tuple.to_list(ip), &(is_integer(&1) and &1 in 0..255)),
         {:ok, _} <- remaining(budget),
         observer = Receipt.observer(receipt),
         true <- node(observer) == node(),
         {:ok, token} <- Observer.reserve_child(receipt, :tcp, budget),
         {:ok, _} <- remaining(budget),
         {:ok, socket} <- :socket.open(:inet, :stream, :tcp) do
      enroll(receipt, observer, token, socket, ip, port, budget)
    else
      false -> {:error, :invalid_arguments}
      {:error, _} = error -> error
    end
  end

  def connect(_, _, _, _), do: {:error, :invalid_arguments}

  @spec close_owned(:socket.socket()) :: :ok | {:error, term()}
  def close_owned(socket) do
    case :socket.getopt(socket, :otp, :controlling_process) do
      {:ok, owner} when owner == self() -> :socket.close(socket)
      {:ok, _owner} -> {:error, :not_owner}
      {:error, _} = error -> error
    end
  catch
    _, _ -> {:error, :close_unconfirmed}
  end

  defp enroll(receipt, observer, token, socket, ip, port, budget) do
    try do
      with :use <- Observer.enroll_socket(receipt, token, socket, budget),
           {:ok, milliseconds} <- remaining(budget),
           true <- Process.alive?(observer) do
        connect_enrolled(receipt, observer, socket, ip, port, milliseconds, budget)
      else
        :stop -> close_error(socket, {:error, :admission_closed})
        false -> close_error(socket, {:error, :acceptance_unconfirmed})
        {:error, _} = error -> close_error(socket, error)
      end
    catch
      kind, reason ->
        _ = close_owned(socket)
        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  defp connect_enrolled(receipt, observer, socket, ip, port, milliseconds, budget) do
    address = %{family: :inet, addr: ip, port: port}

    case :socket.connect(socket, address, milliseconds) do
      :ok ->
        connected(socket, observer, budget)

      {:error, reason} = error ->
        record_failure(receipt, socket, reason, budget)
        close_error(socket, error)
    end
  end

  defp connected(socket, observer, budget) do
    with {:ok, _} <- remaining(budget),
         true <- Process.alive?(observer) do
      {:ok, socket}
    else
      false -> close_error(socket, {:error, :acceptance_unconfirmed})
      {:error, _} = error -> close_error(socket, error)
    end
  end

  # Publish while ownership is still attributable. Closing first can retire the
  # original observer; native errno and this RPC never substitute for cleanup.
  defp record_failure(receipt, socket, reason, budget)
       when reason in [:econnrefused, :enetunreach, :ehostunreach] do
    _ = Observer.record_socket_connect_failure(receipt, socket, reason, budget)
    :ok
  catch
    _, _ -> :ok
  end

  defp record_failure(_receipt, _socket, _reason, _budget), do: :ok

  defp close_error(socket, error) do
    _ = close_owned(socket)
    error
  end

  defp remaining({:abs_ms, deadline}) do
    case deadline - System.monotonic_time(:millisecond) do
      value when value > 0 -> {:ok, min(value, 0xFFFFFFFF)}
      _ -> {:error, :deadline_exceeded}
    end
  end
end
