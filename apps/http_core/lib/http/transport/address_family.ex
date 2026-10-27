defmodule HTTP.Transport.AddressFamily do
  @moduledoc false

  # Preference applies only while establishing native TCP. Once a socket has
  # connected, TLS and HTTP failures are never reasons to try another address.
  def connect(host, port, socket_opts, opts, timeout) do
    address = Keyword.get(opts, :connect_address, String.to_charlist(host))

    if preferred?(opts) do
      deadline = deadline(timeout)

      case connect_attempt(address, port, [:inet6 | socket_opts], deadline) do
        {:ok, _socket} = connected -> connected
        {:error, reason} = interrupted when reason in [:aborted, :request_timeout] -> interrupted
        {:error, _reason} -> connect_attempt(address, port, [:inet | socket_opts], deadline)
      end
    else
      :gen_tcp.connect(address, port, socket_opts, timeout)
    end
  end

  def preferred?(opts) do
    socket_opts = Keyword.get(opts, :socket_opts, [])

    Keyword.get(opts, :prefer_ipv6, false) == true and
      Keyword.get(opts, :connect_address) == nil and is_list(socket_opts) and
      not Enum.any?(socket_opts, &(&1 in [:inet, :inet6]))
  end

  defp connect_attempt(address, port, socket_opts, deadline) do
    receive do
      :abort -> {:error, :aborted}
      :deadline -> {:error, :request_timeout}
      {:close_socket, _ref} -> {:error, :aborted}
    after
      0 ->
        case remaining(deadline) do
          0 -> {:error, :timeout}
          timeout -> :gen_tcp.connect(address, port, socket_opts, timeout)
        end
    end
  end

  defp deadline(:infinity), do: :infinity
  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout
  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
