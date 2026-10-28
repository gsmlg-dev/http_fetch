defmodule SSL.Lifecycle.Carrier do
  @moduledoc false

  alias SSL.{Options, Socket}

  # These control calls use the original setup deadline. A timed-out transfer
  # stays uncertain; it never grants permission to reuse or replay the carrier.
  def owned(socket, deadline), do: call(socket, :carrier_owned, deadline)

  def owned_by?(socket, owner, deadline),
    do: call(socket, {:carrier_owned_by, owner}, deadline) == :ok

  def boundary(socket, deadline) do
    with :ok <- call(socket, :carrier_boundary, deadline) do
      {:messages, messages} = Process.info(self(), :messages)

      if Enum.any?(messages, fn
           {:ssl, ^socket, _} -> true
           {:ssl_closed, ^socket} -> true
           {:ssl_error, ^socket, _} -> true
           _ -> false
         end),
         do: {:error, :pending_plaintext},
         else: :ok
    end
  end

  def transfer(socket, owner, deadline),
    do: call(socket, {:controlling_process, owner}, deadline)

  # The authenticated caller still has to own the carrier when this is handled.
  # Abandoning the reply is not cleanup evidence; both handles remain readable.
  def request_close(%Socket{pid: pid, ref: ref}) do
    request = :gen_statem.send_request(pid, {ref, :close})
    _ = :gen_statem.receive_response(request, 0)
    :ok
  catch
    :exit, _ -> :ok
  end

  defp call(%Socket{pid: pid, ref: ref}, request, deadline) do
    case Options.remaining(deadline) do
      0 -> {:error, :timeout}
      remaining -> :gen_statem.call(pid, {ref, request}, min(remaining, 1_000))
    end
  catch
    :exit, {:timeout, _} -> {:error, :acceptance_unconfirmed}
    :exit, _ -> {:error, :closed}
  end
end
