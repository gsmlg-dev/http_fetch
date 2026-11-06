defmodule Abyss.Test.DropAccountingHandler do
  @moduledoc "Real UDP inputs and controlled application work for drop-accounting regressions."
  @behaviour Abyss.DatagramHandler

  def init(options, _context), do: {:ok, Map.new(options)}

  def handle_datagram(datagram, state) do
    send(state.owner, {:drop_callback, self(), datagram.payload})
    if datagram.payload in ["block", "block-fail"], do: receive(do: (:finish_callback -> :ok))
    transition(datagram.payload, state)
  end

  defp transition("timer", state),
    do: {:ok, state, [{:timer, :large_event, 10, :binary.copy(<<1>>, 2048)}]}

  defp transition("outcomes", state),
    do: {:ok, state, for(i <- 1..32, do: {:reply, <<i>>})}

  defp transition(payload, state) when payload in ["fail", "block-fail"],
    do: {:error, :controlled_failure, state}

  defp transition("failed-send", state),
    do: {:ok, state, [{:reply, :binary.copy(<<1>>, 65_536)}]}

  defp transition(_, state), do: {:ok, state, []}

  def handle_event(event, state) do
    send(state.owner, {:drop_internal_callback, event})
    {:ok, state, []}
  end

  def terminate(reason, state), do: send(state.owner, {:drop_terminated, self(), reason})
end
