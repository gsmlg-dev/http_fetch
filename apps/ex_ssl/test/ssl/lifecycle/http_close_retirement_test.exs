defmodule SSL.PolicyIOHTTPCloseRetirementTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias SSL.PolicyIO

  test "an admitted native close retains its owner through the setup deadline" do
    attempt = attempt(:valid)

    try do
      assert {:ok, nonce, bound} = attempt.reply
      assert bound <= attempt.deadline

      assert {:error, :unauthorized_policy} =
               PolicyIO.call(attempt.context, {:http_close_finish, attempt.generation, nonce})

      await_deadline(attempt.deadline)
      assert Process.alive?(attempt.owner)
      assert %{policy: %{retirement: grace}} = :sys.get_state(attempt.context.observer)
      assert is_integer(grace)
      assert grace <= attempt.deadline + 1_050

      send(attempt.owner, {attempt.reference, :close})
      assert_socket_down(attempt)
      assert_owner_down(attempt, 500)
      assert_observer_down(attempt)
    after
      stop(attempt)
    end
  end

  test "a different socket generation cannot postpone owner retirement" do
    attempt = attempt(:wrong_generation)

    try do
      assert attempt.reply == {:error, :http_close_not_permitted}
      assert :killed = assert_owner_down(attempt, remaining(attempt.deadline + 500))
      assert_socket_down(attempt)
      assert_observer_down(attempt)
    after
      stop(attempt)
    end
  end

  test "a stuck admitted close cannot outlive the existing retirement grace" do
    attempt = attempt(:valid)

    try do
      assert {:ok, _, bound} = attempt.reply
      assert bound <= attempt.deadline
      assert :killed = assert_owner_down(attempt, remaining(attempt.deadline + 1_500))
      assert System.monotonic_time(:millisecond) <= attempt.deadline + 1_500
      assert_socket_down(attempt)
      assert_observer_down(attempt)
    after
      stop(attempt)
    end
  end

  defp attempt(mode) do
    parent = self()
    reference = make_ref()

    {owner, owner_monitor} =
      spawn_monitor(fn ->
        deadline = System.monotonic_time(:millisecond) + 1_000
        {:ok, context} = PolicyIO.install(nil, parent, deadline)
        {:ok, generation, token} = PolicyIO.call(context, :http)
        {:ok, socket} = :socket.open(:inet, :stream, :tcp)
        :use = PolicyIO.call(context, {:http_enroll, generation, token, socket})
        requested = if mode == :valid, do: generation, else: generation + 1
        reply = PolicyIO.call(context, {:http_close_begin, requested, socket, deadline})
        send(parent, {reference, context, socket, generation, deadline, reply})

        receive do
          {^reference, :close} ->
            :socket.close(socket)
            {:ok, nonce, _} = reply

            PolicyIO.request(
              context.observer,
              {:policy, context.capability, {:http_close_finish, generation, nonce}},
              deadline + 1_000
            )
        end
      end)

    assert_receive {^reference, context, socket, generation, deadline, reply}, 1_000

    %{
      reference: reference,
      owner: owner,
      owner_monitor: owner_monitor,
      context: context,
      observer_monitor: Process.monitor(context.observer),
      socket: socket,
      socket_monitor: :socket.monitor(socket),
      generation: generation,
      deadline: deadline,
      reply: reply
    }
  end

  defp await_deadline(deadline) do
    reference = :erlang.start_timer(remaining(deadline + 20), self(), :setup_deadline)
    assert_receive {:timeout, ^reference, :setup_deadline}, remaining(deadline + 500)
  end

  defp remaining(deadline), do: max(1, deadline - System.monotonic_time(:millisecond))

  defp assert_owner_down(%{owner: owner, owner_monitor: monitor}, timeout) do
    assert_receive {:DOWN, ^monitor, :process, ^owner, reason}, timeout
    reason
  end

  defp assert_socket_down(%{socket: socket, socket_monitor: monitor}) do
    assert_receive {:DOWN, ^monitor, :socket, ^socket, :closed}, 500
  end

  defp assert_observer_down(%{context: %{observer: observer}, observer_monitor: monitor}) do
    assert_receive {:DOWN, ^monitor, :process, ^observer, :normal}, 500
  end

  defp stop(attempt) do
    if Process.alive?(attempt.owner), do: Process.exit(attempt.owner, :kill)

    if Process.alive?(attempt.context.observer) do
      monitor = Process.monitor(attempt.context.observer)

      receive do
        {:DOWN, ^monitor, :process, _, _} -> :ok
      after
        1_500 -> Process.exit(attempt.context.observer, :kill)
      end
    end
  end
end
