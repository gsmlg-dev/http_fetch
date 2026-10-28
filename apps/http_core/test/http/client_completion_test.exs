defmodule HTTP.ClientCompletionTest do
  use ExUnit.Case, async: true

  alias HTTP.ClientCompletion
  alias HTTP.RequestLifecycle

  test "receipt survives owner and tracker; repeated and concurrent waits agree" do
    Code.ensure_loaded!(ClientCompletion)
    Code.ensure_loaded!(RequestLifecycle)
    parent = self()

    owner =
      spawn(fn ->
        receipt = ClientCompletion.new()
        :ok = RequestLifecycle.enter(receipt.tracker, :owner)
        send(parent, {:receipt, receipt})

        receive do
          :finish -> RequestLifecycle.complete(receipt.tracker)
        end
      end)

    assert_receive {:receipt, receipt}
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    send(owner, :finish)
    assert :ok = ClientCompletion.await(receipt, 1_000)
    assert :ok = ClientCompletion.await(receipt, 0)
    tasks = for _ <- 1..4, do: Task.async(fn -> ClientCompletion.await(receipt, 10) end)
    assert [:ok, :ok, :ok, :ok] = Enum.map(tasks, &Task.await/1)
    refute Process.alive?(receipt.tracker)
  end

  test "unsealed tracker death can never become empty-set success" do
    receipt = ClientCompletion.new()
    Process.exit(receipt.tracker, :kill)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  test "unsupported route is explicit" do
    assert {:error, {:unsupported_completion, :http3}} =
             ClientCompletion.await(ClientCompletion.unsupported(:http3), 0)
  end
end
