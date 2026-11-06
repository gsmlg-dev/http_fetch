defmodule HTTP.PromiseTest do
  use ExUnit.Case
  doctest HTTP.Promise

  describe "Promise struct" do
    test "create promise" do
      task = Task.async(fn -> {:ok, %HTTP.Response{}} end)
      promise = %HTTP.Promise{task: task}
      assert %HTTP.Promise{} = promise
    end

    test "await promise" do
      task = Task.async(fn -> %HTTP.Response{status: 200} end)
      promise = %HTTP.Promise{task: task}
      assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise)
    end
  end

  describe "await/2" do
    setup do
      %{supervisor: start_supervised!(Task.Supervisor)}
    end

    test "finite waits can time out without losing the eventual result", %{supervisor: supervisor} do
      response = %HTTP.Response{status: 200, body: "finished"}

      task =
        Task.Supervisor.async_nolink(supervisor, fn ->
          receive do
            :finish -> response
          end
        end)

      promise = %HTTP.Promise{task: task}

      for timeout <- [0, 1] do
        assert {:error, :timeout} = HTTP.Promise.await(promise, timeout)
        assert Process.alive?(task.pid)
      end

      send(task.pid, :finish)
      assert ^response = HTTP.Promise.await(promise, 1_000)
    end

    test "request errors remain request errors", %{supervisor: supervisor} do
      task = Task.Supervisor.async_nolink(supervisor, fn -> {:error, :econnrefused} end)
      assert {:error, :econnrefused} = HTTP.Promise.await(%HTTP.Promise{task: task}, 1_000)
    end

    test "task exits are not converted into wait timeouts", %{supervisor: supervisor} do
      task =
        Task.Supervisor.async_nolink(supervisor, fn ->
          receive do
            :finish -> :ok
          end
        end)

      Process.exit(task.pid, :kill)

      assert {:killed, {Task, :await, [^task, 1_000]}} =
               catch_exit(HTTP.Promise.await(%HTTP.Promise{task: task}, 1_000))
    end
  end
end
