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
        assert {:error, :await_timeout} = HTTP.Promise.await(promise, timeout)
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

  describe "then/3" do
    setup do
      %{supervisor: start_supervised!(Task.Supervisor)}
    end

    defp promise(supervisor, result) do
      %HTTP.Promise{task: Task.Supervisor.async_nolink(supervisor, fn -> result end)}
    end

    defp gated(supervisor, result) do
      task =
        Task.Supervisor.async_nolink(supervisor, fn ->
          receive do
            :finish -> result
          end
        end)

      %HTTP.Promise{task: task}
    end

    test "success callback receives the response and its value resolves the chain", %{
      supervisor: supervisor
    } do
      response = %HTTP.Response{status: 200, body: ~s({"name":"Ada"})}

      chained =
        supervisor
        |> promise(response)
        |> HTTP.Promise.then(&HTTP.Response.json/1)

      assert {:ok, %{"name" => "Ada"}} = HTTP.Promise.await(chained, 1_000)
    end

    test "multi-step chains pass each fulfilled value as-is to the next callback", %{
      supervisor: supervisor
    } do
      response = %HTTP.Response{status: 200, body: ~s({"name":"Ada"})}

      result =
        supervisor
        |> promise(response)
        |> HTTP.Promise.then(&HTTP.Response.json/1)
        |> HTTP.Promise.then(fn {:ok, user} -> user["name"] end)
        |> HTTP.Promise.then(&String.upcase/1)
        |> HTTP.Promise.await(1_000)

      assert result == "ADA"
    end

    test "then/3 does not block and callbacks run in the awaiting process", %{
      supervisor: supervisor
    } do
      parent = self()
      root = gated(supervisor, %HTTP.Response{status: 204})
      chained = HTTP.Promise.then(root, fn response -> {self(), response.status} end)

      send(root.task.pid, :finish)
      assert {^parent, 204} = HTTP.Promise.await(chained, 1_000)
    end

    test "rejections skip success callbacks and propagate without an error callback", %{
      supervisor: supervisor
    } do
      result =
        supervisor
        |> promise({:error, :econnrefused})
        |> HTTP.Promise.then(fn _ -> flunk("success callback must not run") end)
        |> HTTP.Promise.then(fn _ -> flunk("success callback must not run") end)
        |> HTTP.Promise.await(1_000)

      assert result == {:error, :econnrefused}
    end

    test "error callbacks receive the reason and may recover or reject", %{
      supervisor: supervisor
    } do
      recovered =
        supervisor
        |> promise({:error, :econnrefused})
        |> HTTP.Promise.then(fn _ -> flunk("unreachable") end, fn reason ->
          {:fallback, reason}
        end)
        |> HTTP.Promise.then(fn value -> {:next, value} end)

      assert {:next, {:fallback, :econnrefused}} = HTTP.Promise.await(recovered, 1_000)

      rejected =
        supervisor
        |> promise({:error, :econnrefused})
        |> HTTP.Promise.then(fn _ -> flunk("unreachable") end, fn _ -> {:error, :handled} end)
        |> HTTP.Promise.then(fn _ -> flunk("unreachable") end)

      assert {:error, :handled} = HTTP.Promise.await(rejected, 1_000)
    end

    test "a success callback returning an error tuple rejects the chain", %{
      supervisor: supervisor
    } do
      result =
        supervisor
        |> promise(%HTTP.Response{status: 200, body: "not json"})
        |> HTTP.Promise.then(fn _ -> {:error, :bad_payload} end)
        |> HTTP.Promise.then(fn _ -> flunk("unreachable") end, fn reason -> {:caught, reason} end)
        |> HTTP.Promise.await(1_000)

      assert result == {:caught, :bad_payload}
    end

    test "callbacks returning a promise are flattened, including its own chain", %{
      supervisor: supervisor
    } do
      comments = %HTTP.Response{status: 200, body: ~s([1,2,3])}

      result =
        supervisor
        |> promise(%HTTP.Response{status: 200, body: ~s({"id":1})})
        |> HTTP.Promise.then(fn _post ->
          supervisor |> promise(comments) |> HTTP.Promise.then(&HTTP.Response.json/1)
        end)
        |> HTTP.Promise.then(fn {:ok, list} -> length(list) end)
        |> HTTP.Promise.await(1_000)

      assert result == 3

      rejected =
        supervisor
        |> promise(%HTTP.Response{status: 200})
        |> HTTP.Promise.then(fn _ -> promise(supervisor, {:error, :nested}) end)
        |> HTTP.Promise.then(fn _ -> flunk("unreachable") end)

      assert {:error, :nested} = HTTP.Promise.await(rejected, 1_000)
    end

    test "await timeout applies to the root request and leaves the chain re-awaitable", %{
      supervisor: supervisor
    } do
      root = gated(supervisor, %HTTP.Response{status: 200})
      chained = HTTP.Promise.then(root, fn response -> response.status end)

      assert {:error, :await_timeout} = HTTP.Promise.await(chained, 0)
      send(root.task.pid, :finish)
      assert 200 = HTTP.Promise.await(chained, 1_000)
    end

    test "await timeout bounds a nested promise returned by a callback", %{
      supervisor: supervisor
    } do
      nested = gated(supervisor, %HTTP.Response{status: 201})

      chained =
        supervisor
        |> promise(%HTTP.Response{status: 200})
        |> HTTP.Promise.then(fn _ -> nested end)
        |> HTTP.Promise.then(fn _ -> flunk("timeout must stop the chain") end, fn _ ->
          flunk("timeout is not a rejection")
        end)

      assert {:error, :await_timeout} = HTTP.Promise.await(chained, 50)
      assert Process.alive?(nested.task.pid)
    end

    test "a crashed root or nested task exits the caller like await/2", %{
      supervisor: supervisor
    } do
      root = gated(supervisor, :never)
      Process.exit(root.task.pid, :kill)
      chained = HTTP.Promise.then(root, fn _ -> flunk("unreachable") end)
      assert {:killed, {Task, :await, _}} = catch_exit(HTTP.Promise.await(chained, 1_000))

      nested = gated(supervisor, :never)
      Process.exit(nested.task.pid, :kill)

      chained =
        supervisor
        |> promise(%HTTP.Response{status: 200})
        |> HTTP.Promise.then(fn _ -> nested end)

      assert {:killed, {Task, :await, _}} = catch_exit(HTTP.Promise.await(chained, 1_000))
    end

    test "chained promises keep the original request completion handle", %{
      supervisor: supervisor
    } do
      root = %{promise(supervisor, %HTTP.Response{}) | completion: :handle}
      assert HTTP.Promise.completion(HTTP.Promise.then(root, & &1)) == :handle
    end
  end
end
