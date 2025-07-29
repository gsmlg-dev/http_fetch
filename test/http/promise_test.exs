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
      task = Task.async(fn -> {:ok, %HTTP.Response{status: 200}} end)
      promise = %HTTP.Promise{task: task}
      assert {:ok, %HTTP.Response{status: 200}} = HTTP.Promise.await(promise)
    end
  end
end