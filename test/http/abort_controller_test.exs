defmodule HTTP.AbortControllerTest do
  use ExUnit.Case
  doctest HTTP.AbortController

  describe "AbortController" do
    test "create abort controller" do
      controller = HTTP.AbortController.new()
      assert is_pid(controller)
    end

    test "check if aborted" do
      controller = HTTP.AbortController.new()
      refute HTTP.AbortController.aborted?(controller)
    end
  end
end