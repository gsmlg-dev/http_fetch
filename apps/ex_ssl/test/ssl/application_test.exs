defmodule SSL.ApplicationTest do
  use ExUnit.Case, async: true

  test "starts the ex_ssl supervision tree" do
    assert Application.get_application(SSL) == :ex_ssl
    assert Process.whereis(SSL.Supervisor) |> Process.alive?()
    assert Process.whereis(SSL.ConnectionSupervisor) |> Process.alive?()
  end
end
