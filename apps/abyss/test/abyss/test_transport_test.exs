defmodule Abyss.TestTransportTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  test "mock transport listener and receive values satisfy the UDP callback shapes" do
    assert {:ok, socket} =
             Abyss.TestTransport.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])

    on_exit(fn -> Abyss.TestTransport.close(socket) end)

    assert {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(socket)
    assert port > 0

    assert {:ok, {{127, 0, 0, 1}, 12_345, "test data"}} =
             Abyss.TestTransport.recv(socket, 0, 1000)

    assert :ok = Abyss.TestTransport.close(socket)
    assert {:error, _reason} = :inet.sockname(socket)
  end
end
