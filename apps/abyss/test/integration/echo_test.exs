defmodule Abyss.Integration.EchoTest do
  use ExUnit.Case, async: false
  alias Abyss.Transport.UDP
  @moduletag :integration

  test "ordinary UDP without QUIC exchanges distinct and empty datagrams" do
    server = start_supervised!({Abyss, [handler_module: Abyss.TestEchoHandler, port: 0]})
    [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
    {_, port} = Abyss.Listener.listener_info(listener)
    {:ok, socket} = UDP.listen(0, [])

    try do
      for data <- ["first", "", "second", :binary.copy("x", 8192)] do
        assert :ok = UDP.send(socket, {127, 0, 0, 1}, port, data)
        assert {:ok, {{127, 0, 0, 1}, ^port, ^data}} = UDP.recv(socket, 0, 1000)
      end
    after
      UDP.close(socket)
    end
  end
end
