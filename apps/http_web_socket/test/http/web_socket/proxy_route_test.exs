defmodule HTTP.WebSocket.ProxyRouteTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  test "an unreachable proxy never causes a direct origin connection" do
    {:ok, origin} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(origin) end)
    {:ok, {_ip, port}} = :inet.sockname(origin)

    for init <- [
          [proxy: "http://127.0.0.1:1"],
          %{"proxy" => "http://127.0.0.1:1"}
        ] do
      assert {:error, :proxy_not_supported} =
               HTTP.WebSocket.new("ws://127.0.0.1:#{port}/socket", [], init)

      assert {:error, :timeout} = :gen_tcp.accept(origin, 25)
    end
  end
end
