defmodule HTTP.EventSource.ProxyRouteTest do
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
      assert_invalid(:proxy_not_supported, fn ->
        HTTP.EventSource.new("http://127.0.0.1:#{port}/events", init)
      end)

      assert {:error, :timeout} = :gen_tcp.accept(origin, 25)
    end
  end

  defp assert_invalid(reason, fun),
    do: assert_raise(ArgumentError, "invalid HTTP.EventSource options: #{inspect(reason)}", fun)
end
