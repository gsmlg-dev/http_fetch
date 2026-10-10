defmodule HTTP.ManagedTransport.ScopeTest do
  use ExUnit.Case, async: false

  alias HTTP.ManagedTransport

  for kind <- [:connection, :tls] do
    test "closed raw socket retains capacity until its #{kind} process terminates" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)
      origin = "http://127.0.0.1:#{port}"

      {:ok, scope} =
        ManagedTransport.open(
          origin: origin,
          connect_address: {127, 0, 0, 1},
          http_version: :http1,
          max_requests: 1,
          max_connections: 1
        )

      {tracker, _} = HTTP.RequestLifecycle.start()

      request = %HTTP.Request{
        url: URI.parse(origin),
        transport_options: [
          transport_scope: scope,
          redirect: :manual,
          decode_body: false,
          stream_response: true
        ]
      }

      assert {:ok, request} = ManagedTransport.prepare(request, [])
      assert :ok = ManagedTransport.associate(request, tracker)
      assert :ok = ManagedTransport.admit(request, tracker)
      Process.put(HTTP.RequestLifecycle, tracker)
      assert {:ok, token} = ManagedTransport.connect_start(request)
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 100)
      owner = spawn(fn -> receive do: (:fixture_stop -> :ok) end)
      owner_monitor = Process.monitor(owner)

      on_exit(fn ->
        :gen_tcp.close(listener)
        :gen_tcp.close(socket)
        send(owner, :fixture_stop)
      end)

      assert :ok = GenServer.call(scope.coordinator, {:track, socket, :socket, token})
      assert :ok = GenServer.call(scope.coordinator, {:track, owner, unquote(kind), token})
      assert :ok = ManagedTransport.connect_done(request, token)
      :gen_tcp.close(socket)
      wait_for(scope, :resources, 1)

      assert {:ok, %{connections: 1}} = ManagedTransport.snapshot(scope, 100)

      assert {:error, {:transport_scope_capacity, :connections}} =
               ManagedTransport.connect_start(request)

      send(owner, :fixture_stop)
      assert_receive {:DOWN, ^owner_monitor, _, ^owner, :normal}
      wait_for(scope, :connections, 0)
      assert {:ok, replacement} = ManagedTransport.connect_start(request)
      assert :ok = ManagedTransport.connect_done(request, replacement)
      GenServer.stop(tracker, :normal)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert :ok = ManagedTransport.await_retired(receipt, 1_000)
      Process.delete(HTTP.RequestLifecycle)
    end
  end

  defp wait_for(scope, key, expected, remaining \\ 100)
  defp wait_for(_, _, _, 0), do: flunk("scope resources did not settle")

  defp wait_for(scope, key, expected, remaining) do
    assert {:ok, snapshot} = ManagedTransport.snapshot(scope, 100)

    if snapshot[key] != expected do
      receive do
      after
        5 -> wait_for(scope, key, expected, remaining - 1)
      end
    end
  end
end
