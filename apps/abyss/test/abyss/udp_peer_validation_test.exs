defmodule Abyss.UDPPeerValidationTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Abyss.Client
  alias Abyss.Transport.UDP
  alias Abyss.Transport.UDP.{Core, Unicast}

  @loopback {127, 0, 0, 1}

  for helper <- [:client, :udp, :unicast], address <- [{127, 0, 0, 1}, {127, 0, 0, 2}] do
    test "#{helper} rejects unrelated source #{inspect(address)} before valid empty reply" do
      helper = unquote(helper)
      address = unquote(Macro.escape(address))
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
      {:ok, stranger} = :gen_udp.open(0, [:binary, active: false, ip: address])
      {:ok, {_, port}} = :inet.sockname(peer)

      try do
        task = Task.async(fn -> request(helper, port, 300) end)
        assert {:ok, {ip, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
        assert :ok = :gen_udp.send(stranger, ip, client_port, "wrong")
        assert :ok = :gen_udp.send(peer, ip, client_port, "")
        result = Task.await(task)

        assert result == expected_response(helper, port, "")
      after
        :gen_udp.close(peer)
        :gen_udp.close(stranger)
      end
    end
  end

  for helper <- [:client, :udp, :unicast] do
    test "#{helper} times out under a continuous wrong-port flood" do
      helper = unquote(helper)
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
      {:ok, {_, port}} = :inet.sockname(peer)
      task = Task.async(fn -> request(helper, port, 80) end)
      assert {:ok, {ip, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)

      flood =
        Task.async(fn ->
          {:ok, sender} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])

          try do
            for _ <- 1..250 do
              :ok = :gen_udp.send(sender, ip, client_port, "wrong")
              Process.sleep(1)
            end
          after
            :gen_udp.close(sender)
          end
        end)

      started = System.monotonic_time(:millisecond)

      try do
        assert {:error, :timeout} = Task.await(task, 500)
        assert System.monotonic_time(:millisecond) - started < 200
      after
        Task.shutdown(flood, :brutal_kill)
        :gen_udp.close(peer)
      end
    end
  end

  test "hostname target is resolved once and valid response is preserved" do
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, {_, port}} = :inet.sockname(peer)

    try do
      task = Task.async(fn -> Client.send_recv("localhost", port, "query", 300) end)
      assert {:ok, {ip, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
      assert :ok = :gen_udp.send(peer, ip, client_port, "answer")
      assert {:ok, "answer"} = Task.await(task)
    after
      :gen_udp.close(peer)
    end
  end

  test "send error precedes receive and zero response budget returns timeout" do
    for helper <- [:client, :udp, :unicast] do
      assert {:error, :emsgsize} = request(helper, 49_999, 100, :binary.copy("x", 65_536))
      assert {:error, :timeout} = request(helper, 49_999, 0)
    end
  end

  test "multicast send_recv preserves a response from a different unicast endpoint" do
    group = {239, 255, 42, 81}
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, add_membership: {group, @loopback}])
    {:ok, responder} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, {_, port}} = :inet.sockname(peer)

    try do
      task = Task.async(fn -> Client.send_recv(group, port, "query", 300, source: @loopback) end)
      assert {:ok, {ip, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
      assert :ok = :gen_udp.send(responder, ip, client_port, "group-answer")
      assert {:ok, "group-answer"} = Task.await(task)
    after
      :gen_udp.close(peer)
      :gen_udp.close(responder)
    end
  end

  test "exact receive preserves ancillary and IPv6 scope matching" do
    {:ok, client} =
      Core.open_socket(0, [{:inet_backend, :inet}, :binary, {:active, false}, {:recvttl, true}])

    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, {_, port}} = :inet.sockname(peer)

    responder =
      Task.async(fn ->
        {:ok, {ip, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
        :gen_udp.send(peer, ip, client_port, "")
      end)

    try do
      assert {:ok, {@loopback, ^port, ancillary, ""}} =
               Core.exchange(client, {@loopback, port}, "query", 300, :exact)

      assert Keyword.has_key?(ancillary, :ttl)
      assert Core.peer_matches?({@loopback, port, ancillary, ""}, {@loopback, port})
      refute Core.peer_matches?({@loopback, port + 1, ancillary, ""}, {@loopback, port})
      assert :ok = Task.await(responder)
    after
      Core.close(client)
      :gen_udp.close(peer)
    end

    ip = {0xFE80, 0, 0, 0, 0, 0, 0, 1}
    expected = %{family: :inet6, addr: ip, port: 1234, scope_id: 2}
    assert Core.peer_matches?({expected, 1234, ""}, expected)
    refute Core.peer_matches?({%{expected | scope_id: 3}, 1234, ""}, expected)
    refute Core.peer_matches?({ip, 1234, ""}, expected)
  end

  test "explicit backend clients filter peer provenance on IPv4 and IPv6" do
    for {ip, family} <- [{@loopback, :inet}, {{0, 0, 0, 0, 0, 0, 0, 1}, :inet6}],
        backend <- [:inet, :socket] do
      {:ok, peer} = :gen_udp.open(0, [family, :binary, {:active, false}, {:ip, ip}])
      {:ok, stranger} = :gen_udp.open(0, [family, :binary, {:active, false}, {:ip, ip}])
      {:ok, {_, port}} = :inet.sockname(peer)

      try do
        task =
          Task.async(fn -> Client.send_recv(ip, port, "query", 300, inet_backend: backend) end)

        assert {:ok, {address, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
        assert :ok = :gen_udp.send(stranger, address, client_port, "wrong")
        assert :ok = :gen_udp.send(peer, address, client_port, "answer")
        assert {:ok, "answer"} = Task.await(task)
      after
        :gen_udp.close(peer)
        :gen_udp.close(stranger)
      end
    end
  end

  test "explicit cross-peer policy remains available without changing the default" do
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, other} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, {_, port}} = :inet.sockname(peer)
    {:ok, {_, other_port}} = :inet.sockname(other)

    try do
      for transport <- [UDP, Unicast] do
        task =
          Task.async(fn ->
            transport.send_recv({@loopback, port}, "query", 300, response_policy: :any)
          end)

        assert {:ok, {address, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
        assert :ok = :gen_udp.send(other, address, client_port, "answer")
        assert {:ok, {@loopback, ^other_port, "answer"}} = Task.await(task)
      end
    after
      :gen_udp.close(peer)
      :gen_udp.close(other)
    end
  end

  test "multicast collectors preserve identical replies from multiple peers" do
    group = {239, 255, 42, 83}
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, add_membership: {group, @loopback}])
    {:ok, other} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, {_, port}} = :inet.sockname(peer)
    {:ok, {_, other_port}} = :inet.sockname(other)

    try do
      task =
        Task.async(fn -> Client.multicast_query(group, port, "query", 80, source: @loopback) end)

      assert {:ok, {address, client_port, "query"}} = :gen_udp.recv(peer, 0, 1000)
      assert :ok = :gen_udp.send(peer, address, client_port, "same")
      assert :ok = :gen_udp.send(other, address, client_port, "same")
      assert {:ok, responses} = Task.await(task)

      assert Enum.sort(responses) ==
               Enum.sort([{@loopback, port, "same"}, {@loopback, other_port, "same"}])
    after
      :gen_udp.close(peer)
      :gen_udp.close(other)
    end
  end

  defp expected_response(:client, _port, data), do: {:ok, data}
  defp expected_response(_, port, data), do: {:ok, {@loopback, port, data}}

  defp request(helper, port, timeout, data \\ "query")
  defp request(:client, port, timeout, data), do: Client.send_recv(@loopback, port, data, timeout)
  defp request(:udp, port, timeout, data), do: UDP.send_recv({@loopback, port}, data, timeout)

  defp request(:unicast, port, timeout, data),
    do: Unicast.send_recv({@loopback, port}, data, timeout)
end
