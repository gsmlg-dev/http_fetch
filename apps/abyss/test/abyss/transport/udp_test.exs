defmodule Abyss.Transport.UDPTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Abyss.Transport.UDP

  describe "listen/2" do
    test "creates UDP socket with default options" do
      assert {:ok, socket} = UDP.listen(0, [])
      assert is_port(socket)
      assert :ok = UDP.close(socket)
    end

    test "creates UDP socket with custom options" do
      options = [recbuf: 8192, sndbuf: 8192, broadcast: true]
      assert {:ok, socket} = UDP.listen(0, options)
      assert is_port(socket)
      assert :ok = UDP.close(socket)
    end

    test "returns error for invalid port" do
      assert {:error, {:invalid_port, -1}} = UDP.listen(-1, [])
    end

    test "binds to specified port" do
      # Find an available port
      {:ok, socket} = UDP.listen(0, [])
      {:ok, {_ip, port}} = UDP.sockname(socket)

      assert is_integer(port) and port > 0
      assert :ok = UDP.close(socket)
    end
  end

  describe "send/3 and recv/3" do
    test "preserves independent packets including empty and large payloads" do
      {:ok, server} = UDP.listen(0, ip: {127, 0, 0, 1}, buffer: 65_536)
      {:ok, {ip, port}} = UDP.sockname(server)
      {:ok, client} = UDP.listen(0, [])

      try do
        for packet <- ["hello", "", "distinct", :binary.copy("x", 65_507)] do
          assert :ok = UDP.send(client, ip, port, packet)
          assert {:ok, {{127, 0, 0, 1}, _, ^packet}} = UDP.recv(server, 0, 1000)
        end
      after
        UDP.close(server)
        UDP.close(client)
      end
    end

    test "preserves available ancillary fields" do
      {:ok, server} = UDP.listen(0, ip: {127, 0, 0, 1}, recvtos: true)
      {:ok, {ip, port}} = UDP.sockname(server)
      {:ok, client} = UDP.listen(0, [])

      try do
        assert :ok = UDP.send(client, ip, port, "ancillary")
        assert {:ok, {_, _, ancillary, "ancillary"}} = UDP.recv(server, 0, 1000)
        assert {:tos, 0} in ancillary
      after
        UDP.close(server)
        UDP.close(client)
      end
    end

    test "idle receive times out" do
      {:ok, server} = UDP.listen(0, [])

      try do
        assert {:error, :timeout} = UDP.recv(server, 0, 10)
      after
        UDP.close(server)
      end
    end
  end

  describe "sockname/1" do
    setup do
      {:ok, socket} = UDP.listen(0, [])
      on_exit(fn -> UDP.close(socket) end)
      {:ok, %{socket: socket}}
    end

    test "returns local socket info", %{socket: socket} do
      assert {:ok, {ip, port}} = UDP.sockname(socket)
      assert is_tuple(ip)
      assert is_integer(port) and port > 0
    end
  end

  describe "peername/1" do
    test "an unconnected UDP socket has no remote endpoint" do
      {:ok, socket} = UDP.listen(0, [])

      try do
        assert {:error, :enotconn} = UDP.peername(socket)
      after
        UDP.close(socket)
      end
    end
  end

  describe "getopts/2 and setopts/2" do
    setup do
      {:ok, socket} = UDP.listen(0, [])
      on_exit(fn -> UDP.close(socket) end)
      {:ok, %{socket: socket}}
    end

    test "get and set socket options", %{socket: socket} do
      assert {:ok, opts} = UDP.getopts(socket, [:recbuf, :sndbuf])
      assert is_list(opts)

      assert :ok = UDP.setopts(socket, recbuf: 16384)
      assert {:ok, [recbuf: recbuf]} = UDP.getopts(socket, [:recbuf])
      assert recbuf > 0
    end
  end

  describe "getstat/1" do
    setup do
      {:ok, socket} = UDP.listen(0, [])
      on_exit(fn -> UDP.close(socket) end)
      {:ok, %{socket: socket}}
    end

    test "returns socket statistics", %{socket: socket} do
      assert {:ok, stats} = UDP.getstat(socket)
      assert is_list(stats)

      # Should contain at least some basic stats
      stat_names = Enum.map(stats, fn {name, _value} -> name end)
      assert :recv_oct in stat_names or :send_oct in stat_names
    end
  end

  describe "controlling_process/2" do
    setup do
      {:ok, socket} = UDP.listen(0, [])
      on_exit(fn -> UDP.close(socket) end)
      {:ok, %{socket: socket}}
    end

    test "transfers socket ownership", %{socket: socket} do
      test_pid = spawn(fn -> Process.sleep(1000) end)

      assert :ok = UDP.controlling_process(socket, test_pid)

      # Verify process is still alive
      assert Process.alive?(test_pid)
      Process.exit(test_pid, :kill)
    end
  end

  describe "close/1" do
    test "closes socket successfully" do
      {:ok, socket} = UDP.listen(0, [])
      assert :ok = UDP.close(socket)

      # Socket should be closed
      assert {:error, :einval} = UDP.sockname(socket)
    end

    test "handles already closed socket" do
      {:ok, socket} = UDP.listen(0, [])
      :ok = UDP.close(socket)
      # Should be idempotent
      assert :ok = UDP.close(socket)
    end
  end

  describe "send_recv/3" do
    test "sends and receives a response" do
      {:ok, server} = UDP.listen(0, ip: {127, 0, 0, 1}, active: false)
      {:ok, {_ip, port}} = UDP.sockname(server)

      echo =
        Task.async(fn ->
          {:ok, {ip, from_port, data}} = UDP.recv(server, 0, 1000)
          UDP.send(server, ip, from_port, data)
        end)

      assert {:ok, {_ip, ^port, "ping"}} = UDP.send_recv({{127, 0, 0, 1}, port}, "ping", 1000)

      Task.await(echo)
      UDP.close(server)
    end

    test "does not leak sockets on timeout" do
      # A silent server: packets arrive but are never answered
      {:ok, server} = UDP.listen(0, ip: {127, 0, 0, 1})
      {:ok, {_ip, port}} = UDP.sockname(server)

      ports_before = length(Port.list())

      for _ <- 1..10 do
        assert {:error, :timeout} = UDP.send_recv({{127, 0, 0, 1}, port}, "ping", 20)
      end

      # A leak would grow the port count by exactly 10
      assert length(Port.list()) - ports_before < 5

      UDP.close(server)
    end

    test "returns an error without raising when send fails" do
      # Payload above the UDP maximum -> send fails locally with :emsgsize
      oversized = :binary.copy(<<0>>, 70_000)
      assert {:error, :emsgsize} = UDP.send_recv({{127, 0, 0, 1}, 9999}, oversized, 20)
    end
  end
end
