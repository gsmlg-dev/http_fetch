defmodule Abyss.ListenerTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  alias Abyss.Listener
  alias Abyss.ServerConfig

  setup do
    config = ServerConfig.new(handler_module: Abyss.TestHandler, port: 0)
    {:ok, %{config: config}}
  end

  describe "start_link/1" do
    test "starts successfully with valid config", %{config: config} do
      server_pid = self()
      listener_id = "test-listener"

      assert {:ok, pid} = Listener.start_link({listener_id, server_pid, config})
      assert Process.alive?(pid)
      Listener.stop(pid)
    end

    test "returns port info via listener_info", %{config: config} do
      server_pid = self()
      listener_id = "test-listener"

      assert {:ok, pid} = Listener.start_link({listener_id, server_pid, config})
      {:ok, {ip, port}} = Listener.listener_info_cached(pid)

      assert is_tuple(ip) or is_atom(ip)
      assert is_integer(port) and port > 0

      Listener.stop(pid)
    end
  end

  describe "listener_info/1" do
    test "returns socket information", %{config: config} do
      server_pid = self()
      listener_id = "test-listener"

      assert {:ok, pid} = Listener.start_link({listener_id, server_pid, config})
      {:ok, info} = Listener.listener_info_cached(pid)

      assert is_tuple(info)
      assert tuple_size(info) == 2

      Listener.stop(pid)
    end
  end

  describe "socket_info/1" do
    test "returns socket and telemetry info", %{config: config} do
      server_pid = self()
      listener_id = "test-listener"

      assert {:ok, pid} = Listener.start_link({listener_id, server_pid, config})
      {socket, telemetry} = Listener.socket_info(pid)

      assert is_port(socket) or is_tuple(socket)
      assert is_reference(telemetry) or is_map(telemetry)

      Listener.stop(pid)
    end
  end

  describe "broadcast mode" do
    test "configures broadcast socket options", %{config: config} do
      server_pid = self()
      listener_id = "test-listener"
      config = %{config | broadcast: true}

      assert {:ok, pid} = Listener.start_link({listener_id, server_pid, config})
      {:ok, {ip, port}} = Listener.listener_info_cached(pid)

      assert is_tuple(ip) or is_atom(ip)
      assert is_integer(port) and port > 0

      Listener.stop(pid)
    end
  end

  describe "error handling" do
    test "configuration rejects an invalid port before opening a socket" do
      assert_raise ArgumentError, ~r/port must be/, fn ->
        ServerConfig.new(handler_module: Abyss.TestHandler, port: -1)
      end
    end
  end
end
