defmodule Hell.ConfigTest do
  use ExUnit.Case, async: true
  use Machete

  alias Hell.ServerConfig

  describe "server_config exceptions" do
    test "raises exception when handler_module is nil" do
      assert_raise ArgumentError, ~r/No handler_module/, fn ->
        ServerConfig.new(port: 4000, handler_module: nil)
      end
    end

    test "raises exception when num_listen_sockets > num_acceptors" do
      assert_raise ArgumentError, ~r/num_listen_sockets/, fn ->
        ServerConfig.new(
          port: 4000,
          handler_module: __MODULE__,
          num_listen_sockets: 5,
          num_acceptors: 3
        )
      end
    end

    test "raises ArgumentError when num_listen_sockets > 1 without reuseport options" do
      assert_raise ArgumentError, fn ->
        ServerConfig.new(
          port: 4000,
          handler_module: __MODULE__,
          num_listen_sockets: 2,
          transport_options: []
        )
      end
    end

    test "raises ArgumentError for an unknown option" do
      assert_raise ArgumentError, ~r/unknown Hell option.*:prot/, fn ->
        ServerConfig.new(handler_module: __MODULE__, prot: 1)
      end
    end

    test "start_link and child_spec start paths reject invalid options with ArgumentError" do
      assert_raise ArgumentError, fn -> Hell.start_link(handler_module: __MODULE__, bogus: 1) end
    end

    test "num_listen_sockets defaults to 1" do
      config = ServerConfig.new(handler_module: __MODULE__)
      assert config.num_listen_sockets == 1
    end

    test "handshake_timeout defaults to 5000 and accepts :infinity" do
      config = ServerConfig.new(handler_module: __MODULE__)
      assert config.handshake_timeout == 5_000

      config = ServerConfig.new(handler_module: __MODULE__, handshake_timeout: :infinity)
      assert config.handshake_timeout == :infinity
    end

    test "allows num_listen_sockets less than num_acceptors" do
      config =
        ServerConfig.new(
          handler_module: __MODULE__,
          num_listen_sockets: 3,
          num_acceptors: 10,
          transport_options: [reuseport: true]
        )

      assert config.num_listen_sockets == 3
      assert config.num_acceptors == 10
    end

    test "allows num_listen_sockets equal to num_acceptors" do
      config =
        ServerConfig.new(
          handler_module: __MODULE__,
          num_listen_sockets: 5,
          num_acceptors: 5,
          transport_options: [reuseport: true]
        )

      assert config.num_listen_sockets == 5
      assert config.num_acceptors == 5
    end
  end
end
