defmodule Hell.UpgradeRegressionTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  defmodule UpgradeHandler do
    use Hell.Handler

    @tls_options [
      certfile: Path.expand("../support/cert.pem", __DIR__),
      keyfile: Path.expand("../support/key.pem", __DIR__)
    ]

    def handle_connection(socket, {parent, timeout}) do
      send(parent, {:connection, self()})
      :ok = Hell.Socket.send(socket, "READY")
      upgrade = {:switch_transport, {Hell.Transports.SSL, tls_options()}, {parent, timeout}}

      case timeout do
        :default -> upgrade
        timeout -> Tuple.insert_at(upgrade, 3, timeout)
      end
    end

    def handle_data(data, socket, state) do
      :ok = Hell.Socket.send(socket, data)
      {:continue, state}
    end

    def handle_timeout(_socket, {parent, _timeout}), do: send(parent, :network_timeout)
    def handle_error(error, _socket, {parent, _timeout}), do: send(parent, {:error, error})

    def handle_info(:timeout, state) do
      send(elem(elem(state, 1), 0), :unexpected_genserver_timeout)
      {:noreply, state}
    end

    def handle_continue(:upgraded, {socket, {parent, _timeout}} = state) do
      send(parent, {:upgraded, socket.transport_module})
      {:noreply, state}
    end

    defp tls_options, do: @tls_options
  end

  defmodule LegacyUpgrade do
    def upgrade(raw_socket, options), do: {:ok, {raw_socket, options}}
  end

  defmodule TimedUpgrade do
    def upgrade(_raw_socket, _options), do: {:error, :legacy_callback_called}
    def upgrade(raw_socket, options, timeout), do: {:ok, {raw_socket, options, timeout}}
  end

  test "a stalled TCP to TLS upgrade obeys handshake_timeout" do
    {server, client, handler} = start_upgrade(:default, handshake_timeout: 50)
    monitor = Process.monitor(handler)

    assert :gen_tcp.recv(client, 0, 2_000) == {:error, :closed}
    assert_receive {:error, :timeout}
    assert_receive {:DOWN, ^monitor, :process, ^handler, {:shutdown, {:upgrade, :timeout}}}
    assert {:ok, %{active_connections: 0}} = Hell.info(server)
  end

  test "handshake_timeout infinity allows a delayed upgrade to finish" do
    {_server, client, handler} = start_upgrade(:default, handshake_timeout: :infinity)
    assert :gen_tcp.recv(client, 0, 100) == {:error, :timeout}
    assert Process.alive?(handler)
    tls = finish_upgrade(client)
    assert :ok = :ssl.send(tls, "echo")
    assert :ssl.recv(tls, 0, 1_000) == {:ok, "echo"}
  end

  test "a shorter one-shot upgrade timeout uses the network timer" do
    {_server, client, _handler} = start_upgrade(50, read_timeout: 5_000)
    tls = finish_upgrade(client)
    assert :ssl.recv(tls, 0, 1_000) == {:error, :closed}
    assert_receive :network_timeout
    refute_received :unexpected_genserver_timeout
  end

  test "a longer one-shot upgrade timeout replaces the default deadline" do
    {_server, client, _handler} = start_upgrade(1_000, read_timeout: 50)
    tls = finish_upgrade(client)
    assert :ssl.recv(tls, 0, 200) == {:error, :timeout}
    assert :ssl.recv(tls, 0, 2_000) == {:error, :closed}
    assert_receive :network_timeout
    refute_received :unexpected_genserver_timeout
  end

  test "an infinite one-shot upgrade timeout disables the default deadline" do
    {_server, client, _handler} = start_upgrade(:infinity, read_timeout: 50)
    tls = finish_upgrade(client)
    assert :ssl.recv(tls, 0, 200) == {:error, :timeout}
    assert :ok = :ssl.send(tls, "echo")
    assert :ssl.recv(tls, 0, 1_000) == {:ok, "echo"}
    # The next ordinary continuation restores the configured read timeout.
    assert :ssl.recv(tls, 0, 1_000) == {:error, :closed}
    assert_receive :network_timeout
  end

  test "a persistent upgrade timeout carries over to later client data" do
    {_server, client, _handler} = start_upgrade({:persistent, 1_000}, read_timeout: 50)
    tls = finish_upgrade(client)
    assert :ok = :ssl.send(tls, "echo")
    assert :ssl.recv(tls, 0, 1_000) == {:ok, "echo"}
    assert :ssl.recv(tls, 0, 200) == {:error, :timeout}
    assert :ssl.recv(tls, 0, 2_000) == {:error, :closed}
    assert_receive :network_timeout
  end

  test "an upgrade continuation still invokes handle_continue" do
    {_server, client, _handler} = start_upgrade({:continue, :upgraded})
    tls = finish_upgrade(client)
    assert_receive {:upgraded, Hell.Transports.SSL}
    assert :ok = :ssl.send(tls, "echo")
    assert :ssl.recv(tls, 0, 1_000) == {:ok, "echo"}
  end

  test "custom transports implementing only upgrade/2 remain supported" do
    socket = socket_config(123)
    assert {:ok, upgraded} = Hell.Socket.upgrade(socket, LegacyUpgrade, [:legacy])
    assert upgraded.socket == {:raw_socket, [:legacy]}
    assert upgraded.transport_module == LegacyUpgrade
  end

  test "custom timeout-aware upgrades receive the configured timeout" do
    socket = socket_config(123)
    assert {:ok, upgraded} = Hell.Socket.upgrade(socket, TimedUpgrade, [:timed])
    assert upgraded.socket == {:raw_socket, [:timed], 123}
    assert upgraded.transport_module == TimedUpgrade
  end

  defp start_upgrade(timeout, options \\ []) do
    server =
      start_supervised!(
        {Hell,
         Keyword.merge(
           [
             port: 0,
             num_acceptors: 1,
             handler_module: UpgradeHandler,
             handler_options: {self(), timeout}
           ],
           options
         )}
      )

    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, [:binary, active: false], 1_000)
    on_exit(fn -> :gen_tcp.close(client) end)
    assert :gen_tcp.recv(client, 0, 1_000) == {:ok, "READY"}
    assert_receive {:connection, handler}
    {server, client, handler}
  end

  defp finish_upgrade(client) do
    {:ok, tls} = :ssl.connect(client, [mode: :binary, active: false, verify: :verify_none], 2_000)
    on_exit(fn -> :ssl.close(tls) end)
    tls
  end

  defp socket_config(timeout) do
    config = Hell.ServerConfig.new(handler_module: UpgradeHandler, handshake_timeout: timeout)
    span = Hell.Telemetry.start_span(:listener, %{}, %{handler: UpgradeHandler})
    Hell.Socket.new(:raw_socket, Hell.HandlerConfig.from_server_config(config), span)
  end
end
