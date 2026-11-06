defmodule Abyss.Integration.ClientTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias Abyss.Client

  defmodule Echo do
    use Abyss.Handler
    @impl true
    def handle_data({ip, port, data}, state) do
      :ok = state.server_config.transport_module.send(state.socket, ip, port, data)
      {:close, state}
    end
  end

  test "client exchanges distinct and empty datagrams through a real Abyss endpoint" do
    {:ok, server} = Abyss.start_link(handler_module: Echo, port: 0, num_listeners: 1)

    try do
      [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
      {_, port} = Abyss.Listener.listener_info(listener)

      for packet <- ["client-1", "", "client-2", :binary.copy("x", 8192)] do
        assert {:ok, ^packet} = Client.send_recv({127, 0, 0, 1}, port, packet, 1000)
      end
    after
      Abyss.stop(server)
    end
  end

  test "client multicast queries reach Abyss and collect original-port replies" do
    group = {239, 255, 42, 31}

    {:ok, server} =
      Abyss.start_link(
        handler_module: Echo,
        port: 0,
        transport_module: Abyss.Transport.UDP.Multicast,
        transport_options: [add_membership: {group, {127, 0, 0, 1}}]
      )

    try do
      [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
      {_, port} = Abyss.Listener.listener_info(listener)

      assert {:ok, [{{127, 0, 0, 1}, ^port, "query"}]} =
               Client.multicast_query(group, port, "query", 50,
                 source: {127, 0, 0, 1},
                 loopback: true
               )
    after
      Abyss.stop(server)
    end
  end
end
