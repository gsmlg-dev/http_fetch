# Run only on an isolated test interface. No destination or interface is guessed.
# mix run example/udp_one_to_many.exs receive 239.255.42.1 test0 49002
# mix run example/udp_one_to_many.exs query 239.255.42.1 test0 49002 probe
# mix run example/udp_one_to_many.exs receive ff02::42 test0 49003
# mix run example/udp_one_to_many.exs query ff02::42 test0 49003 probe
# mix run example/udp_one_to_many.exs receive 255.255.255.255 test0 49001
# mix run example/udp_one_to_many.exs query 255.255.255.255 test0 49001 probe

defmodule OneToManyEcho do
  use Abyss.Handler

  @impl true
  def handle_data({address, port, data}, state) do
    destination =
      if tuple_size(address) == 8,
        do: %{
          family: :inet6,
          addr: address,
          port: port,
          scope_id: Keyword.fetch!(state.server_config.handler_options, :scope_id)
        },
        else: {address, port}

    :ok = state.server_config.transport_module.send(state.socket, destination, data)
    IO.inspect({address, port, data}, label: "received")
    {:close, state}
  end
end

defmodule OneToManyExample do
  alias Abyss.Transport.UDP.Multicast

  def run([mode, destination, interface, port | payload]) do
    {:ok, address} = :inet.parse_address(String.to_charlist(destination))
    family = Multicast.family(address)
    {:ok, selector} = Multicast.resolve_interface(interface, family)
    port = String.to_integer(port)
    multicast = Multicast.multicast_address?(address)

    case mode do
      "receive" ->
        memberships = if multicast, do: [add_membership: {address, selector}], else: []
        options = [family, {:multicast_if, selector} | memberships]

        {:ok, server} =
          Abyss.start_link(
            handler_module: OneToManyEcho,
            port: port,
            broadcast: not multicast,
            handler_options: [scope_id: selector],
            num_connections: 32,
            transport_module: Multicast,
            transport_options: options
          )

        IO.inspect(Abyss.memberships(server), label: "ready memberships")
        Process.sleep(:infinity)

      "query" ->
        packet = Enum.join(payload, " ")
        options = [interface: interface, max_responses: 32, max_response_bytes: 65_536]

        result =
          if multicast,
            do: Abyss.Client.multicast_query(address, port, packet, 500, options),
            else: Abyss.Client.broadcast_send_recv(address, port, packet, 500, options)

        IO.inspect(result, label: "query result")
    end
  end

  def run(_),
    do:
      IO.puts(
        "Usage: mix run example/udp_one_to_many.exs receive|query ADDRESS INTERFACE PORT [PAYLOAD]"
      )
end

OneToManyExample.run(System.argv())
