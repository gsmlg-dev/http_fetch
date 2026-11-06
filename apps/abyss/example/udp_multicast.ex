defmodule UDPDatagramResponder do
  @moduledoc """
  Protocol-neutral one-shot responder. Use caller-selected test groups and
  interfaces; the example does not emit application-protocol traffic.
  """
  use Abyss.Handler

  @impl true
  def handle_data({peer, port, payload}, state) do
    case Abyss.Transport.UDP.send(state.socket, peer, port, payload) do
      :ok -> {:close, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  @doc "Starts one IPv4 group endpoint. Membership and outgoing interface are explicit."
  def start_ipv4(group, interface_address, port) do
    Abyss.start_link(
      handler_module: __MODULE__,
      port: port,
      transport_module: Abyss.Transport.UDP.Multicast,
      transport_options: [
        add_membership: {group, interface_address},
        multicast_if: interface_address,
        multicast_ttl: 1,
        multicast_loop: true
      ]
    )
  end
end
