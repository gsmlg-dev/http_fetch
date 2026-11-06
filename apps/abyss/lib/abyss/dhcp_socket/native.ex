defmodule Abyss.DhcpSocket.Native do
  @moduledoc """
  Compatibility facade for the optional `abyss_raw` package.

  Install the optional package explicitly to use this feature. Provides a
  broadcast-capable UDP socket bound to the interface (`SO_BINDTODEVICE` on
  Linux, `IP_BOUND_IF` on FreeBSD) and raw ARP socket support for Duplicate
  Address Detection (RFC 5227).

  ## Owner messages

  A background poll thread delivers messages to the `owner` pid passed to
  `open/2`:

  - `{:dhcp_rx, binary}` - received DHCP packet (raw UDP payload)
  - `{:arp_rx, binary}` - received ARP frame (full Ethernet frame)
  - `{:dhcp_socket_down, :poll_error | :recv_error | :socket_error}` - the
    poll thread exited abnormally; the socket no longer receives packets and
    the owner should `close/1` it and open a new one
  - `{:arp_socket_down, :recv_error | :socket_error}` - the ARP socket
    failed; DAD probes are unavailable but DHCP reception continues

  No message is sent when the thread exits due to `close/1` or because the
  owner process died.
  """

  @implementation AbyssDhcpSocket.Native

  @spec open(String.t(), pid()) :: reference() | {:error, term()}
  def open(interface, owner), do: invoke(:open, [interface, owner])

  @spec send_broadcast(reference(), iodata()) :: :ok | {:error, term()}
  def send_broadcast(socket, packet), do: invoke(:send_broadcast, [socket, packet])

  @spec send_unicast(reference(), :inet.ip4_address(), iodata()) :: :ok | {:error, term()}
  def send_unicast(socket, dest_ip, packet), do: invoke(:send_unicast, [socket, dest_ip, packet])

  @spec send_arp_probe(reference(), :inet.ip4_address()) :: :ok | {:error, term()}
  def send_arp_probe(socket, target_ip), do: invoke(:send_arp_probe, [socket, target_ip])

  @spec close(reference()) :: :ok | {:error, term()}
  def close(socket), do: invoke(:close, [socket])

  defp invoke(function, arguments) do
    case Code.ensure_loaded(@implementation) do
      {:module, @implementation} -> apply(@implementation, function, arguments)
      {:error, :nofile} -> {:error, {:missing_optional_dependency, :abyss_raw}}
      {:error, reason} -> {:error, {:optional_dependency_load_failed, :abyss_raw, reason}}
    end
  end
end
