defmodule Abyss.RuntimeSmoke do
  @behaviour Abyss.DatagramHandler
  def init(_options, context), do: {:ok, context}

  def handle_datagram(datagram, context) do
    IO.inspect(Map.take(datagram, [:destination, :interface_index, :local_address, :hop_limit]),
      label: "ACTUAL_METADATA"
    )

    {:ok, context, [{:reply, datagram.payload, :strict}]}
  end
end

for family <- [:inet, :inet6] do
  ip = if family == :inet, do: {127, 0, 0, 1}, else: {0, 0, 0, 0, 0, 0, 0, 1}

  {:ok, endpoint} =
    Abyss.Endpoint.start_link(
      datagram_handler: Abyss.RuntimeSmoke,
      io_backend: :socket_native,
      port: 0,
      transport_options: [{:ip, ip}, family]
    )

  {:ok, {^ip, port}} = Abyss.Endpoint.local_endpoint(endpoint)
  {:ok, peer} = :gen_udp.open(0, [:binary, family, active: false, ip: ip])
  :ok = :gen_udp.send(peer, ip, port, "native-live")
  {:ok, {^ip, ^port, "native-live"}} = :gen_udp.recv(peer, 0, 1000)
  :gen_udp.close(peer)
  :ok = Abyss.Endpoint.stop(endpoint, 100)
end

IO.puts("NATIVE_ENDPOINT_IPV4_IPV6_STRICT_REPLY_PASS")
