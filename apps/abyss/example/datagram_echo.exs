# Run: mix run example/datagram_echo.exs
# Application callbacks need neither raw sockets nor telemetry internals.
defmodule DatagramEcho do
  @behaviour Abyss.DatagramHandler
  def init(_options, _context), do: {:ok, 0}
  def handle_datagram(datagram, count), do: {:ok, count + 1, [{:reply, datagram.payload}]}
end

{:ok, endpoint} =
  Abyss.Endpoint.start_link(
    datagram_handler: DatagramEcho,
    execution: :endpoint,
    port: 0,
    transport_options: [ip: {127, 0, 0, 1}]
  )

{:ok, {_, port}} = Abyss.Endpoint.local_endpoint(endpoint)
{:ok, peer} = :gen_udp.open(0, [:binary, active: false])

try do
  for payload <- ["hello", <<>>] do
    :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, payload)
    {:ok, {{127, 0, 0, 1}, ^port, ^payload}} = :gen_udp.recv(peer, 0, 1000)
  end

  IO.puts("DATAGRAM_EXAMPLE_PASS")
after
  :gen_udp.close(peer)
  Abyss.Endpoint.stop(endpoint, 1000)
end
