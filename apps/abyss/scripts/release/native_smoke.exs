{:ok, _} = Application.ensure_all_started(:abyss)
{:ok, _} = Application.ensure_all_started(:abyss_raw)
expected = System.fetch_env!("ABYSS_EXPECTED_VERSION")
raw_expected = System.fetch_env!("ABYSS_RAW_EXPECTED_VERSION")
^expected = Application.spec(:abyss, :vsn) |> to_string()
^raw_expected = Application.spec(:abyss_raw, :vsn) |> to_string()
true = Code.ensure_loaded?(AbyssDhcpSocket.Native)
{:error, "invalid interface name: " <> _} = Abyss.DhcpSocket.Native.open("bad" <> <<0>>, self())
{:error, reason} = Abyss.DhcpSocket.Native.open("abyss-no-iface", self())
true = is_binary(reason)

for {function, arguments} <- [
      {:send_broadcast, [make_ref(), <<1>>]},
      {:send_unicast, [make_ref(), {127, 0, 0, 1}, <<1>>]},
      {:send_arp_probe, [make_ref(), {127, 0, 0, 1}]},
      {:close, [make_ref()]}
    ] do
  try do
    apply(Abyss.DhcpSocket.Native, function, arguments)
    raise "invalid native resource unexpectedly accepted"
  rescue
    ArgumentError -> :ok
  end
end

priv = :code.priv_dir(:abyss_raw) |> to_string()
true = File.dir?(priv)
true = Enum.any?(Path.wildcard(Path.join(priv, "native/*")), &File.regular?/1)

true =
  String.starts_with?(
    :code.which(AbyssDhcpSocket.Native) |> to_string(),
    :code.lib_dir(:abyss_raw) |> to_string()
  )

defmodule RawReleaseEcho do
  @behaviour Abyss.DatagramHandler
  def init(_, context), do: {:ok, context}
  def handle_datagram(datagram, state), do: {:ok, state, [{:reply, datagram.payload}]}
end

{:ok, endpoint} =
  Abyss.Endpoint.start_link(
    datagram_handler: RawReleaseEcho,
    port: 0,
    transport_options: [ip: {127, 0, 0, 1}]
  )

{:ok, {{127, 0, 0, 1}, port}} = Abyss.Endpoint.local_endpoint(endpoint)
{:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
:ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "raw-release-udp")
{:ok, {{127, 0, 0, 1}, ^port, "raw-release-udp"}} = :gen_udp.recv(peer, 0, 2000)
:gen_udp.close(peer)
:ok = Abyss.Endpoint.stop(endpoint, 1000)
IO.puts("ABYSS_RAW_COMPATIBILITY_PASS core=#{expected} raw=#{raw_expected} priv=#{priv}")
