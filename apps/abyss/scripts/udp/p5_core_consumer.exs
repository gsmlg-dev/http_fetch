defmodule P5CoreEcho do
  @behaviour Abyss.DatagramHandler
  def init(_, context), do: {:ok, context}
  def handle_datagram(datagram, state), do: {:ok, state, [{:reply, datagram.payload}]}
end

if expected = System.get_env("ABYSS_EXPECTED_VERSION") do
  ^expected = Application.spec(:abyss, :vsn) |> to_string()
end

for executable <- ["cargo", "rustc", "rustup"] do
  nil = System.find_executable(executable)
end

false = Code.ensure_loaded?(AbyssDhcpSocket.Native)
false = Code.ensure_loaded?(Rustler)
false = Code.ensure_loaded?(ElixirQuic)

false =
  Enum.any?(Map.keys(Mix.Project.deps_paths()), fn app ->
    app in [:rustler, :abyss_raw, :abyss_dhcp_socket, :elixir_quic, :ex_ssl]
  end)

false =
  Enum.any?(Application.loaded_applications(), fn {app, _, _} ->
    app in [:rustler, :abyss_raw, :abyss_dhcp_socket, :elixir_quic, :ex_ssl]
  end)

for {function, arguments} <- [
      {:open, ["lo", self()]},
      {:send_broadcast, [make_ref(), <<>>]},
      {:send_unicast, [make_ref(), {127, 0, 0, 1}, <<>>]},
      {:send_arp_probe, [make_ref(), {127, 0, 0, 1}]},
      {:close, [make_ref()]}
    ] do
  {:error, {:missing_optional_dependency, :abyss_raw}} =
    apply(Abyss.DhcpSocket.Native, function, arguments)
end

{:ok, endpoint} =
  Abyss.Endpoint.start_link(
    datagram_handler: P5CoreEcho,
    port: 0,
    transport_options: [ip: {127, 0, 0, 1}]
  )

{:ok, {{127, 0, 0, 1}, port}} = Abyss.Endpoint.local_endpoint(endpoint)
{:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
:ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, "packaged-core-udp")
{:ok, {{127, 0, 0, 1}, ^port, "packaged-core-udp"}} = :gen_udp.recv(peer, 0, 2000)
:gen_udp.close(peer)
:ok = Abyss.Endpoint.stop(endpoint, 1000)
false = Code.ensure_loaded?(AbyssDhcpSocket.Native)
IO.puts("P5_CORE_NO_RUST_UDP_PASS")
