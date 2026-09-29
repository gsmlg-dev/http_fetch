alias HTTP.QUIC.ExQuic, as: Adapter
running = Enum.map(Application.started_applications(), &elem(&1, 0))

for app <- [:http_core, :elixir_quic, :ex_ssl, :crypto, :public_key, :ssl] do
  unless app in running, do: raise("runtime application missing: #{app}")
end

for app <- [:elixir_quic, :ex_ssl] do
  unless app in Application.spec(:http_core, :applications), do: raise("http_core missing #{app}")
end

unless :ex_ssl in Application.spec(:elixir_quic, :applications),
  do: raise("elixir_quic missing ex_ssl")

false = :quic in running
false = :quic_h3 in running
true = Code.ensure_loaded?(SSL.QUIC)
%{http3: false, delivery: :pull, max_write_bytes: 16_384} = Adapter.capabilities()
# Normal startup, public endpoint creation and actual UDP binding in both the
# standalone consumer VM and the running release. Network exchange has its own gate.
{:ok, endpoint} =
  Adapter.client("localhost", cacerts: :public_key.cacerts_get(), alpn: ["ex-quic-phase1"])

{_ip, port} = Adapter.local(endpoint)
true = port > 0
monitor = Process.monitor(endpoint)
:ok = Adapter.stop_endpoint(endpoint)

receive do
  {:DOWN, ^monitor, :process, ^endpoint, :normal} -> :ok
after
  5_000 -> raise("endpoint leaked")
end

IO.inspect(
  %{
    ex_ssl: Application.spec(:ex_ssl, :vsn),
    elixir_quic: Application.spec(:elixir_quic, :vsn),
    ssl_module: :code.which(SSL.QUIC),
    quic_module: :code.which(Quic)
  },
  label: "PHASE1_STARTUP_PASS"
)
