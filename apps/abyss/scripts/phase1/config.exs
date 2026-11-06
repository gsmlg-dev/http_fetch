Process.flag(:trap_exit, true)
true = Code.ensure_loaded?(Quic)
true = Code.ensure_loaded?(AbyssEchoExample.Handler)

for tls <- [[], [cert: nil, key: nil], [cert: ["bad"], key: {:ECPrivateKey, "bad"}]] do
  case Abyss.QUIC.start_link(handler: AbyssEchoExample.Handler, alpn: ["test"], tls: tls) do
    {:error, :missing_server_credentials} when tls == [] ->
      :ok

    {:error, {:invalid_tls, %{kind: :configuration}}} ->
      :ok

    {:ok, listener} ->
      Abyss.QUIC.stop(listener)
      raise "invalid TLS accepted at startup"
  end
end

IO.puts("INVALID_TLS_STARTUP_PASS")
