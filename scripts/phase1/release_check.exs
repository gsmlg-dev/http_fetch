{:ok, dependencies} = :application.get_key(:elixir_quic, :applications)
unless :ex_ssl in dependencies, do: raise("ex_ssl missing from runtime dependencies")
running = Enum.map(Application.started_applications(), &elem(&1, 0))
unless :ex_ssl in running and :public_key in running, do: raise("runtime dependency not started")
if :ssl in running, do: raise("OTP ssl must not be the implementation")
unless Code.ensure_loaded?(SSL.QUIC), do: raise("SSL.QUIC missing from release")

IO.inspect(%{runtime_dependency: :ex_ssl, quic_provider: SSL.QUIC.capabilities()},
  label: "RELEASE_PASS"
)
