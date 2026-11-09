# Fails when the server packages (abyss, hell) import any OTP TLS module:
# `ssl`, or any `ssl_*`, `tls_*` or `dtls_*` module (a static import check).
# Usage (umbrella root, after `MIX_ENV=prod mix compile`):
#   elixir scripts/release/no_otp_server_audit.exs _build/prod/lib
Code.require_file("no_otp_release_audit.exs", __DIR__)

[lib_dir] = System.argv()

# An absent package would otherwise pass vacuously.
for app <- ~w(abyss hell),
    Path.wildcard(Path.join([lib_dir, "#{app}{,-*}", "ebin", "*.beam"])) == [] do
  IO.puts(:stderr, "no compiled #{app} BEAMs under #{lib_dir}")
  System.halt(1)
end

case NoOTP.ReleaseAudit.server_ssl_imports(lib_dir) do
  [] ->
    IO.puts("server packages (abyss, hell): zero OTP ssl/ssl_*/tls_*/dtls_* imports")

  imports ->
    Enum.each(imports, &IO.puts(:stderr, "OTP TLS module import: #{inspect(&1)}"))
    System.halt(1)
end
