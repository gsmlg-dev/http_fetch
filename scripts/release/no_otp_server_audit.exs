# Fails when the server packages (abyss, hell) import OTP `:ssl`.
# Usage (umbrella root, after `MIX_ENV=prod mix compile`):
#   elixir scripts/release/no_otp_server_audit.exs _build/prod/lib
Code.require_file("no_otp_release_audit.exs", __DIR__)

[lib_dir] = System.argv()

case NoOTP.ReleaseAudit.server_ssl_imports(lib_dir) do
  [] ->
    IO.puts("server packages (abyss, hell): zero OTP :ssl imports")

  imports ->
    Enum.each(imports, &IO.puts(:stderr, "OTP :ssl import: #{inspect(&1)}"))
    System.halt(1)
end
