#!/usr/bin/env bash
set -euo pipefail

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$1" >&2
    exit 1
  fi
}

require_command elixir
require_command erl
require_command openssl
require_command python3

printf 'OS:\n'
uname -a
if [ -r /etc/os-release ]; then
  sed -n 's/^PRETTY_NAME=/OS release: /p' /etc/os-release
fi

printf '\nElixir and OTP:\n'
elixir --version
elixir -e '
  version = Path.join([to_string(:code.root_dir()), "releases",
    to_string(:erlang.system_info(:otp_release)), "OTP_VERSION"])
  IO.puts("OTP exact version: #{String.trim(File.read!(version))}")
  IO.puts("ERTS exact version: #{:erlang.system_info(:version)}")
  IO.inspect(:crypto.info_lib(), label: "OTP crypto provider")
'

printf '\nOpenSSL CLI:\n'
openssl version -a
cli_ciphers=$(openssl ciphers -v 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384')
printf '%s\n' "$cli_ciphers"

for cipher in \
  ECDHE-RSA-AES128-GCM-SHA256 \
  ECDHE-RSA-AES256-GCM-SHA384 \
  ECDHE-ECDSA-AES128-GCM-SHA256 \
  ECDHE-ECDSA-AES256-GCM-SHA384; do
  if ! grep -q "^${cipher}[[:space:]]" <<<"$cli_ciphers"; then
    printf 'OpenSSL CLI lacks required TLS 1.2 cipher: %s\n' "$cipher" >&2
    exit 1
  fi
done

for curve in prime256v1 secp384r1; do
  if ! openssl ecparam -list_curves | grep -Eq "^[[:space:]]*${curve}[[:space:]]*:"; then
    printf 'OpenSSL CLI lacks required curve: %s\n' "$curve" >&2
    exit 1
  fi
done

if ! openssl list -public-key-algorithms | grep -q 'X25519'; then
  printf 'OpenSSL CLI lacks required X25519 support\n' >&2
  exit 1
fi

printf '\nPython ssl/OpenSSL:\n'
python3 - <<'PYTHON'
import ssl
import sys

print(sys.version)
print("Python ssl/OpenSSL:", ssl.OPENSSL_VERSION)
if not hasattr(ssl.TLSVersion, "TLSv1_2") or not hasattr(ssl.TLSVersion, "TLSv1_3"):
    raise SystemExit("Python ssl lacks TLS 1.2 or TLS 1.3")
if not ssl.HAS_TLSv1_3 or not ssl.HAS_ALPN:
    raise SystemExit("Python ssl lacks TLS 1.3 or ALPN")

for cipher in (
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(cipher)
    if cipher not in {item["name"] for item in context.get_ciphers()}:
        raise SystemExit(f"Python ssl lacks required TLS 1.2 cipher: {cipher}")

for curve in ("prime256v1", "secp384r1"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_ecdh_curve(curve)

print("Python TLS 1.2/1.3, ALPN, ECDHE/AES-GCM, and P-256/P-384 peer capability: available")
PYTHON
