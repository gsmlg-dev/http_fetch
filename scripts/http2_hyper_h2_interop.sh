#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python_bin=${PYTHON_BIN:-python3}
port_file=$(mktemp)
server_log=$(mktemp)

if ! "$python_bin" -c 'import h2; assert h2.__version__ == "4.2.0"' >/dev/null 2>&1; then
  echo "hyper-h2 4.2.0 is required; install scripts/requirements-http2-interop.txt" >&2
  exit 2
fi

"$python_bin" "$repo_root/scripts/http2_hyper_h2_server.py" \
  --port 0 --port-file "$port_file" >"$server_log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  if test -s "$port_file"; then
    break
  fi
  sleep 0.05
done

if ! test -s "$port_file"; then
  cat "$server_log" >&2
  exit 1
fi

port=$(cat "$port_file")
result=$(cd "$repo_root" && MIX_ENV=test mix run -e '
  response =
    HTTP.fetch("http://127.0.0.1:'"$port"'/independent", http_version: :h2c, http2_profile: :native_v1)
    |> HTTP.Promise.await()

  IO.puts("#{response.status}|#{HTTP.Headers.get(response.headers, "x-peer")}|#{HTTP.Response.read_all(response)}")
')

wait "$server_pid"
printf '%s\n' "$result"
cat "$server_log"
