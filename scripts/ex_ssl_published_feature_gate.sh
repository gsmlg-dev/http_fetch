#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec env EX_SSL_DEP_MODE=published "$repo_root/scripts/ex_ssl_source_smoke.sh" "$@"
