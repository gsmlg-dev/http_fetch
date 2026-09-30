#!/usr/bin/env bash
set -euo pipefail
# ExDoc is a development dependency; the acceptance runner isolates its dev build.
test "${MIX_ENV:-}" = dev
mix deps.get --check-locked
mix docs
