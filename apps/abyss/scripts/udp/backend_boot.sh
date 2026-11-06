#!/usr/bin/env bash
set -euo pipefail
ERL_FLAGS='' mix run scripts/udp/backend_boot.exs inet omitted
ERL_FLAGS='-kernel inet_backend inet' mix run scripts/udp/backend_boot.exs inet omitted
ERL_FLAGS='-kernel inet_backend socket' mix run scripts/udp/backend_boot.exs socket omitted
ERL_FLAGS='-kernel inet_backend socket' mix run scripts/udp/backend_boot.exs inet inet
ERL_FLAGS='-kernel inet_backend inet' mix run scripts/udp/backend_boot.exs socket socket
