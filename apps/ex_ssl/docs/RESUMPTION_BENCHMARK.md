# Local TLS 1.3 resumption measurements

Command (repository root):

```sh
MIX_ENV=test mix run scripts/resumption_benchmark.exs
```

Executed 2026-09-22 with Elixir 1.18.5, OTP 28 / ERTS 16.4.0.5,
OpenSSL 3.6.3 on this Linux workstation. Each backend/mode uses a fresh local
OpenSSL server context, the same generated CA/server certificate, verified
`exssl.test` identity, TLS_AES_128_GCM_SHA256, X25519, RSA-PSS-RSAE-SHA256,
ALPN http/1.1, passive binary mode and explicit TCP nodelay. Each sample opens
a fresh TCP/TLS connection. One warmup precedes five measured connections.
Transfer time includes sending 1 MiB and receiving its exact echoed payload.
It excludes handshake time and the out-of-band peer metadata read.

| Backend / mode | Handshake median (range), microseconds | Transfer median (range), microseconds |
| --- | --- | --- |
| OTP / full | 2874 (2720–3504) | 6480 (5451–7020) |
| OTP / resumed | 1568 (1427–1963) | 5961 (5354–6601) |
| ex_ssl / full | 2921 (2670–3303) | 6987 (5962–7418) |
| ex_ssl / resumed | 2658 (2202–5926) | 7470 (6821–8246) |

OpenSSL reported `[false, false, false, false, false, false]` for both full
modes and `[false, true, true, true, true, true]` for both resumed modes.
The script checks protocol, cipher, ALPN, resumption and every echoed byte;
it does not infer resumption from latency. ex_ssl revalidates its cached
certificate chain on each connection. This small local sample shows no transfer
speed benefit from resumption and is not a throughput or production-latency claim.
CPU scheduling, cache warmup, loopback and a single cipher/peer limit comparison.
No performance-based default change is proposed.

The initial script runs failed on a malformed bitstring assertion and OTP's
active/list defaults; those produced no valid measurements. A preliminary run
without explicit TCP nodelay showed roughly 48 ms median ex_ssl transfer times.
The recorded final configuration pins TCP nodelay for both backends; it does not
change either library's defaults. Output was captured in
`/tmp/ex-ssl-resumption-benchmark-final.log` during this execution.
