# Caddy JA3/JA4 end-to-end test

This isolated Mix project uses the public `SSL.connect/send/recv/close` API to
complete an authenticated TLS 1.3 handshake, send an HTTP/1.1 request, and check
the exact JA3 and JA4 values observed by Caddy's pinned listener plugins. Its
helper only supplies the WireProfile and parses the small test HTTP response;
it contains no independent TLS implementation.

The Caddy image build and live end-to-end test run only in the CI
`.github/workflows/e2e.yml` and `.github/workflows/release.yml` workflows.
Do not build or start the Caddy fixture locally.

Local checks are limited to formatting and compiling the isolated harness:

```sh
cd e2e
mix deps.get
mix format --check-formatted
mix compile --warnings-as-errors
```

The certificate authority and server key are disposable test fixtures for
`localhost` and `127.0.0.1`. They must never be used outside this test.

The assertions are fixed independently of the plugin response. The profile's
JA3 source string is
`771,4865-4866,0-10-11-13-16-43-51,29,0`. Its JA4 hash inputs are
`1301,1302` and `000a,000b,000d,002b,0033_0403`. They produce:

```text
JA3 af851f784aed02a8b1e0b6ac13251239
JA4 t13d0207h1_62ed6f6ca7ad_032b58638d3d
```

Pinned server dependencies:

- Caddy `v2.8.4`
- `caddy-ja3` commit `bd46d4a35cb63fb9dda5e694fc426ae031147ecf`
- `caddy-ja4` `v0.2.1`, commit `a0fecfabcde03dc76b1bd86b9f8f3811a1d11324`
