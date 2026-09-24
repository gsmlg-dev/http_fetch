# HTTP/2 Fingerprints

Profiles are configuration, not hashes. `WireProfile.digest/1` hashes the
validated canonical profile while preserving ordered wire lists. The built-in
profiles are `native_v1`, `synthetic_test_v1`, and `synthetic_test_v2`.

`HTTP.HTTP2.Fingerprint.observe/2` accepts serialized client bytes, records an
explicit source (`planned`, `serialized`, `transport_send_ok`, or
`peer_observed`), and bounds input to 1 MiB and 4096 frames by default. It
records ordered SETTINGS/window/header/frame summaries and redacts
authorization and cookie values. Raw capture is disabled unless explicitly
requested and is capped at 64 KiB. `diff/2` reports field-level changes;
`summary` is an intentionally lossy projection and is not a browser identity.

Current evidence is `engine_verified` for the pure profile compiler and
observer tests. No captured browser manifest or independent browser wire
sample is included, so `browser_profile_verified` remains false.
