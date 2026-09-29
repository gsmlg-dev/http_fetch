# HTTP/2 Fingerprints

Profiles are configuration, not hashes. `WireProfile.digest/1` hashes the
validated canonical profile while preserving ordered wire lists. The built-in
profiles are `native_v1`, `synthetic_test_v1`, and `synthetic_test_v2`.

The built-ins now carry revision 2. `native_v1` sends
`SETTINGS_ENABLE_PUSH=0` instead of an empty SETTINGS payload;
`synthetic_test_v1` appends the same setting and advertises its configured
131,072-byte stream receive window consistently. `synthetic_test_v2` keeps its
ordered settings but also moves to revision 2. Existing profile identifiers
remain accepted. These corrected bytes and canonical digests differ from
revision 1, so stored profile digests and wire fixtures need recapture before
comparison. Custom profiles with `push: :disabled` must explicitly include
`{2, 0}` when supplying a settings list.

The supported profile receive policy is the default 65,535-byte target,
32,767-byte threshold, and 32,767-byte increment. Initial connection and
stream receive allowances are capped at 1 MiB. Other receive policies,
padding modes, and user-agent modes are rejected by the compiler until the
runtime supports them.

`HTTP.HTTP2.Fingerprint.observe/2` accepts serialized client bytes, records an
explicit source (`planned`, `serialized`, `transport_send_ok`, or
`peer_observed`), and bounds input to 1 MiB and 4096 frames by default. It
records ordered SETTINGS/window/header/frame summaries and redacts
authorization and cookie values. Raw capture is disabled unless explicitly
requested and is capped at 64 KiB. `diff/2` reports field-level changes;
`summary` is an intentionally lossy projection and is not a browser identity.
Invalid or negative observation limits return a structured error instead of
attempting an unbounded parse.

Current evidence is `engine_verified` for the pure profile compiler and
observer tests. No captured browser manifest or independent browser wire
sample is included, so `browser_profile_verified` remains false.
