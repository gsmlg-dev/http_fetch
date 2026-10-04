# ClientHello fingerprint observation

`SSL.Fingerprint.client_hello(encoded_handshake, :tcp | :quic)` returns
`{:ok, result}` or a structured `{:error, reason}`. Input includes the handshake
header, not a TLS record. The body limit is 65,535 bytes. The result contains:

- `transport` and `source: :visible_client_hello`;
- `observation`: exact encoded bytes, original cipher IDs, ordered extension
  `{id, payload}` pairs, legacy version, session ID and compression bytes;
- `ja3: %{raw: projection, hash: lowercase_md5}`;
- `ja4: %{prefix: ..., cipher_raw: ..., extension_raw: ..., raw: ..., hash: ...}`.

`SSL.Fingerprint.new(transport)` / `feed(observer, bytes)` handle arbitrary
fragmentation of one ClientHello. Feed returns `{:ok, observer, results}`; the
result is emitted once. Trailing data is rejected. On error discard the observer.
No authentication, TLS negotiation, records, sockets or QUIC offsets are needed.
Unknown algorithms/extensions are retained; observation is separate from the
stricter negotiation/profile validation. Known fingerprint fields need valid
vector framing. The API supports visible legacy ClientHello versions as well as
TLS 1.3, but does not decode SSLv2-format handshakes or DTLS.

JA3 preserves offer order and removes GREASE. JA4 sorts only analytical cipher
and extension projections, excludes SNI/ALPN from its extension hash, and keeps
signature-algorithm order. Transport is mandatory and never inferred from ALPN.
QUIC uses `q`, TCP uses `t`; JA3's projection is identical but its result carries
explicit transport provenance. No projection changes the input or transcript.
ECH observations refer only to visible outer fields. Neither a fingerprint nor
its equality authenticates a client or proves browser equivalence.

For simulation, create a legal `WireProfile`, let `SSL.QUIC.new/2` generate fresh
key material, then pass its actual `{:emit, :initial, client_hello}` bytes to
`SSL.Fingerprint.client_hello/2`. Never substitute a configured target hash.

## Pinned references and licensing

JA4 technical definition and worked example:
https://github.com/FoxIO-LLC/ja4/blob/16b96d95c220762cf658f67d678cda2aac95c81e/technical_details/JA4.md

JA4 TLS client fingerprinting is BSD-3-Clause (not the separate JA4+ FoxIO
license). Its copyright/license notice is retained at
`test/fixtures/fingerprint/LICENSE-JA4`. The official example's expected digest
is `t13d1516h2_8daaf6152771_e5627efa2ab1`. Tests build encoded ClientHello bytes
from its listed fields and compare both the raw components and digest. No other
JA4+ algorithm is implemented.

JA3 is the Salesforce BSD-3-Clause algorithm. The independent Caddy fixture and
pinned plugin versions are documented in `e2e/README.md`: JA3 raw
`771,4865-4866,0-10-11-13-16-43-51,29,0`, digest
`af851f784aed02a8b1e0b6ac13251239`. That captured result is checked separately
from the official JA4 example.

Validation: `mix test test/ssl/fingerprint_test.exs` covers official/reference
values, raw/hash consistency, q/t provenance, GREASE, unknown IDs, sorting versus
signature order, binary ALPN edge cases, malformed/oversized input and bytewise
fragmentation of an actual `SSL.QUIC` ClientHello.
