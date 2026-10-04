# QUIC-TLS interface

`SSL.QUIC` is an experimental caller-owned TLS 1.3 certificate-handshake API.
Both client and server perform actual ECDHE, signatures and Finished verification.
See [QUIC_TLS_IMPLEMENTATION.md](QUIC_TLS_IMPLEMENTATION.md) for executed evidence
and validation limitations. No production-readiness claim is made.

## Public calls and ownership

- `capabilities/0`: implemented TLS algorithms and separate runtime availability,
  plus role-specific limitations. This does not prove QUIC packet/header protection.
- `new(:client | :server, options)`: `{:ok, state, ordered_actions}` or
  `{:error, %SSL.QUIC.Error{kind: :configuration}}`.
- `feed(state, level, bytes)`: `{:ok, next_state, ordered_actions}` or
  `{:error, error, terminal_state, ordered_actions}`.
- `info(state)`: role, phase, legal receive level, cipher suite, ALPN, configured
  allowed algorithm IDs, peer identity authentication, peer-parameter
  authentication and TLS completion. No secrets.
- `abort(state, reason)`: terminal state with obsolete sensitive references removed.

The caller owns the only current opaque state and discards older versions. No
socket, `SSL.Connection`, Registry, ETS, timer or hidden process is created.
The API cannot prevent an application from retaining old immutable terms.
`abort/2` does not emit a network close; the caller owns connection lifecycle.

Levels are `:initial`, `:handshake`, and `:application`. Input consists solely of
handshake type/uint24-length/body bytes. The caller reassembles CRYPTO offsets,
removes duplicates and supplies only new contiguous bytes within each level.
TLS handles arbitrary fragmentation and same-level coalescing with bounded
buffers. Partial messages cannot cross levels. Use `info(state).receive_level`
to buffer future-level bytes in the caller before feeding them. Wrong-level
input fails the instance rather than being cached internally.

## Configuration

Options are a keyword list; unknown and duplicate keys reject. Files are loaded
by the caller, not during feed. No permissive verification mode is supported.
All local configuration failures return
`{:error, %SSL.QUIC.Error{kind: :configuration, alert: nil, reason: :invalid_configuration}}`
without a state or actions. In particular, `verify: :verify_none` is rejected,
not treated as an instruction to omit authentication. TCP facade option names
such as `cacertfile`, `certfile`, `keyfile` and `alpn_advertised_protocols` are
not aliases in this API.

| Option | Meaning |
| --- | --- |
| `alpn` | Both roles: required nonempty list of unique opaque nonempty binaries, each at most 255 bytes; encoded entries total at most 65,533 bytes; no product protocol default |
| `transport_parameters` | Required binary; `<<>>` means present with empty payload, not missing |
| `cacerts` | Client-only in-memory DER trust-anchor list or PEM bundle |
| `reference_identity` | Client-only required `{:dns_id, binary}` or `{:ip, address}`; independent of SNI. IP addresses are valid IPv4/IPv6 tuples or UTF-8 numeric address binaries parsed by `:inet.parse_address/1`; malformed addresses reject at construction |
| `server_name` | Optional client SNI binary; omitted/nil does not disable reference-identity verification |
| `cert`, `key` | Server-required or optional client identity: leaf-first DER chain (or leaf DER), plus `{asn1_type, key_der}` as accepted by the existing identity loader; no file options |
| `ciphers` | Nonempty ordered TLS 1.3 cipher ID list; defaults to runtime-available implemented suites |
| `groups` | Nonempty ordered group ID list; defaults to runtime-available groups; first client group gets the initial fresh share |
| `signature_algorithms` | Nonempty ordered implemented signature IDs; server intersects with its validated identity |
| `profile` | Client-only explicit `SSL.ClientHello.WireProfile`; must have empty session ID, `%SSL.ClientHello.RecordPolicy{mode: :none}`, the exact ALPN and local parameters, and implemented algorithms |
| `depth`, `customize_hostname_check` | Client PKIX settings matching the existing verifier; unsupported server authentication policy rejects |
| `limits` | Keyword overrides below; positive values can lower but not raise hard bounds |

Default QUIC profiles use TLS 1.3 only, empty session ID, no record policy/CCS,
explicit ALPN, certificate-signature policy, fresh key share, and raw extension
57 for the configured transport parameters. TCP default profiles remain distinct.
Explicit profiles with TCP's `record.mode: :default` reject. The server currently
uses a single identity and configured algorithm preference, not a server profile.

The client requires both explicit trust and a reference identity. SNI only
selects a virtual host: neither absent SNI nor a matching SNI value substitutes
for reference-identity verification. The server rejects client trust, reference
identity, SNI, depth, custom hostname checking and profile options; it has no
client-certificate authentication policy. Optional client `cert`/`key` supports
an independent server's in-handshake CertificateRequest, not server mTLS here.
ALPN is byte-oriented (including non-UTF-8 tokens); negotiated actions and
`info/1` return the selected bytes. No `h3`, `doq`, DNS or HTTP behavior is implied.

Limits (bytes unless count):

| Key | Default / hard maximum |
| --- | ---: |
| `max_handshake_length` | 1,048,576 per body |
| `max_total_handshake_bytes` | 2,097,152 cumulative inbound plus emitted bytes, including post-handshake tickets |
| `max_certificate_count` | 16 |
| `max_total_certificate_bytes` | 524,288 |
| `max_certificate_bytes` | 262,144 |
| `max_extension_bytes` | 65,535 |
| `max_signature_bytes` | 16,384 |

ClientHello parsing additionally bounds its body to 65,535 bytes. Identity loading
has its existing key/certificate bounds. Local parameter payloads are at most
65,000 bytes and within the configured extension bound, leaving space for TLS
extension overhead. No QUIC parameter-item decoder is present.

`max_extension_bytes` is an **inbound** encoded extension-vector budget: each
entry's four-byte type/length header and payload count; the outer vector length
and handshake header do not. It covers server-received ClientHello and
client-received ServerHello/HRR, EncryptedExtensions, CertificateRequest,
certificate-entry extensions (also cumulatively across the chain), and
NewSessionTicket. ServerHello/HRR declared extension lengths are rejected as soon
as the fixed prefix and vector length arrive, even before the payload. Rejection
precedes retry key generation, CH2 serialization and secret actions, with
`kind: :tls, alert: :decode_error, reason: :extension_length_exceeded`.
The independent per-message and cumulative handshake limits still apply.

Outbound messages retain their per-message/cumulative handshake budgets and local
parameter-payload checks. The configured extension budget is **not** a total
outbound extension-vector cap: an accepted HRR cookie can make CH2's extensions
larger than the receive budget. This change closes the inbound Initial-message
gap; it does not add an outbound extension-vector policy.

## Ordered actions and authentication

Actions form one list, processed from left to right:

```elixir
{:emit, level, exact_handshake_bytes}
%SSL.QUIC.Secret{
  level: :handshake | :application,
  direction: :read | :write,
  cipher_suite: integer_id,
  aead: cipher_atom,
  hkdf: :sha256 | :sha384,
  secret: binary
}
{:peer_transport_parameters, raw_bytes, :unverified | :authenticated}
{:peer_authenticated, :server}
{:negotiated_alpn, protocol}
:handshake_complete
{:error, %SSL.QUIC.Error{kind: kind, alert: alert_atom_or_nil, reason: reason_atom}}
```

Directions always refer to the local endpoint. Ordinary inspection of Secret and
state hides secret/private material. The explicit `secret` field is intentionally
available only to the driver. Never log actions by extracting their maps or raw
fields. No master secret, private key, TLS `TrafficState`, Initial secret or
packet/header-protection key is an action or `info/1` result.

Normal client sequence:

1. Emit Initial ClientHello (or a second ClientHello after validated HRR).
2. On ServerHello, install Handshake read then write secrets.
3. On EncryptedExtensions, surface unverified server parameters.
4. Verify chain/reference identity, CertificateVerify and server Finished.
5. Install Application read secret; report server authentication, authenticated
   parameters and negotiated ALPN.
6. Emit optional client Certificate/CertificateVerify, then Finished at Handshake.
7. Install Application write secret; report TLS completion.

Normal server sequence:

1. Parse ClientHello and, if necessary, emit Initial HRR and await a constrained
   second ClientHello with the exact message_hash transcript rewrite.
2. Surface unverified client parameters; emit Initial ServerHello.
3. Install Handshake read then write secrets.
4. Emit EncryptedExtensions, Certificate, CertificateVerify and Finished at
   Handshake, using the already installed write secret.
5. Install Application write then read secrets. This is **not** TLS completion.
6. Verify client Finished, then authenticate parameters, report ALPN and complete.
   `peer_authenticated` stays false: no client certificate identity was requested.

Returned bytes are committed to the caller's reliable send queue, not sent or
acknowledged on the network. Retransmit those bytes without another TLS call.
Empty calls at the legal receive level emit nothing. Failure/abort is terminal;
later calls return a closed error and no repeated error action, secret or
completion. A failing feed returns only its terminal error action; any actions
from earlier successful feeds remain delivered and cannot be retracted.

`handshake_complete` and `peer_authenticated` are historical TLS facts, not QUIC
handshake confirmation. This API does not send/receive HANDSHAKE_DONE, discard
packet keys, acknowledge packets or update QUIC keys. State/action reference
release is not guaranteed physical erasure on BEAM.

## Extensions and post-handshake policy

Extension 0x0039 is required in ClientHello and EncryptedExtensions. Missing and
present-empty differ. TLS validates envelope length, duplicates, placement and
resource limits, retaining raw bytes. The caller validates QUIC parameter IDs,
duplicate parameter IDs, CID, flow control and version-specific semantics.
Ordinary TCP profiles cannot emit this extension accidentally.

Certificate/ECDHE negotiation requires both supported_groups and key_share.
A missing extension fails with `missing_extension` / `negotiation_extensions`;
a present, correctly encoded empty client_shares vector can trigger HRR.
Duplicate shares and invalid group relationships remain `illegal_parameter`,
and malformed vectors remain `decode_error`. These are negotiation checks;
fingerprint observation still accepts syntactically valid offers without these
capabilities. The client currently requires a matching real initial key share:
an explicit empty-share profile cannot initiate a connection. Accepting an empty
peer share list does not change that client limitation or the nonempty default.

EE and post-handshake ticket decoding use the shared TLS core's classification:
unoffered/unsupported extensions produce `unsupported_extension`, known
extensions in forbidden positions produce `illegal_parameter`, and malformed
encoding/lengths produce `decode_error`. Missing QUIC parameters remain
`missing_extension`; selecting an unoffered ALPN remains `illegal_parameter`.
The `SSL.QUIC` function signatures, ordered-action contract and error domains
are unchanged; callers need no migration, but now receive the corrected alerts.

Local resumption, 0-RTT and server-mTLS requests are unsupported configuration.
A legal peer PSK/early-data proposal can be declined for a certificate handshake;
no PSK is selected and no early traffic secret is produced. Unknown PSK mode IDs
remain observable and unselected. A completed client boundedly parses and ignores
NewSessionTicket, retaining no tickets. Unexpected post-handshake messages,
including TLS KeyUpdate and post-handshake authentication, terminate the instance.
TLS KeyUpdate returns `kind: :tls, alert: :unexpected_message` (QUIC 0x010a).
Post-handshake CertificateRequest on the client returns `kind: :quic` (QUIC
PROTOCOL_VIOLATION, 0x0a), as do nonempty client session IDs and wrong encryption
levels. TLS alert atoms map to 0x100 + their registered alert number; local
configuration/closed errors are not peer TLS alerts. See the
[standards and errata audit](QUIC_TLS_STANDARDS.md).

## Pure driver example

Load credentials outside TLS, then drive only the public API:

```elixir
client_options = [
  cacerts: trusted_der_certificates,
  reference_identity: {:dns_id, "example.test"},
  alpn: ["example-protocol"],
  transport_parameters: local_client_parameters
]
server_options = [
  cert: server_der_chain,
  key: {key_asn1_type, key_der},
  alpn: ["example-protocol"],
  transport_parameters: local_server_parameters
]
{:ok, client, client_actions} = SSL.QUIC.new(:client, client_options)
{:ok, server, []} = SSL.QUIC.new(:server, server_options)

# The caller processes every action in order. This helper illustrates only
# moving emitted bytes in a no-network test; a QUIC driver also installs every
# Secret, validates parameter events and handles terminal Error actions.
transfer = fn receiver, actions ->
  Enum.reduce(actions, {receiver, []}, fn
    {:emit, level, bytes}, {state, accumulated} ->
      {:ok, next, emitted} = SSL.QUIC.feed(state, level, bytes)
      {next, accumulated ++ emitted}
    _event, accumulator -> accumulator
  end)
end
{server, server_actions} = transfer.(server, client_actions)
{client, client_actions} = transfer.(client, server_actions)
{server, _server_events} = transfer.(server, client_actions)
true = SSL.QUIC.info(client).handshake_complete
true = SSL.QUIC.info(server).handshake_complete
```

The example assumes no HRR; a general driver repeats transfers until neither
side has emitted bytes. `test/ssl/quic_test.exs` contains an executable duplex
loop including HRR, per-byte fragmentation and directional-secret comparisons.

## Fingerprints and independent verification

Pass actual emitted Initial ClientHello bytes to
`SSL.Fingerprint.client_hello(bytes, :quic)`. Its observation and fingerprint
result is independent of TLS authentication; see [FINGERPRINTS.md](FINGERPRINTS.md).
The [pinned aioquic harness](../e2e/quic_tls/README.md) drives only this public
interface, comparing both roles, ALPN, parameters and directional secrets.

## Application startup and source consumption

Use a normal Mix dependency (`:ex_ssl`, with runtime enabled). The generated
production application declares `:crypto` and `:public_key`; ordinary consumer
application startup starts them transitively. `:ssl` is declared only in this
repository's test environment for independent reference peers. Runtime TLS work
is performed by ex_ssl. Applications bypassing Mix startup must explicitly call
`Application.ensure_all_started(:ex_ssl)` before using the API.

`bash scripts/phase1_consumer_smoke.sh` builds an unpublished package, compiles a
standalone normal consumer and starts it in a fresh VM. It verifies dependency
startup, the public QUIC exports and initial ClientHello materialization while
asserting that OTP `:ssl` is not started. It does not publish or edit a downstream
repository. The current source/worktree identity, executed phase-one checks and
remaining validation limits are in [phase1-acceptance.md](phase1-acceptance.md).
