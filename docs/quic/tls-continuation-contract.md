# QUIC TLS continuation contract (Task B)

Implementation contract for Task A. Status: provider implementation and scoped independent TLS validation pass; capability flags remain false pending full QUIC runtime acceptance. API is record-free and caller-owned; no storage, processes, clock reads or network IO are introduced in the pure core.

## Configuration

Existing `SSL.QUIC.new(role, options)` remains unchanged when resumption is omitted. Enable with `resumption: [enabled: true, context: binary, now: monotonic_ms]`. `context` is a bounded (1..256 bytes) runtime-computed partition digest covering QUIC version, static profile/application version, algorithms and current trust/credential policy. It excludes generated keys/CIDs/transport parameters/ages/binders. Runtime owns endpoint-local stores and live monotonic expiry checks; a TLS ticket never validates a peer address.

Client may additionally supply `session: %SSL.QUIC.Session{}` inside `resumption`. Provider revalidates the cached peer certificate under current trust/reference identity and algorithm/name policy before offering; an ineligible session triggers a fresh authenticated handshake. Server `ticket_lifetime` defaults to 600 seconds and may be shortened (1..600). `now` is provided by runtime and must use the same monotonic domain as cached sessions.

Early data remains off unless `early_data: true` inside the enabled resumption policy. Runtime must also bind its required application-profile version into context. Client offers early only for a validated session with `max_early_data == 0xffffffff`. Server's atomic commit receipt determines whether early data may be accepted after all transport policy/quota checks. Provider eligibility additionally requires the original cipher and a ticket-age difference of at most 10 seconds; authority admission may reject more conservatively.

## Session and requests

`%SSL.QUIC.Session{identity, psk, hash, cipher_suite, age_add, issued_at, expires_at, alpn, server_name, context, peer, transport_parameters, max_early_data}` is redacted on inspection. Identity and PSK are private runtime/cache material. Server sessions need no peer chain (`peer: nil`); client sessions retain the authenticated server `peer` map. `transport_parameters` remembers the ticket-issuing peer's original parameters; server sessions remember their own advertised original parameters for quota checks. `max_early_data` is 0 or `0xffffffff`. Do not expose sessions in ordinary application events.

`%SSL.QUIC.Request{id, operation, identity, context, session, lease, early_data}` is redacted. `operation` is `:lookup | :commit | :store`; unused fields are nil. Exactly one outstanding request exists in each state. IDs are opaque and scoped to one state generation. Thread the returned state through every call; immutable snapshot reuse is outside this linear ownership contract.

## Ordered actions and replies

1. Server parses exact CH1 and validates the structural TLS offer before emitting `{:session_lookup, request}` for identity zero. More identities may be legal but are not selected.
2. Call `SSL.QUIC.continue(state, request.id, {:ok, session, lease, now_ms})` or `:miss`. `{:error, reason}` is equivalent to a miss before any selected PSK flight. Lookup only grants a lease: it must not consume. Provider verifies eligibility and binder before emitting `{:session_commit, request}`. Binder mismatch for a selected eligible PSK is fatal `decrypt_error`; no fallback/commit.
3. Commit must atomically consume the live single-use ticket. Reply `{:ok, :resumed}` to resume with early data rejected; `{:ok, :early_data}` additionally attests runtime TP/application/cipher/age/quota admission. `:miss` or `{:error, reason}` falls back to certificate authentication before any selected PSK flight. Unknown timeout consumption must never restore the ticket. No selected PSK flight or server early secret is emitted before positive commit.
4. HRR consumes CH1's ticket before HRR. Provider retains that session privately, rejects early, and verifies CH2's binder over `message_hash(CH1) || HRR || Truncate(CH2)`. No second lookup/commit occurs. Failure burns the ticket.
5. After verified client Finished, `:handshake_complete` precedes optional `{:session_store, request}`. Runtime stores the supplied `request.session` atomically under its endpoint limits. Reply `:ok` emits a single `{:emit, :application, new_session_ticket}`; `:miss` or `{:error, reason}` skips issuance without failing the established connection. Store has an independent <=100 ms lifecycle deadline and cannot extend handshake time.
6. Client NST yields `{:session_ticket, session}` privately to runtime. Cache receipt never enters ordinary application output. Client provider limits receipts per connection.

Actions retain the existing `{:emit, level, bytes}`, `%SSL.QUIC.Secret{}`, peer parameter/authentication/ALPN and completion actions. For R2 `Secret.level` may be `:early_data` (client write or server read), and `{:early_data, :accepted | :rejected}` reports TLS disposition once. HRR rejects it. The client receives its early write secret after its Initial ClientHello is queued. Server receives an early read secret only after commit approval. Early secrets do not imply handshake completion/authenticated parameters or permission for application delivery. QUIC sends no TLS EndOfEarlyData. Runtime must retain early plaintext until verified Finished plus transport validation, discard on failure/rejection and never automatically replay.

## Error and ownership semantics

`continue/3` returns the same tagged shapes as `feed/3`: `{:ok, state, actions}` or `{:error, %SSL.QUIC.Error{}, state, actions}`. While pending, a nonempty `feed` returns a recoverable configuration error `:continuation_pending`, unchanged state and no actions; runtime must retain unconsumed contiguous CRYPTO. Empty feeds at the advertised receive level are harmless. Wrong/stale/duplicate IDs return recoverable configuration error `:invalid_continuation`, unchanged state and no actions. Malformed matching replies are fatal configuration errors `:invalid_continuation_result` and erase pending secret material. Terminal states return closed errors. `abort/2` destroys pending/session references.

Runtime bounds authority requests by the handshake deadline and <=100 ms authority deadline, separately generation/ref checks late replies, abandons reservation on timeout/death, and keeps quota charged until authority settlement. Provider actions never acknowledge address validation or release runtime quotas. After a continuation resolves, runtime can feed retained bytes at `info(state).receive_level`.

The provider cannot enforce atomic single use across immutable state snapshots or independent processes. This is the endpoint authority's responsibility; one owner holds the current TLS state. No arbitrary callbacks or TCP session-cache access are introduced.
