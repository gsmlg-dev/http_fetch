# Sources and inspected revisions

Accessed 2026-09-23. Repository facts were read through the connected GitHub tools. Standards were checked against primary RFC/maintainer sources. Snapshot facts and proposed architecture must not be conflated.

## R1 — ex_ssl source snapshot and minimal repair

Repository: `gsmlg-dev/ex_ssl`.
Current reviewed HEAD: `02eb981f59d4e182d4473e264a9f8b093ec6bf3d`.
Minimal syntax repair: `6cc7450006e3552dbc0ed22b697b64239539bc03`.
Previous reviewed baseline: `606087058e912b08ce20e145bcd8505744be8a78`.

- `https://github.com/gsmlg-dev/ex_ssl/commit/6cc7450006e3552dbc0ed22b697b64239539bc03`
- `https://github.com/gsmlg-dev/ex_ssl/commit/02eb981f59d4e182d4473e264a9f8b093ec6bf3d`

The two commits were read with full file diffs. The first changes the three previously identified source files plus documentation; the second changes version/changelog only.

## R2 — release and recorded evidence

- `https://github.com/gsmlg-dev/ex_ssl/releases/tag/v0.7.1`
- `https://github.com/gsmlg-dev/ex_ssl/blob/02eb981f59d4e182d4473e264a9f8b093ec6bf3d/docs/QUIC_TLS_IMPLEMENTATION.md`

Release body read directly. It distinguishes local formatter tests, supported-runtime CI, historical full-integration failures and the absence of Hex publication by this release task. Counts reproduced in the review are attributed to that record when not read from raw execution logs.

## R3 — actual TLS interface

- `https://github.com/gsmlg-dev/ex_ssl/blob/02eb981f59d4e182d4473e264a9f8b093ec6bf3d/docs/QUIC_TLS_INTERFACE.md`
- `https://github.com/gsmlg-dev/ex_ssl/blob/02eb981f59d4e182d4473e264a9f8b093ec6bf3d/lib/ssl/quic.ex`

The interface document was read at the reviewed pin. The public production module is unchanged by the minimal syntax repair; its earlier reviewed implementation remains the basis. Any later upstream upgrade must rerun consumer contract tests.

## R4 — actual fingerprint interface

- `https://github.com/gsmlg-dev/ex_ssl/blob/02eb981f59d4e182d4473e264a9f8b093ec6bf3d/docs/FINGERPRINTS.md`

Describes direct/fragmented observation, provenance, limits, visibility, profile simulation, pinned external vectors and retained attribution. Its official JA4 fixture is tied to a particular maintainer revision; do not substitute a different online example without updating fixture provenance.

## R5 — Abyss starting point

Reviewed HEAD: `d4ed1467295edca50266901fc2890cb00e973048`.

- `https://github.com/gsmlg-dev/abyss/blob/d4ed1467295edca50266901fc2890cb00e973048/lib/abyss/listener.ex`
- `https://github.com/gsmlg-dev/abyss/blob/d4ed1467295edca50266901fc2890cb00e973048/lib/abyss/connection.ex`

Both sources were read. The proposed dispatcher/writer contracts do not already exist merely because they are named in this plan.

## R6 — remote CI evidence

Job lists/steps were read for the build, Test and reference runs below:

- CI: `https://github.com/gsmlg-dev/ex_ssl/actions/runs/35828024753`
- Test: `https://github.com/gsmlg-dev/ex_ssl/actions/runs/35827826151`
- QUIC TLS reference: `https://github.com/gsmlg-dev/ex_ssl/actions/runs/35828024798`

Additional successful runs linked by the release record, not independently inspected job-by-job in this review:

- TLS peers/downstream: `https://github.com/gsmlg-dev/ex_ssl/actions/runs/35827826186`
- Caddy JA3/JA4: `https://github.com/gsmlg-dev/ex_ssl/actions/runs/35827826143`

Success describes each workflow's actual scope. It does not certify every optional suite or every platform.

## S1 — QUIC v1 transport

RFC 9000, transport states, streams, parameters, CID/path handling, packetization and error domains.

`https://www.rfc-editor.org/rfc/rfc9000.html`

Implementation must maintain a requirements-to-test map and review applicable errata; this plan does not claim an exhaustive errata audit.

## S2 — QUIC TLS and protection

RFC 9001, handshake/protection integration and test vectors.

`https://www.rfc-editor.org/rfc/rfc9001.html`

## S3 — Recovery and congestion

RFC 9002, QUIC loss detection and congestion control.

`https://www.rfc-editor.org/rfc/rfc9002.html`

## S4 — Current upstream TLS normative baseline

RFC 9846, TLS 1.3, published July 2026 and obsoleting RFC8446. This was checked against RFC Editor, not assumed from earlier conversation text. QUIC-specific integration continues to use RFC9001.

`https://www.rfc-editor.org/info/rfc9846/`

## S5 — Deferred application protocol

RFC 9114, HTTP/3.

`https://www.rfc-editor.org/rfc/rfc9114.html`

This is why QUIC transport support alone is not a claim of HTTP/3 support.

## S6 — Future version boundary

RFC 9369, QUIC v2, consulted for version separation only; v2 execution is not part of the initial v1 milestone.

`https://www.rfc-editor.org/rfc/rfc9369.html`

## S7 — JA4 maintainer definition

- `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md`
- `https://github.com/FoxIO-LLC/ja4`

Use the actual upstream ex_ssl fixture pin for exact regression expectations. JA4 TLS client fingerprinting is distinct from other JA4+ methods, including their license scope. No broader family of algorithms or fingerprint database is included by this plan.

## Workspace and artifact status

A GitHub repository metadata request for `gsmlg-dev/ex_quic` returned 404. This only describes access at review time; it is not evidence that a local/private workspace cannot exist. Inspect the real Codex workspace first.

This document package supersedes the earlier supplied ex_quic v1/v2 planning packages. It creates no GitHub repository and contains no protocol implementation, certificates, private keys, traffic secrets or claimed new test results.

## S8 — unreliable QUIC DATAGRAM extension

[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), sections 3–5,
read 2026-09-29 for issue #5. Covers transport parameter 0x20, frame types
0x30/0x31, encoded-frame size limits, one-way negotiation, ACK elicitation,
non-retransmission, congestion control and receiver resource drops.
