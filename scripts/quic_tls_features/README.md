# Record-free QUIC TLS resumption reference

`run.exs` checks only the public `SSL.QUIC` provider against pinned aioquic 1.2.0.
It runs both roles, AES128/SHA256, AES256/SHA384 and ChaCha20/SHA256, with early
data off/on, each using a full then resumed handshake. It compares directional
traffic-secret hashes and both peers' resumed/early acceptance outcomes. The
Python peer is a separate TLS implementation, controlled over bounded pipes;
this harness sends no QUIC packets and claims no transport/application delivery.

From the umbrella root, use installed Mix dependencies and a task-owned build:

```sh
python3 -m venv /tmp/quic-tls-provider-peer
/tmp/quic-tls-provider-peer/bin/pip install -r apps/ex_ssl/e2e/quic_tls/requirements.txt
ERL_FLAGS='+S 2:2' MIX_ENV=test HTTP_FETCH_CI_APP=ex_ssl \
  MIX_BUILD_PATH=/tmp/quic-tls-provider-build/test \
  QUIC_TLS_PYTHON=/tmp/quic-tls-provider-peer/bin/python \
  mix run scripts/quic_tls_features/run.exs
```

`binder_vectors.py` uses Python stdlib HKDF/HMAC to reproduce the public synthetic
vectors in `apps/ex_ssl/test/fixtures/quic_binder_vectors.json`. These include
SHA256/SHA384, additional unselected PSK identities and HRR transcript prefixes,
plus early traffic-secret derivation. No real credential/session material is
contained in those vectors or printed by either handshake harness.

The provider/authority contract is `docs/quic/tls-continuation-contract.md` and
executed evidence is `docs/quic/tls-resumption-validation.md`. Authority single
use, deadlines, quotas and QUIC packet-level acceptance belong to the runtime.
