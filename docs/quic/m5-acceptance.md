# M5 Abyss acceptance evidence

The Abyss dispatcher seam is at `gsmlg-dev/abyss@ace6cce`; the external
endpoint and dependency-free adapter are at `ex_quic@9a0308e`.

The real UDP smoke command and its scope are recorded here. It uses a concrete
loopback bind, keeps Abyss as the shared socket owner, routes through the
external `Quic.Endpoint`, and sends through the dispatcher writer.

```sh
ABYSS_CHECKOUT=/Users/gao/Workspace/gsmlg-dev/ex_quic/.trees/abyss-m5 \
  mix run scripts/interop/abyss_m5.exs
```

The script now runs two concurrent clients, closes one, resumes the listener on
a new port, and connects a third client after restart. A passing run requires
both initial clients to establish, the second to remain established after the
first closes, and the third to establish through the restarted listener.
Writer failure, stream transfer, and ordinary UDP regression remain open cells.
