#!/usr/bin/env python3
"""Inspect pinned independent source; success is source compatibility, never wire acceptance."""
import hashlib
import json
import re
import urllib.request

REPOSITORY = "quic-go/webtransport-go"
REVISION = "5232f760bf1b10b1e85841725cd73bc22ecf61e7"
BASE = f"https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/"
QUIC_REVISION = "793f74d8e03368c5aded128af6f48d21dbb47f73"


def main():
    sources = {}
    digests = {}
    for path in ("protocol.go", "server.go", "go.mod", "README.md"):
        with urllib.request.urlopen(BASE + path, timeout=30) as response:
            data = response.read()
        sources[path] = data.decode("utf-8")
        digests[path] = hashlib.sha256(data).hexdigest()
    quic_sources = {}
    for path in ("internal/wire/transport_parameters.go", "internal/wire/frame_type.go"):
        url = f"https://raw.githubusercontent.com/quic-go/quic-go/{QUIC_REVISION}/{path}"
        with urllib.request.urlopen(url, timeout=30) as response:
            quic_sources[path] = response.read().decode("utf-8")
    protocol = sources["protocol.go"]
    setting = re.search(r"settingsWebTransportEnabled\s*=\s*(0x[0-9a-fA-F]+)", protocol).group(1)
    result = {
        "repository": REPOSITORY,
        "revision": REVISION,
        "source_sha256": digests,
        "connect_token_matches": 'protocolHeader = "webtransport-h3"' in protocol,
        "wt_enabled_codepoint": setting,
        "draft17_setting_matches": int(setting, 16) == 0x20B8933B,
        "h3_datagram_enabled_in_source": "s.EnableDatagrams = true" in sources["server.go"],
        "partial_reset_enabled_in_source": "quicConf.EnableStreamResetPartialDelivery = true" in sources["server.go"],
        "quic_dependency": "github.com/quic-go/quic-go v0.62.0",
        "quic_immutable_identity": QUIC_REVISION,
        "quic_datagram_parameter_in_source": "maxDatagramFrameSizeParameterID" in quic_sources["internal/wire/transport_parameters.go"],
        "reset_stream_at_parameter": re.search(r"resetStreamAtParameterID transportParameterID = (0x[0-9a-f]+)", quic_sources["internal/wire/transport_parameters.go"]).group(1),
        "reset_stream_at_frame": re.search(r"FrameTypeResetStreamAt FrameType = (0x[0-9a-f]+)", quic_sources["internal/wire/frame_type.go"]).group(1),
        "reset_draft11_acceptance": "NOT RUN; source comments reference draft-09",
        "wire_acceptance": "NOT RUN",
        "result": "BLOCKED: pinned source advertises an incompatible WT setting",
    }
    print(json.dumps(result, indent=2))
    return 2 if not result["draft17_setting_matches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
