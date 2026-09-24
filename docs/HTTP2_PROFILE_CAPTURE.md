# HTTP/2 Profile Capture

Capture workflow:

1. Enable `raw_capture: true` only for a bounded diagnostic run.
2. Store the redacted observation and the SHA-256 digest of the fixture with
   product/version, OS, tool version, origin, h2/h2c mode, and cold/reused
   connection context.
3. Compare with `HTTP.HTTP2.Fingerprint.diff/2`; report exact fields and known
   differences rather than only the lossy summary.

The executable provenance boundary is `HTTP.HTTP2.ProfileCapture`. Build a
manifest with `build_manifest/2`, passing the fixture bytes and metadata, or
validate an imported map with `validate_manifest/1`. The builder replaces the
fixture digest with a SHA-256 digest of the supplied bytes. Validation requires
the product/version/platform, capture tool and time, origin, `:h2` or `:h2c`,
`:cold` or `:reused` connection context, source evidence level, license,
matched fields, and known differences. It rejects unversioned browser labels
and malformed digests before a fixture can be imported.

This repository currently contains synthetic fixtures only. A real browser
profile must identify its product version/platform and independent capture
source before it can be marked `captured-verified`.
