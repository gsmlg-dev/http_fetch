# HTTP/2 Profile Capture

Capture workflow:

1. Enable `raw_capture: true` only for a bounded diagnostic run.
2. Store the redacted observation and the SHA-256 digest of the fixture with
   product/version, OS, tool version, origin, h2/h2c mode, and cold/reused
   connection context.
3. Compare with `HTTP.HTTP2.Fingerprint.diff/2`; report exact fields and known
   differences rather than only the lossy summary.

This repository currently contains synthetic fixtures only. A real browser
profile must identify its product version/platform and independent capture
source before it can be marked `captured-verified`.
