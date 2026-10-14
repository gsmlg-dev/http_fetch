# Cross-signed path regression fixtures

Synthetic public certificates for issue [#113](https://github.com/gsmlg-dev/http_fetch/issues/113).
No private keys are included. These are test trust anchors, not production trust.

`leaf.pem` (`example.test`) is signed by the intermediate key shared by
`intermediate_a.pem` and `intermediate_b.pem`. The former is signed by
`root_a.pem`; the latter by `root_b.pem`. The presented order is leaf,
intermediate A, intermediate B. With only root A trusted, the valid path uses
the first two certificates. OTP `:public_key.pkix_path_validation/3` independently
checks that prefix and rejects the entire reversed presentation as an invalid
issuer sequence.

The roots, intermediates and valid leaf expire on 2036-10-11. `expired.pem` is
an independently signed leaf with the same identity, expired since 2020-01-01.
The tests retain normal time validation. The valid leaf and intermediate A
include Any Policy; explicitly trusting intermediate A still produces OTP's
`policy_requirement_not_met` rejection for this fixture. The regression checks
that path selection preserves that reference rejection.

The valid leaf's DER SHA256 is
`1197FA2578BA3CC7D0239A10203A823BEB4EA2512AB0A309F69FF337B6EB7EE6`.
Root A's DER SHA256 is
`6133C848CB39890FB4DAF3F5221359FE608F7270C1F8550DAFF0B2398A22CA12`.
