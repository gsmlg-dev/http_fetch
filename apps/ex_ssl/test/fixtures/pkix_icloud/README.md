# Captured iCloud CalDAV public certificate chain

`chain.pem` is the exact leaf-first public chain supplied in
[issue #113](https://github.com/gsmlg-dev/http_fetch/issues/113) for
`caldav.icloud.com:443`: the leaf, Apple Public Server ECC CA 1 - G1 signed by
DigiCert Global Root G3, then an alternative cross-sign of that intermediate
signed by Apple Root CA G3. `digicert_global_root_g3.pem` is the explicit sole
trust anchor used by the regression. These files contain no private keys.

Pinned DER SHA256 fingerprints:

- Leaf: `882969869F9E85BBE6A6E009698DE55CC041DAFBB19A3303971E9AEF4C9A15CD`
- DigiCert root: `31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0`

The captured leaf expires on 2027-02-18. The test independently validates the
two-certificate prefix using OTP `:public_key.pkix_path_validation/3` and requires
the same success or expiry rejection from ex_ssl for both the prefix and the
complete presentation. It never disables time validation or skips an expired
fixture. The separate synthetic cross-signed fixtures keep the successful path
selection regression valid through 2036.
