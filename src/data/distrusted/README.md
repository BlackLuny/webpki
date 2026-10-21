# Legacy webpki distrust backport

The eight SPKI values are copied byte-for-byte from [rustls/webpki#546](https://github.com/rustls/webpki/pull/546), commit `e981b775c50fe3d7f7802127164673e8043b0523`, released in rustls-webpki 0.103.16. They are SEQUENCE contents, not complete DER SPKI objects.

- `EMDVTLSCAG3B.spki.der`: `2d5f988ee3ceaf696845a34299ca3e05816429cdb5de92427889533175f97b95`
- `EMDVTLSCAG3C.spki.der`: `616e9a92539c40f454813f7fb8ae4a6db719498495215774f02d8b8b5a615d36`
- `EMEVTLSCAG3B.spki.der`: `bdf5ab18303069ebc3e3ddbb0fc0613693acef01b2fb7be1a0624aab60fbff0d`
- `EMEVTLSCAG3C.spki.der`: `b941c7577b918f7b9a9374aff3b02d8eda92545c86adb5b5268d1e121fe58ce2`
- `EMOVTLSCAG3B.spki.der`: `7f09de2d155cc9fbc2dc4585f2c134ea3fc04ea9d9b3e31fa2d6bf9fdc0a02a2`
- `EMOVTLSCAG3C.spki.der`: `6fc13706463e00b2cd2ae357f86de2441e59d501e322c7a02a531a9871e450f6`
- `EMOVCSCAG3B.spki.der`: `e8263cea915a92109a29fb497105dceeeb58fa099c2552c4082aff1e1a9a33b2`
- `EMOVCSCAG3C.spki.der`: `09f75d128061fcdc6d31d8317ce3fe0aea4dab2c66777ce548858dd23f763ce7`

`tests/` contains synthetic certificates, valid 2026–2036, signed by an ephemeral P-256 test CA. The eight named leaves carry the real distrusted public keys: without distrust they form valid chains under the test root. No compromised private key is needed or included. The other fixtures cover intermediate, root, cross-sign and unused-certificate behavior. No fixture private keys are retained.

`ErrorExt::CertDistrusted` is non-fatal for path search so an unrelated rejected issuer cannot hide a valid alternative. The semver-compatible legacy `Error` API maps it to `UnknownIssuer`, as it does other extended errors.

`webpki-roots/` preserves the 0.22 `TLS_SERVER_ROOTS` API, generating its static anchors from `webpki-roots >=1.0.10` at build time. This avoids a second stale root database and does not add runtime allocation. Workspace consumers must patch both `webpki` and `webpki-roots`; dependency-level patches do not propagate. Version-based audit tools can still flag the legacy API version, so check the pinned Git source and this regression suite rather than suppressing advisories globally.
