# ZFC legacy TLS security backport

This fork keeps webpki 0.22.4 API compatibility for rustls 0.20 (including ShadowTLS) while rejecting the eight emSign public keys distrusted by rustls-webpki 0.103.16. Source and fixture provenance: [src/data/distrusted/README.md](src/data/distrusted/README.md).

The companion `webpki-roots` 0.22.6 workspace package generates the old static API from maintained `webpki-roots >=1.0.10`. It removes emSign ECC Root CA - G3 without changing callers or copying the legacy root database.

Both packages must be patched at **each final workspace root**. Cargo does not propagate patches from library dependencies. ZFC, private_tun, and shadow-tls-tokio pin the same Git revision. Keep modern TLS dependencies at rustls-webpki >=0.103.16 and webpki-root[s|-certs] >=1.0.10 as well. The public-key block applies even to caller-provided roots and cross-signed certificates.

The non-exhaustive ErrorExt gains CertDistrusted; the old exhaustive Error API maps it to UnknownIssuer. Distrust is non-fatal to path search, allowing an alternative valid issuer. The no_std and no-allocation behavior of webpki and its old root API is preserved.

Regression checks (run `cargo generate-lockfile` first in a fresh checkout; upstream does not track the library workspace lockfile):

```sh
cargo test -p webpki --lib --locked
cargo test -p rcgen-tests --locked
cargo test -p webpki-roots@0.22.6 --locked
cargo check -p webpki --no-default-features --locked
```

Version-only scanners may still flag 0.22.x; the Git revision, generated modern root source, and regression checks establish the mitigation. Do not globally ignore the RustSec advisories. The full ShadowTLS TLS-stack migration remains tracked separately in BlackLuny/zfc#312.
