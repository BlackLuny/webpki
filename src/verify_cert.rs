// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use core::default::Default;

use crate::{
    budget::Budget,
    cert::{self, Cert, EndEntityOrCa},
    der, equal,
    error::ErrorExt,
    name, signed_data, time, Error, SignatureAlgorithm, TrustAnchor,
};

pub fn build_chain(
    required_eku_if_present: KeyPurposeId,
    supported_sig_algs: &[&SignatureAlgorithm],
    trust_anchors: &[TrustAnchor],
    intermediate_certs: &[&[u8]],
    cert: &Cert,
    time: time::Time,
) -> Result<(), ErrorExt> {
    build_chain_inner(
        required_eku_if_present,
        supported_sig_algs,
        trust_anchors,
        intermediate_certs,
        cert,
        time,
        0,
        &mut Budget::default(),
        DISTRUSTED_SPKIS,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_chain_inner(
    required_eku_if_present: KeyPurposeId,
    supported_sig_algs: &[&SignatureAlgorithm],
    trust_anchors: &[TrustAnchor],
    intermediate_certs: &[&[u8]],
    cert: &Cert,
    time: time::Time,
    sub_ca_count: usize,
    budget: &mut Budget,
    distrusted_spkis: &[&[u8]],
) -> Result<(), ErrorExt> {
    if distrusted_spkis.contains(&cert.spki.value().as_slice_less_safe()) {
        return Err(ErrorExt::CertDistrusted);
    }

    let used_as_ca = used_as_ca(&cert.ee_or_ca);

    check_issuer_independent_properties(
        cert,
        time,
        used_as_ca,
        sub_ca_count,
        required_eku_if_present,
    )?;

    // TODO: HPKP checks.

    match used_as_ca {
        UsedAsCa::Yes => {
            const MAX_SUB_CA_COUNT: usize = 6;

            if sub_ca_count >= MAX_SUB_CA_COUNT {
                return Err(Error::UnknownIssuer.into());
            }
        }
        UsedAsCa::No => {
            assert_eq!(0, sub_ca_count);
        }
    }

    // TODO: revocation.

    #[allow(clippy::blocks_in_conditions)]
    match loop_while_non_fatal_error(trust_anchors, |trust_anchor: &TrustAnchor| {
        let trust_anchor_subject = untrusted::Input::from(trust_anchor.subject);
        if !equal(cert.issuer, trust_anchor_subject) {
            return Err(Error::UnknownIssuer.into());
        }

        let trust_anchor_spki = untrusted::Input::from(trust_anchor.spki);

        if distrusted_spkis.contains(&trust_anchor.spki) {
            return Err(ErrorExt::CertDistrusted);
        }

        check_signatures(supported_sig_algs, cert, trust_anchor_spki, budget)?;

        check_signed_chain_name_constraints(cert, trust_anchor)?;

        Ok(())
    }) {
        Ok(()) => {
            return Ok(());
        }
        Err(e) => {
            if e.is_fatal() {
                return Err(e);
            }
            // If the error is not fatal, then keep going.
        }
    }

    loop_while_non_fatal_error(intermediate_certs, |cert_der| {
        let potential_issuer =
            cert::parse_cert(untrusted::Input::from(cert_der), EndEntityOrCa::Ca(cert))?;

        if !equal(potential_issuer.subject, cert.issuer) {
            return Err(Error::UnknownIssuer.into());
        }

        // Prevent loops; see RFC 4158 section 5.2.
        let mut prev = cert;
        loop {
            if equal(potential_issuer.spki.value(), prev.spki.value())
                && equal(potential_issuer.subject, prev.subject)
            {
                return Err(Error::UnknownIssuer.into());
            }
            match &prev.ee_or_ca {
                EndEntityOrCa::EndEntity => {
                    break;
                }
                EndEntityOrCa::Ca(child_cert) => {
                    prev = child_cert;
                }
            }
        }

        let next_sub_ca_count = match used_as_ca {
            UsedAsCa::No => sub_ca_count,
            UsedAsCa::Yes => sub_ca_count + 1,
        };

        budget.consume_build_chain_call()?;
        build_chain_inner(
            required_eku_if_present,
            supported_sig_algs,
            trust_anchors,
            intermediate_certs,
            &potential_issuer,
            time,
            next_sub_ca_count,
            budget,
            distrusted_spkis,
        )
    })
}

fn check_signatures(
    supported_sig_algs: &[&SignatureAlgorithm],
    cert_chain: &Cert,
    trust_anchor_key: untrusted::Input,
    budget: &mut Budget,
) -> Result<(), ErrorExt> {
    let mut spki_value = trust_anchor_key;
    let mut cert = cert_chain;
    loop {
        budget.consume_signature()?;
        signed_data::verify_signed_data(supported_sig_algs, spki_value, &cert.signed_data)?;

        // TODO: check revocation

        match &cert.ee_or_ca {
            EndEntityOrCa::Ca(child_cert) => {
                spki_value = cert.spki.value();
                cert = child_cert;
            }
            EndEntityOrCa::EndEntity => {
                break;
            }
        }
    }

    Ok(())
}

fn check_signed_chain_name_constraints(
    cert_chain: &Cert,
    trust_anchor: &TrustAnchor,
) -> Result<(), Error> {
    let mut cert = cert_chain;
    let mut name_constraints = trust_anchor.name_constraints.map(untrusted::Input::from);

    loop {
        untrusted::read_all_optional(name_constraints, Error::BadDer, |value| {
            name::check_name_constraints(value, cert)
        })?;

        match &cert.ee_or_ca {
            EndEntityOrCa::Ca(child_cert) => {
                name_constraints = cert.name_constraints;
                cert = child_cert;
            }
            EndEntityOrCa::EndEntity => {
                break;
            }
        }
    }

    Ok(())
}

fn check_issuer_independent_properties(
    cert: &Cert,
    time: time::Time,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
    required_eku_if_present: KeyPurposeId,
) -> Result<(), Error> {
    // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;
    // TODO: Check signature algorithm like mozilla::pkix.
    // TODO: Check SPKI like mozilla::pkix.
    // TODO: check for active distrust like mozilla::pkix.

    // See the comment in `remember_extension` for why we don't check the
    // KeyUsage extension.

    cert.validity
        .read_all(Error::BadDer, |value| check_validity(value, time))?;
    untrusted::read_all_optional(cert.basic_constraints, Error::BadDer, |value| {
        check_basic_constraints(value, used_as_ca, sub_ca_count)
    })?;
    untrusted::read_all_optional(cert.eku, Error::BadDer, |value| {
        check_eku(value, required_eku_if_present)
    })?;

    Ok(())
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
fn check_validity(input: &mut untrusted::Reader, time: time::Time) -> Result<(), Error> {
    let not_before = der::time_choice(input)?;
    let not_after = der::time_choice(input)?;

    if not_before > not_after {
        return Err(Error::InvalidCertValidity);
    }
    if time < not_before {
        return Err(Error::CertNotValidYet);
    }
    if time > not_after {
        return Err(Error::CertExpired);
    }

    // TODO: mozilla::pkix allows the TrustDomain to check not_before and
    // not_after, to enforce things like a maximum validity period. We should
    // do something similar.

    Ok(())
}

#[derive(Clone, Copy)]
enum UsedAsCa {
    Yes,
    No,
}

fn used_as_ca(ee_or_ca: &EndEntityOrCa) -> UsedAsCa {
    match ee_or_ca {
        EndEntityOrCa::EndEntity => UsedAsCa::No,
        EndEntityOrCa::Ca(..) => UsedAsCa::Yes,
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
fn check_basic_constraints(
    input: Option<&mut untrusted::Reader>,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
) -> Result<(), Error> {
    let (is_ca, path_len_constraint) = match input {
        Some(input) => {
            let is_ca = der::optional_boolean(input)?;

            // https://bugzilla.mozilla.org/show_bug.cgi?id=985025: RFC 5280
            // says that a certificate must not have pathLenConstraint unless
            // it is a CA certificate, but some real-world end-entity
            // certificates have pathLenConstraint.
            let path_len_constraint = if !input.at_end() {
                let value = der::small_nonnegative_integer(input)?;
                Some(usize::from(value))
            } else {
                None
            };

            (is_ca, path_len_constraint)
        }
        None => (false, None),
    };

    match (used_as_ca, is_ca, path_len_constraint) {
        (UsedAsCa::No, true, _) => Err(Error::CaUsedAsEndEntity),
        (UsedAsCa::Yes, false, _) => Err(Error::EndEntityUsedAsCa),
        (UsedAsCa::Yes, true, Some(len)) if sub_ca_count > len => {
            Err(Error::PathLenConstraintViolated)
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Copy)]
pub struct KeyPurposeId {
    oid_value: untrusted::Input<'static>,
}

// id-pkix            OBJECT IDENTIFIER ::= { 1 3 6 1 5 5 7 }
// id-kp              OBJECT IDENTIFIER ::= { id-pkix 3 }

// id-kp-serverAuth   OBJECT IDENTIFIER ::= { id-kp 1 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub static EKU_SERVER_AUTH: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 1]),
};

// id-kp-clientAuth   OBJECT IDENTIFIER ::= { id-kp 2 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub static EKU_CLIENT_AUTH: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 2]),
};

// id-kp-OCSPSigning  OBJECT IDENTIFIER ::= { id-kp 9 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub static EKU_OCSP_SIGNING: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 9]),
};

// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// Notable Differences from RFC 5280:
//
// * We follow the convention established by Microsoft's implementation and
//   mozilla::pkix of treating the EKU extension in a CA certificate as a
//   restriction on the allowable EKUs for certificates issued by that CA. RFC
//   5280 doesn't prescribe any meaning to the EKU extension when a certificate
//   is being used as a CA certificate.
//
// * We do not recognize anyExtendedKeyUsage. NSS and mozilla::pkix do not
//   recognize it either.
//
// * We treat id-Netscape-stepUp as being equivalent to id-kp-serverAuth in CA
//   certificates (only). Comodo has issued certificates that require this
//   behavior that don't expire until June 2020. See https://bugzilla.mozilla.org/show_bug.cgi?id=982292.
fn check_eku(
    input: Option<&mut untrusted::Reader>,
    required_eku_if_present: KeyPurposeId,
) -> Result<(), Error> {
    match input {
        Some(input) => {
            loop {
                let value = der::expect_tag_and_get_value(input, der::Tag::OID)?;
                if equal(value, required_eku_if_present.oid_value) {
                    input.skip_to_end();
                    break;
                }
                if input.at_end() {
                    return Err(Error::RequiredEkuNotFound);
                }
            }
            Ok(())
        }
        None => {
            // http://tools.ietf.org/html/rfc6960#section-4.2.2.2:
            // "OCSP signing delegation SHALL be designated by the inclusion of
            // id-kp-OCSPSigning in an extended key usage certificate extension
            // included in the OCSP response signer's certificate."
            //
            // A missing EKU extension generally means "any EKU", but it is
            // important that id-kp-OCSPSigning is explicit so that a normal
            // end-entity certificate isn't able to sign trusted OCSP responses
            // for itself or for other certificates issued by its issuing CA.
            if equal(
                required_eku_if_present.oid_value,
                EKU_OCSP_SIGNING.oid_value,
            ) {
                return Err(Error::RequiredEkuNotFound);
            }

            Ok(())
        }
    }
}

fn loop_while_non_fatal_error<V>(
    values: V,
    mut f: impl FnMut(V::Item) -> Result<(), ErrorExt>,
) -> Result<(), ErrorExt>
where
    V: IntoIterator,
{
    for v in values {
        match f(v) {
            Ok(()) => {
                return Ok(());
            }
            Err(e) => {
                if e.is_fatal() {
                    return Err(e);
                }
                // If the error is not fatal, then keep going.
            }
        }
    }
    Err(Error::UnknownIssuer.into())
}

// Backported from rustls/webpki#546 (RUSTSEC-2026-0382). These are the
// contents of SPKI SEQUENCEs, without their DER tag/length. Reject by key at
// every path position, including explicitly configured trust anchors.
const DISTRUSTED_SPKIS: &[&[u8]] = &[
    include_bytes!("data/distrusted/EMDVTLSCAG3B.spki.der"),
    include_bytes!("data/distrusted/EMDVTLSCAG3C.spki.der"),
    include_bytes!("data/distrusted/EMEVTLSCAG3B.spki.der"),
    include_bytes!("data/distrusted/EMEVTLSCAG3C.spki.der"),
    include_bytes!("data/distrusted/EMOVTLSCAG3B.spki.der"),
    include_bytes!("data/distrusted/EMOVTLSCAG3C.spki.der"),
    include_bytes!("data/distrusted/EMOVCSCAG3B.spki.der"),
    include_bytes!("data/distrusted/EMOVCSCAG3C.spki.der"),
];

#[cfg(test)]
mod distrust_tests {
    use super::*;
    use crate::{EndEntityCert, TlsServerTrustAnchors, ECDSA_P256_SHA256};
    use core::convert::TryFrom;

    const ROOT: &[u8] = include_bytes!("data/distrusted/tests/root.der");
    const ISSUER: &[u8] = include_bytes!("data/distrusted/tests/issuer.der");
    const INTERMEDIATE: &[u8] = include_bytes!("data/distrusted/tests/intermediate.der");
    const CROSS_SIGNED: &[u8] = include_bytes!("data/distrusted/tests/cross-signed.der");
    const UNRELATED: &[u8] = include_bytes!("data/distrusted/tests/unrelated.der");
    const LEAF: &[u8] = include_bytes!("data/distrusted/tests/leaf.der");
    fn now() -> time::Time {
        time::Time::from_seconds_since_unix_epoch(1_800_000_000)
    }

    fn verify(
        leaf: &[u8],
        intermediates: &[&[u8]],
        roots: &[TrustAnchor],
        distrust: &[&[u8]],
    ) -> Result<(), ErrorExt> {
        let cert = EndEntityCert::try_from(leaf).unwrap();
        build_chain_inner(
            EKU_SERVER_AUTH,
            &[&ECDSA_P256_SHA256],
            roots,
            intermediates,
            cert.inner(),
            now(),
            0,
            &mut Budget::default(),
            distrust,
        )
    }

    #[test]
    fn distrust_rejects_every_path_position_and_cross_sign() {
        let roots = &[TrustAnchor::try_from_cert_der(ROOT).unwrap()];
        let intermediates = &[INTERMEDIATE, ISSUER, UNRELATED];
        assert!(verify(LEAF, intermediates, roots, &[]).is_ok());
        for der in [ROOT, ISSUER, INTERMEDIATE, LEAF] {
            let anchor = TrustAnchor::try_from_cert_der(der).unwrap();
            assert!(verify(LEAF, intermediates, roots, &[anchor.spki]).is_err());
        }

        let unrelated = TrustAnchor::try_from_cert_der(UNRELATED).unwrap();
        assert!(verify(LEAF, intermediates, roots, &[unrelated.spki]).is_ok());

        let cross_signed = &[INTERMEDIATE, ISSUER, CROSS_SIGNED];
        let issuer = TrustAnchor::try_from_cert_der(ISSUER).unwrap();
        assert!(verify(LEAF, cross_signed, roots, &[issuer.spki]).is_ok());
        let intermediate = TrustAnchor::try_from_cert_der(INTERMEDIATE).unwrap();
        assert!(verify(LEAF, cross_signed, roots, &[intermediate.spki]).is_err());

        // No issuer is needed to reject a distrusted path node.
        let leaf = TrustAnchor::try_from_cert_der(LEAF).unwrap();
        assert!(matches!(
            verify(LEAF, &[], &[], &[leaf.spki]),
            Err(ErrorExt::CertDistrusted)
        ));
    }

    #[test]
    fn distrust_real_emsign_public_keys_in_valid_chains() {
        let roots = &[TrustAnchor::try_from_cert_der(ROOT).unwrap()];
        let leaves: &[&[u8]] = &[
            include_bytes!("data/distrusted/tests/EMDVTLSCAG3B.der"),
            include_bytes!("data/distrusted/tests/EMDVTLSCAG3C.der"),
            include_bytes!("data/distrusted/tests/EMEVTLSCAG3B.der"),
            include_bytes!("data/distrusted/tests/EMEVTLSCAG3C.der"),
            include_bytes!("data/distrusted/tests/EMOVTLSCAG3B.der"),
            include_bytes!("data/distrusted/tests/EMOVTLSCAG3C.der"),
            include_bytes!("data/distrusted/tests/EMOVCSCAG3B.der"),
            include_bytes!("data/distrusted/tests/EMOVCSCAG3C.der"),
        ];
        assert_eq!(leaves.len(), DISTRUSTED_SPKIS.len());
        for leaf in leaves {
            // A real CA signature makes each leaf valid without the backport.
            assert!(verify(leaf, &[], roots, &[]).is_ok());
            let cert = EndEntityCert::try_from(*leaf).unwrap();
            assert!(matches!(
                cert.verify_is_valid_tls_server_cert_ext(
                    &[&ECDSA_P256_SHA256], &TlsServerTrustAnchors(roots), &[], now(),
                ),
                Err(ErrorExt::CertDistrusted)
            ));
            // Old rustls uses this API: it must also reject, without changing Error.
            assert_eq!(
                cert.verify_is_valid_tls_server_cert(
                    &[&ECDSA_P256_SHA256], &TlsServerTrustAnchors(roots), &[], now(),
                ),
                Err(Error::UnknownIssuer)
            );
        }
    }
}
