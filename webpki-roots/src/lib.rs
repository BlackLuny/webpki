//! Compatibility for webpki 0.22 consumers, generated from webpki-roots >=1.0.10.
#![no_std]

include!(concat!(env!("OUT_DIR"), "/roots.rs"));

#[cfg(test)]
mod tests {
    use super::TLS_SERVER_ROOTS;

    #[test]
    fn legacy_api_has_current_roots_without_emsign_g3() {
        assert!(!TLS_SERVER_ROOTS.0.is_empty());
        let removed_name = b"emSign ECC Root CA - G3";
        assert!(!TLS_SERVER_ROOTS.0.iter().any(|anchor| {
            anchor.subject.windows(removed_name.len()).any(|name| name == removed_name)
        }));
    }
}
