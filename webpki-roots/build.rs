use std::{env, fmt::Write, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut output = String::from(
        "pub static TLS_SERVER_ROOTS: webpki::TlsServerTrustAnchors<'static> = \
         webpki::TlsServerTrustAnchors(&[\n",
    );
    for anchor in modern_roots::TLS_SERVER_ROOTS {
        let constraints = match &anchor.name_constraints {
            Some(value) => format!("Some(&{:?})", value.as_ref()),
            None => String::from("None"),
        };
        writeln!(
            output,
            "webpki::TrustAnchor {{ subject: &{:?}, spki: &{:?}, name_constraints: {} }},",
            anchor.subject.as_ref(),
            anchor.subject_public_key_info.as_ref(),
            constraints,
        ).unwrap();
    }
    output.push_str("]);\n");
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("roots.rs"), output).unwrap();
}
