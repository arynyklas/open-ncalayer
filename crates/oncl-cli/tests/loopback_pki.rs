//! Not a test: a synthetic certification authority on loopback for native smoke runs of the
//! desktop's signing (a root, a signing key, an OCSP responder). Everything is generated here
//! and trusts nothing real. It runs until its stdin closes.
//!
//! `LOOPBACK_PKI_DIR=<directory> cargo test -p oncl-cli --test loopback_pki -- --ignored --nocapture`
mod support;

use std::io::Read;

#[test]
#[ignore = "a development tool for native smoke runs, not a check"]
fn serve_a_synthetic_authority_until_stdin_closes() {
    let target = std::env::var("LOOPBACK_PKI_DIR").expect("LOOPBACK_PKI_DIR");
    let w = support::world();
    std::fs::create_dir_all(&target).unwrap();
    let root = std::path::Path::new(&target).join("root.cer");
    let key = std::path::Path::new(&target).join("signing.p12");
    std::fs::copy(&w.root, &root).unwrap();
    std::fs::copy(&w.rsa_key, &key).unwrap();
    println!("root={}", root.display());
    println!("key={}", key.display());
    println!("password={}", support::PASSWORD);
    println!("origin={}", w.origin);
    println!("as_of={}", support::NOW_SECONDS);
    println!("ready");
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}
