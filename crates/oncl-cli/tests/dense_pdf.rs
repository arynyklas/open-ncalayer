//! `oncl sign/verify --profile pdf` of dense documents (many objects/pages, object and
//! cross-reference streams, several revisions): the object count of a real document is
//! not a metadata ceiling (D4/D6), while a lying or hostile cross-reference table is
//! refused before any key use.
#[path = "../../oncl-pdf/tests/support/dense_gen.rs"]
mod dense_gen;
mod support;
use std::{path::Path, time::Instant};
use support::*;

fn trust(w: &World) -> Vec<&str> {
    vec![
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ]
}
fn sign(w: &World, input: &Path, output: &Path) -> std::process::Output {
    let mut args = vec![
        "sign",
        "--profile",
        "pdf",
        "--input",
        path(input),
        "--output",
        path(output),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    args.extend(trust(w));
    run(&args, b"")
}
fn verify(w: &World, input: &Path) -> std::process::Output {
    let mut args = vec![
        "verify",
        "--profile",
        "pdf",
        "--input",
        path(input),
        "--json",
    ];
    args.extend(trust(w));
    run(&args, b"")
}

#[test]
fn oncl_signs_and_verifies_dense_documents_far_past_the_object_ceiling() {
    let w = world();
    for (name, doc) in [
        ("classic x3", dense_gen::classic(20_000, 3)),
        ("stream x3", dense_gen::streamed(20_000, 3, true)),
    ] {
        let input = w.dir.path().join("dense.pdf");
        let output = w.dir.path().join("dense.signed.pdf");
        std::fs::write(&input, &doc.bytes).unwrap();
        let signed = sign(&w, &input, &output);
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let valid = verify(&w, &output);
        assert_eq!(valid.status.code(), Some(0), "{name}: {valid:?}");
        let bytes = std::fs::read(&output).unwrap();
        assert!(bytes.starts_with(&doc.bytes), "{name}: incremental update");
        std::fs::remove_file(&output).unwrap();
    }
}

#[test]
fn oncl_refuses_a_lying_cross_reference_table_before_key_use_and_quickly() {
    let w = world();
    let input = w.dir.path().join("lying.pdf");
    let output = w.dir.path().join("lying.signed.pdf");
    let started = Instant::now();
    for (name, bytes) in [
        (
            "declares billions of entries",
            dense_gen::classic_with_table("0 4000000000\n0000000000 65535 f \n"),
        ),
        (
            "declares millions with no rows behind",
            dense_gen::classic_with_table("0 4000000\n0000000000 65535 f \n"),
        ),
    ] {
        std::fs::write(&input, bytes).unwrap();
        let refused = sign(&w, &input, &output);
        assert_eq!(refused.status.code(), Some(1), "{name}: {refused:?}");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(stderr.contains("applied=NotApplied"), "{name}: {stderr}");
        assert!(!output.exists(), "{name}: nothing may be published");
    }
    assert!(started.elapsed().as_secs() < 60, "{:?}", started.elapsed());
}

/// Measurement hook, not a regression test: signs the PDF named by `ONCL_DENSE_PDF`
/// (for example one made by `scripts/pdf-dense/gen_dense_pdf.py`) and verifies it.
#[test]
#[ignore = "measurement: set ONCL_DENSE_PDF"]
fn external_dense_pdf_signs_and_verifies() {
    let input = std::path::PathBuf::from(std::env::var("ONCL_DENSE_PDF").expect("ONCL_DENSE_PDF"));
    let w = world();
    let output = w.dir.path().join("external.signed.pdf");
    let started = Instant::now();
    let signed = sign(&w, &input, &output);
    eprintln!(
        "sign: {:?} in {:?}",
        signed.status.code(),
        started.elapsed()
    );
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let started = Instant::now();
    let valid = verify(&w, &output);
    eprintln!(
        "verify: {:?} in {:?}",
        valid.status.code(),
        started.elapsed()
    );
    assert_eq!(valid.status.code(), Some(0), "{valid:?}");
    if let Ok(keep) = std::env::var("ONCL_DENSE_PDF_OUT") {
        std::fs::copy(&output, keep).unwrap();
    }
}
