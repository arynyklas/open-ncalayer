//! Real `oncl batch` processes: mixed ordered items, exits 0/2/3/4, observable
//! hash digests, owned-output publication and honest per-item private-use
//! state. Real Ctrl-Break (130) and deadline (4) are in `batch_signal.rs`.
mod support;
use serde_json::json;
use support::*;

fn manifest(w: &World, value: serde_json::Value) -> std::path::PathBuf {
    let path = w.dir.path().join("batch.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}
fn args<'a>(w: &'a World, manifest: &'a std::path::Path) -> Vec<&'a str> {
    vec![
        "batch",
        "run",
        "--manifest",
        path(manifest),
        "--key",
        path(&w.rsa_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--json",
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ]
}
#[test]
fn mixed_batch_signs_verifies_and_retains_completed_outputs_when_a_later_item_is_bad() {
    let w = world();
    let (a, b) = (w.dir.path().join("a.bin"), w.dir.path().join("b.bin"));
    std::fs::write(&a, b"first document").unwrap();
    std::fs::write(&b, b"second document").unwrap();
    let (sig_a, sig_b) = (w.dir.path().join("a.der"), w.dir.path().join("b.der"));
    let missing = w.dir.path().join("missing.bin");
    let m = manifest(
        &w,
        json!({"items":[
            {"op":"hash","id":"h","algorithm":"sha256","input":a},
            {"op":"sign","id":"sa","profile":"cms-detached","input":a,"output":sig_a},
            {"op":"sign","id":"bad","profile":"cms","input":missing,"output":w.dir.path().join("bad.der")},
            {"op":"sign","id":"sb","profile":"cms-detached","input":b,"output":sig_b},
        ]}),
    );
    let result = run(&args(&w, &m), b"");
    // A batch output may never feed another item of the same approved composition.
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap_or_default();
    let items = report["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{result:?}"));
    let status = |id: &str| {
        items.iter().find(|i| i["id"] == id).unwrap()["status"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(status("h"), "Completed");
    // The hash item's digest is observable and equals the independent SHA-256
    // of the exact file bytes (computed with Python hashlib).
    let hash_row = items.iter().find(|i| i["id"] == "h").unwrap();
    assert_eq!(hash_row["digest"]["algorithm"], "sha256");
    assert_eq!(
        hash_row["digest"]["hex"],
        "c12b830cf529be550d6510a49374625759c70b6d6ca04f448387845e5ec88f44"
    );

    assert_eq!(
        status("sa"),
        "Completed",
        "{report}\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(status("bad"), "Failed");
    assert_eq!(
        status("sb"),
        "Completed",
        "a local bad source does not stop healthy later items: {report}"
    );
    assert_eq!(result.status.code(), Some(4), "{result:?}");
    // Completed outputs are kept; the failed item published nothing.
    assert!(sig_a.exists() && sig_b.exists() && !w.dir.path().join("bad.der").exists());
    for (signature, document) in [(&sig_a, &a), (&sig_b, &b)] {
        let verify = run(
            &[
                "verify",
                "--profile",
                "cms",
                "--input",
                path(signature),
                "--detached",
                path(document),
                "--root",
                path(&w.root),
                "--pki-endpoint",
                &w.origin,
                "--as-of",
                "1793620800",
            ],
            b"",
        );
        assert_eq!(verify.status.code(), Some(0), "{verify:?}");
    }
    assert_eq!(
        items.iter().find(|i| i["id"] == "sa").unwrap()["published"],
        true
    );
    assert_eq!(
        items.iter().find(|i| i["id"] == "bad").unwrap()["published"],
        false
    );
    let text = String::from_utf8_lossy(&result.stderr);
    assert_eq!(
        text.matches("applied=Applied succeeded=true").count(),
        2,
        "{text}"
    );
}
#[test]
fn clean_batch_exits_by_worst_verification_and_manifest_errors_precede_all_io() {
    let w = world();
    let doc = w.dir.path().join("doc.bin");
    std::fs::write(&doc, b"abc").unwrap();
    let sig = w.dir.path().join("doc.der");
    assert_eq!(
        run(
            &[
                "sign",
                "--profile",
                "cms",
                "--detached",
                "--input",
                path(&doc),
                "--output",
                path(&sig),
                "--key",
                path(&w.rsa_key),
                "--secret-file",
                path(&w.secret),
                "--authorize",
                "--root",
                path(&w.root),
                "--pki-endpoint",
                &w.origin,
                "--as-of",
                "1793620800"
            ],
            b""
        )
        .status
        .code(),
        Some(0)
    );
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&altered, b"abd").unwrap();
    let valid = manifest(
        &w,
        json!({"items":[{"op":"verify","id":"v","input":sig,"detached":doc}]}),
    );
    let a: Vec<&str> = {
        let mut out = Vec::new();
        let mut skip = false;
        for x in args(&w, &valid) {
            if skip {
                skip = false;
                continue;
            }
            if x == "--key" || x == "--secret-file" {
                skip = true;
                continue;
            }
            out.push(x);
        }
        out
    };
    assert_eq!(run(&a, b"").status.code(), Some(0));
    let invalid = manifest(
        &w,
        json!({"items":[{"op":"verify","id":"v","input":sig,"detached":altered}]}),
    );
    let mut b = a.clone();
    b[3] = path(&invalid);
    assert_eq!(run(&b, b"").status.code(), Some(2));
    // Duplicate ids, unknown fields, and existing destinations fail before any source/key I/O.
    let existing = w.dir.path().join("existing.out");
    std::fs::write(&existing, b"keep").unwrap();
    for bad in [
        json!({"items":[{"op":"hash","id":"x","algorithm":"sha256","input":doc},{"op":"hash","id":"x","algorithm":"sha256","input":doc}]}),
        json!({"items":[{"op":"hash","id":"x","algorithm":"sha256","input":doc,"surprise":1}]}),
        json!({"items":[{"op":"extract","id":"x","input":sig,"output":existing}]}),
        json!({"items":[{"op":"hash","id":"x","algorithm":"sha256","input":"-"}]}),
    ] {
        let m = manifest(&w, bad);
        let mut c = a.clone();
        c[3] = path(&m);
        let result = run(&c, b"");
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains("private_use"));
    }
    assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
}

fn keyless<'a>(w: &'a World, manifest: &'a std::path::Path, extra: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut skip = false;
    for x in args(w, manifest) {
        if skip {
            skip = false;
            continue;
        }
        if matches!(x, "--key" | "--secret-file") {
            skip = true;
            continue;
        }
        out.push(x);
    }
    out.extend(extra);
    out
}
#[test]
fn batch_exit_is_the_worst_of_valid_indeterminate_invalid_and_incomplete_outranks() {
    let w = world();
    let doc = w.dir.path().join("doc.bin");
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&doc, b"abc").unwrap();
    std::fs::write(&altered, b"abd").unwrap();
    let sig = w.dir.path().join("doc.der");
    let signed = run(
        &[
            "sign",
            "--profile",
            "cms",
            "--detached",
            "--input",
            path(&doc),
            "--output",
            path(&sig),
            "--key",
            path(&w.rsa_key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
            "--root",
            path(&w.root),
            "--pki-endpoint",
            &w.origin,
            "--as-of",
            "1793620800",
        ],
        b"",
    );
    assert_eq!(signed.status.code(), Some(0));
    let good = json!({"op":"verify","id":"good","input":sig,"detached":doc});
    let bad = json!({"op":"verify","id":"bad","input":sig,"detached":altered});
    let missing =
        json!({"op":"verify","id":"gone","input":w.dir.path().join("none.der"),"detached":doc});
    let hash = json!({"op":"hash","id":"hash","algorithm":"sha256","input":doc});
    let exit = |items: Vec<serde_json::Value>, extra: &[&str]| {
        let m = manifest(&w, json!({ "items": items }));
        let result = run(&keyless(&w, &m, extra), b"");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap_or_default();
        (result.status.code(), report)
    };
    // Strict online: Valid 0; one Invalid makes 2.
    assert_eq!(exit(vec![hash.clone(), good.clone()], &[]).0, Some(0));
    assert_eq!(exit(vec![good.clone(), bad.clone()], &[]).0, Some(2));
    // Offline: every verification is Indeterminate (3); Invalid still outranks it.
    let (code, report) = exit(vec![good.clone(), hash.clone()], &["--offline"]);
    assert_eq!(code, Some(3), "{report}");
    assert_eq!(report["items"][0]["verdict"], "Indeterminate");
    assert_eq!(
        exit(vec![good.clone(), bad.clone()], &["--offline"]).0,
        Some(2)
    );
    assert_eq!(
        exit(vec![bad.clone(), good.clone()], &["--offline"]).0,
        Some(2)
    );
    // A failed item makes the batch incomplete (4), outranking Invalid and Indeterminate.
    assert_eq!(exit(vec![bad.clone(), missing.clone()], &[]).0, Some(4));
    assert_eq!(
        exit(vec![good.clone(), missing.clone()], &["--offline"]).0,
        Some(4)
    );
}
#[test]
fn publication_failure_after_private_use_is_applied_unpublished_and_leaves_the_destination() {
    let w = world();
    let (a, b) = (w.dir.path().join("a.bin"), w.dir.path().join("b.bin"));
    std::fs::write(&a, b"first document").unwrap();
    std::fs::write(&b, b"second document").unwrap();
    let out = w.dir.path().join("x.der");
    // Two spellings of one destination are lexically distinct, so the whole
    // manifest is admitted; the second no-clobber publication must then fail
    // after its key use, without touching what the first published.
    std::fs::create_dir(w.dir.path().join("sub")).unwrap();
    let alias = w.dir.path().join("sub").join("..").join("x.der");
    let m = manifest(
        &w,
        json!({"items":[
            {"op":"sign","id":"one","profile":"cms-detached","input":a,"output":out},
            {"op":"sign","id":"two","profile":"cms-detached","input":b,"output":alias},
        ]}),
    );
    let result = run(&args(&w, &m), b"");
    assert_eq!(result.status.code(), Some(4), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let row = |id: &str| {
        report["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(row("one")["status"], "Completed");
    assert_eq!(row("one")["published"], true);
    assert_eq!(row("two")["status"], "Failed", "{report}");
    assert_eq!(row("two")["applied"], "Applied", "{report}");
    assert_eq!(row("two")["published"], false);
    let text = String::from_utf8_lossy(&result.stderr);
    assert_eq!(
        text.matches("applied=Applied succeeded=true").count(),
        2,
        "{text}"
    );
    // The destination still holds item one's signature over document a.
    let verify = |document: &std::path::Path| {
        run(
            &[
                "verify",
                "--profile",
                "cms",
                "--input",
                path(&out),
                "--detached",
                path(document),
                "--root",
                path(&w.root),
                "--pki-endpoint",
                &w.origin,
                "--as-of",
                "1793620800",
            ],
            b"",
        )
        .status
        .code()
    };
    assert_eq!(verify(&a), Some(0));
    assert_eq!(verify(&b), Some(2));
}
#[test]
fn batch_human_output_lists_every_item_and_its_digest() {
    let w = world();
    let doc = w.dir.path().join("doc.bin");
    std::fs::write(&doc, b"first document").unwrap();
    let m = manifest(
        &w,
        json!({"items":[{"op":"hash","id":"h","algorithm":"sha256","input":doc}]}),
    );
    let mut a = keyless(&w, &m, &[]);
    a.retain(|x| *x != "--json");
    let result = run(&a, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(text.starts_with("1/1 items completed\n"), "{text}");
    assert!(
        text.contains(
            "h: Completed sha256 c12b830cf529be550d6510a49374625759c70b6d6ca04f448387845e5ec88f44"
        ),
        "{text}"
    );
}
#[test]
fn manifest_from_stdin_cannot_share_stdin_with_an_interactive_secret() {
    let w = world();
    let result = run(
        &[
            "batch",
            "run",
            "--manifest",
            "-",
            "--key",
            path(&w.rsa_key),
            "--secret-interactive",
            "--authorize",
        ],
        b"{}",
    );
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("SecretRequiresSeparateInput"));
}
