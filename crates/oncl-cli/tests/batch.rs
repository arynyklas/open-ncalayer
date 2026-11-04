//! Real `oncl batch` processes: mixed ordered items, exits 0/2/3/4/130,
//! owned-output publication and honest per-item private-use state.
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
    let mut a = args(&w, &valid);
    a.retain(|x| !matches!(*x, "--key" | "--secret-file"));
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
