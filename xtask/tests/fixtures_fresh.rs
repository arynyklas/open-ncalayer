//! The committed synthetic PKI (`fixtures/synthetic/`) matches `cargo xtask gen-fixtures` and
//! is usable: every container opens and chains to its root.

use oncl_pki::{cert, pkcs12};
use oncl_testkit::{read, synthetic_all, workspace_root};

#[test]
fn committed_fixtures_are_fresh() {
    assert!(
        xtask::fixtures::check(&workspace_root()).unwrap(),
        "fixtures/synthetic is stale: run `cargo xtask gen-fixtures`"
    );
}

#[test]
fn every_p12_loads_and_chains_to_its_root() {
    let all = synthetic_all();
    assert_eq!(all.len(), 10);
    for f in all {
        let entries =
            pkcs12::load(&read(&f.path), &f.password).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        let aliases: Vec<&str> = entries.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(aliases, f.aliases, "{}", f.name);
        let root = cert::parse(&read(&f.root)).unwrap();
        for entry in &entries {
            cert::verify_signature(&entry.cert, &root)
                .unwrap_or_else(|e| panic!("{} / {}: {e}", f.name, entry.alias));
        }
    }
    let multi = oncl_testkit::synthetic("multi-gost2015");
    assert_eq!(multi.aliases.len(), 2);
}
