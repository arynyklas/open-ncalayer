//! Embeds the public keys of the update index, `keys/current.pub` and `keys/next.pub`, if
//! they are there: the maintainer adds them (`cargo xtask sign keygen`). A build without
//! them has no keys, and its updater is off.

use std::path::Path;

const KEYS: [&str; 2] = ["current.pub", "next.pub"];

fn main() {
    let dir = Path::new("keys");
    // A missing path would rerun the script on every build; until `keys/` exists, the
    // crate's directory is watched for it instead.
    if dir.is_dir() {
        println!("cargo:rerun-if-changed=keys");
    } else {
        println!("cargo:rerun-if-changed=.");
    }
    let mut keys = Vec::new();
    for name in KEYS {
        let path = dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(text) => keys.push(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("cannot read {}: {e}", path.display()),
        }
    }
    let out = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    let code = format!("&{keys:?}");
    std::fs::write(Path::new(&out).join("keys.rs"), code).expect("cannot write keys.rs");
}
