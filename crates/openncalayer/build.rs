//! Gives the program the git commit it is built from (`ONCL_GIT_COMMIT`, `unknown` outside
//! a git checkout), for the About window, and embeds the built-in modules' WebAssembly
//! (`$OUT_DIR/builtins.rs`): taken from `ONCL_BUILTINS_DIR` if it is set, else built.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Err(e) = oncl_builtins_build::embed(&workspace) {
        panic!("the built-in modules: {e}");
    }
    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=ONCL_GIT_COMMIT={commit}");
    // A commit, checkout or reset moves HEAD or the branch it names, and is written to
    // HEAD's reflog even when the branch's ref is packed.
    let mut watched = vec![
        "HEAD".to_owned(),
        "logs/HEAD".to_owned(),
        "packed-refs".to_owned(),
    ];
    watched.extend(git(&["symbolic-ref", "-q", "HEAD"]));
    for name in watched {
        if let Some(path) = git(&["rev-parse", "--git-path", &name])
            && Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

/// The trimmed output of `git <args>`, if it succeeds.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (out.status.success() && !text.is_empty()).then(|| text.to_owned())
}
