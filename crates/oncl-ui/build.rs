//! Compiles the dialogs with their Kazakh and Russian translations bundled, and gives the
//! About window the git commit of the build (`ONCL_GIT_COMMIT`, `unknown` outside a git
//! checkout).

use std::process::Command;

use slint_build::{CompilerConfiguration, DefaultTranslationContext};

fn main() {
    let config = CompilerConfiguration::new()
        .with_bundled_translations("po")
        // The catalogs key strings by text alone: a string shared by both dialogs is
        // translated once.
        .with_default_translation_context(DefaultTranslationContext::None);
    if let Err(e) = slint_build::compile_with_config("ui/dialogs.slint", config) {
        panic!("{e}");
    }

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=ONCL_GIT_COMMIT={commit}");
    // A new commit or a checkout moves HEAD or the branch it names.
    let mut watched = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    watched.extend(git(&["symbolic-ref", "-q", "HEAD"]));
    for name in watched {
        if let Some(path) = git(&["rev-parse", "--git-path", &name])
            && std::path::Path::new(&path).exists()
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
