//! Embeds the application manifest into the installer entry (`oncl-winget-setup.exe`).
//!
//! Without a manifest Windows treats a program whose file name says "setup" as a legacy
//! installer and asks for elevation (UAC) before it starts, although the entry installs
//! per user and refuses an elevated token (exit 8). The manifest says `asInvoker`, so it
//! starts with the caller's token. The MSVC linker writes the `RT_MANIFEST` resource itself
//! (`/MANIFEST:EMBED`); no resource compiler or extra dependency is needed.

use std::env;
use std::path::Path;

fn main() {
    let manifest = "windows/oncl-winget-setup.manifest";
    println!("cargo:rerun-if-changed={manifest}");
    println!("cargo:rerun-if-changed=build.rs");
    let windows_msvc = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows")
        && env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc");
    if !windows_msvc {
        return;
    }
    let dir = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let path = Path::new(&dir).join(manifest);
    let bin = "oncl-winget-setup";
    println!("cargo:rustc-link-arg-bin={bin}=/MANIFEST:EMBED");
    // The input carries its own trustInfo: the linker must not add a second one.
    println!("cargo:rustc-link-arg-bin={bin}=/MANIFESTUAC:NO");
    println!(
        "cargo:rustc-link-arg-bin={bin}=/MANIFESTINPUT:{}",
        path.display()
    );
}
