//! Exports of the DLL: the forwards of `combase.def`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=combase.def");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").expect("CARGO_CFG_TARGET_ENV");
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-cdylib-link-arg=/DEF:{dir}/combase.def");
    // link.exe resolves a forward `NAME=ole32.NAME` against the import libraries on its
    // command line and fails with LNK2001 unless ole32's is one of them. The export stays a
    // forward: the DLL does not import ole32.
    println!("cargo:rustc-cdylib-link-arg=ole32.lib");
}
