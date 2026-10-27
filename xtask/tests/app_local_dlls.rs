//! The import gate against the app-local DLLs built from this workspace: the imports the
//! `windows` crates make of `combase.dll` and `api-ms-win-core-winrt-error-l1-1-0.dll` pass
//! next to them, other names do not, and the forwards stay in `ole32.dll` (Windows only).

#![cfg(windows)]

use std::path::Path;
use std::sync::LazyLock;

use oncl_testkit::dll::build_cdylib;
use xtask::imports::{AppLocalDll, Image, Import, app_local_violations, read_image, violations};

/// The app-local DLLs, built for the host target, under their shipping names.
static BUILT: LazyLock<[AppLocalDll; 2]> = LazyLock::new(|| {
    let build = |package, name| {
        let dll = build_cdylib(package, Path::new(env!("CARGO_TARGET_TMPDIR")));
        AppLocalDll {
            name,
            image: read_image(&std::fs::read(dll).unwrap()).unwrap(),
        }
    };
    [
        build("oncl-win7shim-combase", "combase.dll"),
        build(
            "oncl-win7shim-winrt-error",
            "api-ms-win-core-winrt-error-l1-1-0.dll",
        ),
    ]
});

fn imp(dll: &str, symbol: &str) -> Import {
    Import {
        dll: dll.to_owned(),
        symbol: Some(symbol.to_owned()),
    }
}

#[test]
fn windows_crate_imports_pass_next_to_the_built_dlls() {
    let exe = Image {
        pe64: cfg!(target_pointer_width = "64"),
        imports: vec![
            imp("combase.dll", "CoTaskMemFree"),
            imp("combase.dll", "CoCreateFreeThreadedMarshaler"),
            imp(
                "api-ms-win-core-winrt-error-l1-1-0.dll",
                "RoOriginateErrorW",
            ),
            imp("combase.dll", "CoTaskMemAlloc"),
        ],
        exports: Vec::new(),
    };
    assert_eq!(
        violations(&exe, &*BUILT),
        ["combase.dll!CoTaskMemAlloc: the app-local combase.dll does not export it"]
    );
}

#[test]
fn built_forwards_stay_in_ole32() {
    let mut combase = BUILT[0].clone();
    let forwards = combase
        .image
        .exports
        .iter()
        .filter_map(|export| export.forward.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        forwards,
        [
            imp("ole32.dll", "CoCreateFreeThreadedMarshaler"),
            imp("ole32.dll", "CoTaskMemFree"),
        ]
    );
    // A test build links the CRT dynamically; `cargo xtask win7` checks the imports of the
    // release builds with the static CRT.
    combase.image.imports.clear();
    assert_eq!(app_local_violations(&combase), Vec::<String>::new());
}
