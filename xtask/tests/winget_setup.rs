//! The WinGet installer entry as `cargo xtask package winget-setup` makes it: real programs
//! (this test's own executable stands for both the entry and `Setup.exe`; `build.rs` gives it
//! the entry's `asInvoker` manifest), read back the way the installer reads its payload.
#![cfg(windows)]

use oncl_update::Version;
use oncl_winget_setup::manifest;
use oncl_winget_setup::payload::{self, Arch};
use xtask::package::windows::{flavor, winget_setup, winget_setup_name};

fn this_flavor() -> &'static str {
    match Arch::this() {
        Some(Arch::X86) => "win-x86",
        _ => "win-x64",
    }
}

#[test]
fn the_entry_carries_exactly_the_setup_it_was_given() {
    let exe = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let version = Version::parse("0.2.0-alpha.1").unwrap();
    let flavor = flavor(this_flavor()).unwrap();
    let made = winget_setup(&exe, &exe, &version, &flavor, dir.path()).unwrap();
    assert_eq!(
        made.file_name().unwrap().to_string_lossy(),
        winget_setup_name(&version, &flavor)
    );
    assert!(
        made.file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("-winget-setup.exe")
    );
    let bytes = std::fs::read(&made).unwrap();
    let embedded = payload::read(&bytes).unwrap();
    assert_eq!(embedded.setup, std::fs::read(&exe).unwrap());
    assert_eq!(embedded.version, version);
    // An entry that already carries a payload takes no second one.
    assert!(winget_setup(&made, &exe, &version, &flavor, dir.path()).is_err());
}

#[test]
fn windows_7_flavors_and_the_other_architecture_get_none() {
    let exe = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let version = Version::parse("0.2.0").unwrap();
    for name in ["win7-x64", "win7-x86"] {
        let flavor = flavor(name).unwrap();
        let err = winget_setup(&exe, &exe, &version, &flavor, dir.path()).unwrap_err();
        assert!(err.to_string().contains("WinGet"), "{err}");
    }
    let other = flavor(if this_flavor() == "win-x64" {
        "win-x86"
    } else {
        "win-x64"
    })
    .unwrap();
    assert!(winget_setup(&exe, &exe, &version, &other, dir.path()).is_err());
    assert!(
        dir.path().read_dir().unwrap().next().is_none(),
        "nothing is written for a refusal"
    );
}

/// This test executable with its resource table cut off: a real PE without a manifest.
fn without_manifest(exe: &std::path::Path, to: &std::path::Path) {
    let mut image = std::fs::read(exe).unwrap();
    let pe_at = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = pe_at + 24;
    let directories = optional + if image[optional + 1] == 0x01 { 96 } else { 112 };
    image[directories + 16..directories + 24].fill(0);
    std::fs::write(to, image).unwrap();
}

#[test]
fn the_stand_in_entry_really_carries_the_manifest() {
    let exe = std::env::current_exe().unwrap();
    assert!(manifest::is_as_invoker(&std::fs::read(exe).unwrap()));
}

#[test]
fn an_entry_without_an_as_invoker_manifest_is_refused_and_nothing_is_written() {
    let exe = std::env::current_exe().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let entry = dir.path().join("entry.exe");
    without_manifest(&exe, &entry);
    assert!(!manifest::is_as_invoker(&std::fs::read(&entry).unwrap()));
    let out = dir.path().join("dist");
    let version = Version::parse("0.2.0-alpha.1").unwrap();
    let flavor = flavor(this_flavor()).unwrap();
    let err = winget_setup(&entry, &exe, &version, &flavor, &out).unwrap_err();
    assert!(err.to_string().contains("asInvoker"), "{err}");
    assert!(!out.exists(), "nothing is written for a refusal");
}
