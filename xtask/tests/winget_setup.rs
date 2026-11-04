//! The WinGet installer entry as `cargo xtask package winget-setup` makes it: real programs
//! (this test's own executable stands for both the entry and `Setup.exe`), read back the way
//! the installer reads its payload.
#![cfg(windows)]

use oncl_update::Version;
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
