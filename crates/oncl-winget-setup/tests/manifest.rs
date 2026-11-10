//! The installer entry carries an `asInvoker` manifest, and the payload still goes in after
//! it (finding F1: without the manifest Windows asks for elevation because of the file name).

#![cfg(all(windows, target_env = "msvc"))]

use oncl_winget_setup::manifest;
use oncl_winget_setup::payload::{self, Arch};
use semver::Version;

const ENTRY: &str = env!("CARGO_BIN_EXE_oncl-winget-setup");

#[test]
fn the_entry_has_an_as_invoker_manifest() {
    let image = std::fs::read(ENTRY).expect("the built entry");
    let text = manifest::of(&image).expect("the entry has no RT_MANIFEST resource");
    assert!(text.contains("level=\"asInvoker\""), "{text}");
    assert!(text.contains("uiAccess=\"false\""), "{text}");
    // The Windows 10/11 GUID: without it the compatibility layer treats the program as old.
    assert!(
        text.contains("8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"),
        "{text}"
    );
    assert!(manifest::is_as_invoker(&image));
}

#[test]
fn the_payload_still_goes_in_after_the_resource_section() {
    let image = std::fs::read(ENTRY).expect("the built entry");
    let arch = Arch::this().expect("x64 or x86");
    // Any program of the entry's architecture stands in for the Setup.
    let setup = image.clone();
    let version = Version::new(1, 2, 3);
    let made = payload::append(&image, &setup, &version, arch).expect("append");
    let read = payload::read(&made).expect("the payload reads back");
    assert_eq!(read.setup, setup.as_slice());
    assert_eq!(read.version, version);
    assert!(manifest::is_as_invoker(&made));
}

#[test]
fn an_image_without_a_resource_table_has_no_manifest() {
    let mut image = std::fs::read(ENTRY).expect("the built entry");
    // Zero the resource data directory (index 2): the PE of the unfixed entry.
    let pe_at = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = pe_at + 24;
    let directories = optional + if image[optional + 1] == 0x01 { 96 } else { 112 };
    image[directories + 16..directories + 24].fill(0);
    assert_eq!(manifest::of(&image), None);
    assert!(!manifest::is_as_invoker(&image));
}
