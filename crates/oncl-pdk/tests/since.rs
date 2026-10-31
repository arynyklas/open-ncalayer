//! The core version each host function appeared in: a plugin importing it needs a `min_core`
//! of at least that.

use oncl_pdk::abi::Import;
use semver::Version;

/// The first core with plugins.
const FIRST_PLUGIN_CORE: &str = "0.1.0-alpha.3";

/// Every core released so far. A function that is not in a released core must name a newer
/// one, or that core would be offered plugins it cannot load.
const RELEASED: [&str; 4] = [
    "0.1.0-alpha.1",
    "0.1.0-alpha.2",
    "0.1.0-alpha.3",
    "0.1.0-alpha.4",
];

/// The functions of the first core with plugins.
const FIRST: [Import; 14] = [
    Import::Log,
    Import::Now,
    Import::Random,
    Import::CertInfo,
    Import::KeysChoose,
    Import::KeysSignCms,
    Import::KeysSignRaw,
    Import::KeysSignXml,
    Import::KeysRelease,
    Import::DialogMessage,
    Import::DialogConfirm,
    Import::FileOpen,
    Import::FileSave,
    Import::HttpRequest,
];

/// The functions `0.1.0-alpha.4` added: the plugin ports'.
const ALPHA_4: [Import; 31] = [
    Import::ReplyDrop,
    Import::Hash,
    Import::CertDetails,
    Import::LocalTime,
    Import::Platform,
    Import::CaList,
    Import::CaIssuer,
    Import::KeysSelect,
    Import::KeysChain,
    Import::KeysTerminals,
    Import::KeysOpen,
    Import::DialogPassword,
    Import::KeysSignCmsEx,
    Import::TspStamp,
    Import::TspRequest,
    Import::OcspFetch,
    Import::CrlFetch,
    Import::CmsVerify,
    Import::KeysSignXmlEx,
    Import::XmlVerify,
    Import::HttpRequestEx,
    Import::FileChoose,
    Import::FileOpenEx,
    Import::PageFileRead,
    Import::PageFileWrite,
    Import::DialogChoice,
    Import::SettingsGet,
    Import::SettingsPut,
    Import::SharedGet,
    Import::SharedPut,
    Import::KeysSignXades,
];

#[test]
fn every_import_has_since() {
    let first = Version::parse(FIRST_PLUGIN_CORE).unwrap();
    for import in Import::ALL {
        assert!(import.since() >= first, "{}", import.name());
        assert_eq!(Import::from_name(import.name()), Some(import));
    }
    assert_eq!(Import::ReplyDrop.name(), "reply_drop");
    assert_eq!(Import::ReplyDrop.capability(), None);
}

#[test]
fn the_first_plugin_core_has_its_functions() {
    let first = Version::parse(FIRST_PLUGIN_CORE).unwrap();
    for import in FIRST {
        assert_eq!(import.since(), first, "{}", import.name());
    }
    let alpha_4 = Version::parse("0.1.0-alpha.4").unwrap();
    for import in ALPHA_4 {
        assert_eq!(import.since(), alpha_4, "{}", import.name());
    }
}

#[test]
fn later_functions_name_an_unreleased_core() {
    let released: Vec<Version> = RELEASED
        .iter()
        .map(|v| Version::parse(v).unwrap())
        .collect();
    let shipped = |i: &Import| FIRST.contains(i) || ALPHA_4.contains(i);
    for import in Import::ALL.into_iter().filter(|i| !shipped(i)) {
        for version in &released {
            assert!(
                import.since() > *version,
                "{} claims {}, but the released {version} lacks it",
                import.name(),
                import.since()
            );
        }
    }
}

#[test]
fn since_is_not_newer_than_the_workspace() {
    let workspace = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    for import in Import::ALL {
        assert!(
            import.since() <= workspace,
            "{} appeared in {}, after the workspace's {workspace}",
            import.name(),
            import.since()
        );
    }
}
