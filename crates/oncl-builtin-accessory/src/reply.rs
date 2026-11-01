//! What the module reports of the original's bundles and modules and of OpenNCALayer itself.

use oncl_pdk::abi::Os;

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.ncalayerservices.accessory";

/// The bundle symbolic name `getBundles` reports OpenNCALayer under.
pub const SYMNAME: &str = "io.github.arynyklas.openncalayer";

/// The original's modules as `getServices` lists them on `os`: in the order of its OSGi
/// service registry, which its builds for Windows and for Linux keep differently. macOS
/// follows Linux.
pub fn original_services(os: Os) -> [&'static str; 4] {
    const BASICS: &str = "kz.gov.pki.knca.basics";
    const APPLET: &str = "kz.gov.pki.knca.applet.Applet";
    const COMMON_UTILS: &str = "kz.gov.pki.knca.commonUtils";
    match os {
        Os::Windows => [BASICS, APPLET, COMMON_UTILS, MODULE_NAME],
        Os::Linux | Os::Macos => [APPLET, MODULE_NAME, BASICS, COMMON_UTILS],
    }
}

/// The bundles the original reports whose functions this daemon implements: its OSGi
/// framework and its core bundles. The versions are what the original's
/// `Bundle.getVersion().toString()` gives (OSGi `major.minor.micro`) once it has updated to
/// the live update manifest (http://crl.pki.gov.kz/updates/ncalayer.der, manifest version
/// 1.4, signed by `ncalayersigner2024_2`); the framework is the Apache Felix both
/// distributions embed (`org/apache/felix/framework/Felix.properties`: `felix.version=7.0.3`).
///
/// `getBundles` puts them into its `HashMap` in this order, which keeps the original's order of
/// installing them where its replies show it: the framework before `NCALayerServices`,
/// `knca_provider_jce_kalkan` before `osgi.layer.websocket` (each pair shares a bucket).
pub const CORE_BUNDLES: [(&str, &str); 8] = [
    ("org.apache.felix.framework", "7.0.3"),
    ("kz.gov.pki.api.layer.NCALayerServices", "0.8.3"),
    ("kz.gov.pki.kalkan.knca_provider_jce_kalkan", "0.7.8"),
    ("kz.gov.pki.kalkan.xmldsig", "0.5.2"),
    ("kz.gov.pki.knca.applet.knca_applet", "0.4.13"),
    ("kz.gov.pki.osgi.layer.common", "0.3.4"),
    ("kz.gov.pki.osgi.layer.websocket", "0.4.3"),
    ("kz.gov.pki.provider.knca_provider_util", "0.9.2"),
];

/// What `getBundles` reports of a core of this version, `(symname, version)` in the order
/// they go into its map: the original's framework and core bundles, then OpenNCALayer itself
/// ([`SYMNAME`]).
pub fn bundles() -> Vec<(&'static str, &'static str)> {
    let mut bundles = CORE_BUNDLES.to_vec();
    bundles.push((SYMNAME, env!("CARGO_PKG_VERSION")));
    bundles
}

/// `Bundle.getVersion().toString()` of a bundle whose manifest says `version`: the OSGi
/// `Version` the framework parses it into, `major.minor.micro` with `.qualifier` when there is
/// one, so `1.2` is `1.2.0` and `2` is `2.0.0`.
///
/// The grammar is the OSGi core specification's, which Felix's `Version(String)` follows:
/// `major ['.' minor ['.' micro ['.' qualifier]]]` around surrounding whitespace, the three
/// numbers decimal digits within `i32`, the qualifier one or more of `A-Z a-z 0-9 _ -`. A
/// semver pre-release (`1.0.0-beta.2`) is not that: the original's framework refuses it, no
/// bundle of the original carries one, and no OSGi rendering of it exists, so a `version` that
/// is not an OSGi version is reported as written.
pub fn osgi_version(version: &str) -> String {
    parse_osgi(version).unwrap_or_else(|| version.to_owned())
}

fn parse_osgi(version: &str) -> Option<String> {
    let version = version.trim_matches(|c: char| c <= ' ');
    let mut parts = version.splitn(4, '.');
    let number = |part: &str| -> Option<u32> {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok().filter(|&n| n <= i32::MAX as u32)
    };
    let major = number(parts.next()?)?;
    let Some(minor) = parts.next() else {
        return Some(format!("{major}.0.0"));
    };
    let minor = number(minor)?;
    let Some(micro) = parts.next() else {
        return Some(format!("{major}.{minor}.0"));
    };
    let micro = number(micro)?;
    match parts.next() {
        None => Some(format!("{major}.{minor}.{micro}")),
        Some(q)
            if !q.is_empty()
                && q.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            Some(format!("{major}.{minor}.{micro}.{q}"))
        }
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::osgi_version;

    #[test]
    fn osgi_versions_are_major_minor_micro() {
        for (written, reported) in [
            ("1.2", "1.2.0"),
            ("1.2.0", "1.2.0"),
            ("2", "2.0.0"),
            ("0.1.3", "0.1.3"),
            ("1.0.445", "1.0.445"),
            ("01.002.0003", "1.2.3"),
            (" 6.0 ", "6.0.0"),
            ("1.2.3.RC_1-x", "1.2.3.RC_1-x"),
            ("1.2.3.20240101", "1.2.3.20240101"),
            ("2147483647", "2147483647.0.0"),
        ] {
            assert_eq!(osgi_version(written), reported, "{written:?}");
        }
    }

    #[test]
    fn what_is_not_an_osgi_version_is_reported_as_written() {
        for written in [
            "1.0.0-beta.2",
            "1.0.0-beta",
            "1.2.3.",
            "1.2.3.a.b",
            "1.2.3.é",
            "1.",
            ".1",
            "1..2",
            "-1",
            "+1",
            "a",
            "2147483648",
            "99999999999999999999",
            "",
        ] {
            assert_eq!(osgi_version(written), written, "{written:?}");
        }
    }
}
