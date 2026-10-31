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
