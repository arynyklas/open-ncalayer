//! `cargo xtask upstream`: the watcher of the original NCALayer. It polls the signed
//! manifest `ncalayer.der`, the distributions and the download page, downloads what changed
//! into a temporary directory, unpacks it without running anything of the original, turns it
//! into public facts (versions, sizes, hashes, certificates, URLs, class and method names)
//! and diffs them with the previous facts. Only JSON leaves the run: the `upstream` branch
//! and the issues are written from it (`docs/dev/upstream-watch.md`).

pub mod cli;
pub mod manifest;
pub mod testkit;

/// Largest manifest, in bytes.
pub const MANIFEST_MAX: u64 = 1 << 20;
/// Largest HTML page.
pub const PAGE_MAX: u64 = 2 << 20;
/// Largest bundle JAR.
pub const BUNDLE_MAX: u64 = 256 << 20;
/// Largest distribution.
pub const DIST_MAX: u64 = 1 << 30;
/// Most redirects followed by one request.
pub const REDIRECTS_MAX: u32 = 5;
/// Failed polls in a row after which a source counts as gone.
pub const FAILURES_TO_REMOVE: u32 = 3;
/// The signed manifest of the original NCALayer.
pub const MANIFEST_URL: &str = "https://crl.pki.gov.kz/updates/ncalayer.der";
/// The official download page.
pub const DOWNLOAD_PAGE_URL: &str = "https://ncl.pki.gov.kz/";
/// Files published at fixed addresses outside the manifest: `(source id, URL)`.
pub const FIXED_URLS: [(&str, &str); 2] = [
    (
        "fixed:ncalayer.zip",
        "https://crl.pki.gov.kz/updates/ncalayer.zip",
    ),
    (
        "fixed:tzdb.dat",
        "https://crl.pki.gov.kz/updates/jre/tzdb.dat",
    ),
];

/// Where the sources are: the real addresses by default, a mock in the tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoints {
    /// The manifest.
    pub manifest: String,
    /// The download page.
    pub page: String,
    /// `(source id, URL)` of the fixed files.
    pub fixed: Vec<(String, String)>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            manifest: MANIFEST_URL.to_owned(),
            page: DOWNLOAD_PAGE_URL.to_owned(),
            fixed: FIXED_URLS
                .iter()
                .map(|(id, url)| ((*id).to_owned(), (*url).to_owned()))
                .collect(),
        }
    }
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(bytes))
}
