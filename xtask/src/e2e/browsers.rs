//! The browsers and their WebDriver drivers: downloaded into `target/browsers/` (`--download`)
//! or taken from `ONCL_CHROME`/`ONCL_CHROMEDRIVER` and `ONCL_FIREFOX`/`ONCL_GECKODRIVER`.
//!
//! - Chromium: Chrome for Testing, the latest Stable with the chromedriver of the same
//!   version (branded Chrome ignores `--load-extension`).
//! - Firefox: the latest release and the latest geckodriver release.
//!
//! Every download lands in a directory named after its version, so a later run reuses it.
//! All of them go through one agent with timeouts and a size cap. The Firefox tarball is
//! checked against the release's `SHA256SUMS`; Chrome for Testing and geckodriver publish no
//! digests. Remote version strings are checked before they reach a path or a URL.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use serde_json::Value;
use ureq::Agent;

use crate::fetch::verify_sha256;

/// Chrome for Testing versions with their downloads.
const CFT_VERSIONS: &str = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
/// Firefox release versions.
const FIREFOX_VERSIONS: &str = "https://product-details.mozilla.org/1.0/firefox_versions.json";
/// Redirects to the tag page of the latest geckodriver release.
const GECKODRIVER_LATEST: &str = "https://github.com/mozilla/geckodriver/releases/latest";
/// Firefox releases: `<version>/SHA256SUMS` and the tarballs.
const FIREFOX_RELEASES: &str = "https://ftp.mozilla.org/pub/firefox/releases";

/// Longest wait for a connection or for response headers.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest time for a whole body (a browser archive is ~100–200 MB).
const BODY_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Largest archive downloaded.
const MAX_DOWNLOAD: u64 = 1 << 30;
/// Largest text document read (version lists, `SHA256SUMS`).
const MAX_TEXT: u64 = 16 << 20;

/// A browser of the e2e run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Browser {
    Chromium,
    Firefox,
}

impl Browser {
    /// Lower-case name: the column of the result table and the sandbox directory.
    pub fn name(self) -> &'static str {
        match self {
            Browser::Chromium => "chromium",
            Browser::Firefox => "firefox",
        }
    }

    /// Variables naming the browser and its driver without `--download`.
    fn env_vars(self) -> (&'static str, &'static str) {
        match self {
            Browser::Chromium => ("ONCL_CHROME", "ONCL_CHROMEDRIVER"),
            Browser::Firefox => ("ONCL_FIREFOX", "ONCL_GECKODRIVER"),
        }
    }
}

/// A browser executable and its WebDriver driver.
#[derive(Debug)]
pub struct Binaries {
    pub browser: PathBuf,
    pub driver: PathBuf,
}

/// The binaries named by the browser's environment variables.
///
/// # Errors
///
/// If a variable is not set or does not name a file.
pub fn from_env(browser: Browser) -> anyhow::Result<Binaries> {
    let (browser_var, driver_var) = browser.env_vars();
    let path = |var: &str| -> anyhow::Result<PathBuf> {
        let path = std::env::var_os(var)
            .map(PathBuf::from)
            .with_context(|| format!("{var} is not set (or pass --download)"))?;
        ensure!(path.is_file(), "{var}={} is not a file", path.display());
        Ok(path)
    };
    Ok(Binaries {
        browser: path(browser_var)?,
        driver: path(driver_var)?,
    })
}

/// Downloads (or reuses) the browser and its driver under `dir` (`target/browsers/`).
///
/// # Errors
///
/// If a version list cannot be read or names an unexpected version, a download fails or does
/// not match its published digest, or an archive does not unpack.
pub fn download(browser: Browser, dir: &Path) -> anyhow::Result<Binaries> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    match browser {
        Browser::Chromium => download_chrome(dir),
        Browser::Firefox => download_firefox(dir),
    }
}

/// The agent of every download: timeouts on connecting, the response and the whole body.
fn agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_recv_response(Some(RESPONSE_TIMEOUT))
            .timeout_recv_body(Some(BODY_TIMEOUT))
            .build()
            .into()
    })
}

fn download_chrome(dir: &Path) -> anyhow::Result<Binaries> {
    let versions: Value = serde_json::from_str(&get_text(CFT_VERSIONS)?)
        .with_context(|| format!("{CFT_VERSIONS} is not JSON"))?;
    let (version, chrome_url, driver_url) = cft_stable(&versions)?;
    let chrome = unpacked(&dir.join(format!("chrome-{version}")), |to| {
        unzip(&download_to(&chrome_url, to)?, to)
    })?;
    let driver = unpacked(&dir.join(format!("chromedriver-{version}")), |to| {
        unzip(&download_to(&driver_url, to)?, to)
    })?;
    println!("Chrome for Testing {version}");
    Ok(Binaries {
        browser: chrome.join("chrome-linux64").join("chrome"),
        driver: driver.join("chromedriver-linux64").join("chromedriver"),
    })
}

/// The Stable version of the Chrome for Testing list and its linux64 chrome and chromedriver
/// zip URLs (https, ending in a plain file name).
pub fn cft_stable(versions: &Value) -> anyhow::Result<(String, String, String)> {
    let stable = &versions["channels"]["Stable"];
    let version = stable["version"]
        .as_str()
        .context("no Stable version in the Chrome for Testing list")?;
    let version = path_component(version)
        .with_context(|| format!("unexpected Chrome for Testing version {version:?}"))?;
    let url = |kind: &str| -> anyhow::Result<String> {
        let url = stable["downloads"][kind]
            .as_array()
            .and_then(|downloads| {
                downloads
                    .iter()
                    .find(|d| d["platform"] == "linux64")
                    .and_then(|d| d["url"].as_str())
            })
            .with_context(|| format!("no linux64 {kind} for Chrome for Testing {version}"))?;
        let valid = url.starts_with("https://")
            && url.rsplit('/').next().and_then(path_component).is_some();
        ensure!(valid, "unexpected {kind} URL {url:?}");
        Ok(url.to_owned())
    };
    Ok((version.to_owned(), url("chrome")?, url("chromedriver")?))
}

fn download_firefox(dir: &Path) -> anyhow::Result<Binaries> {
    let versions: Value = serde_json::from_str(&get_text(FIREFOX_VERSIONS)?)
        .with_context(|| format!("{FIREFOX_VERSIONS} is not JSON"))?;
    let version = versions["LATEST_FIREFOX_VERSION"]
        .as_str()
        .context("no LATEST_FIREFOX_VERSION")?;
    let version = path_component(version)
        .with_context(|| format!("unexpected Firefox version {version:?}"))?
        .to_owned();
    let tag = geckodriver_tag()?;
    let firefox = unpacked(&dir.join(format!("firefox-{version}")), |to| {
        let file = firefox_tarball(&version);
        let sums_url = format!("{FIREFOX_RELEASES}/{version}/SHA256SUMS");
        let sums = get_text(&sums_url)?;
        let expected = firefox_sha256(&sums, &file)
            .with_context(|| format!("{file} is not listed in {sums_url}"))?;
        let tarball = download_to(&format!("{FIREFOX_RELEASES}/{version}/{file}"), to)?;
        let bytes = fs::read(&tarball).with_context(|| format!("reading {}", tarball.display()))?;
        verify_sha256(&bytes, &expected).with_context(|| format!("{file} against {sums_url}"))?;
        println!("sha256 of {file} matches {sums_url}");
        untar(&tarball, to)
    })?;
    let driver = unpacked(&dir.join(format!("geckodriver-{tag}")), |to| {
        let url = format!(
            "https://github.com/mozilla/geckodriver/releases/download/{tag}/geckodriver-{tag}-linux64.tar.gz"
        );
        untar(&download_to(&url, to)?, to)
    })?;
    println!("Firefox {version}, geckodriver {tag}");
    Ok(Binaries {
        browser: firefox.join("firefox").join("firefox"),
        driver: driver.join("geckodriver"),
    })
}

/// The linux-x86_64 en-US tarball of Firefox `version`, as named in `SHA256SUMS`.
fn firefox_tarball(version: &str) -> String {
    format!("linux-x86_64/en-US/firefox-{version}.tar.xz")
}

/// The sha256 that `SHA256SUMS` (`<hex>  <path>` lines) lists for `file`.
pub fn firefox_sha256(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hex, name) = line.split_once(char::is_whitespace)?;
        let valid =
            name.trim() == file && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit());
        valid.then(|| hex.to_owned())
    })
}

/// The tag of the latest geckodriver release, from where `/releases/latest` redirects
/// (the GitHub API would count against the anonymous rate limit of CI runners).
fn geckodriver_tag() -> anyhow::Result<String> {
    let response = agent()
        .get(GECKODRIVER_LATEST)
        .config()
        .max_redirects(0)
        .max_redirects_will_error(false)
        .build()
        .call()
        .with_context(|| format!("GET {GECKODRIVER_LATEST}"))?;
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .with_context(|| format!("{GECKODRIVER_LATEST} did not redirect"))?;
    release_tag(location).with_context(|| format!("no release tag in {location}"))
}

/// `v0.36.0` of `https://github.com/mozilla/geckodriver/releases/tag/v0.36.0`.
pub fn release_tag(location: &str) -> Option<String> {
    let tag = location.rsplit_once("/tag/")?.1.trim_end_matches('/');
    path_component(tag).map(str::to_owned)
}

/// `value` if it can be one path segment or URL segment as is: 1–64 ASCII letters, digits,
/// `.`, `-` or `_`, not starting with `.`.
pub fn path_component(value: &str) -> Option<&str> {
    let valid = (1..=64).contains(&value.len())
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    valid.then_some(value)
}

/// `dir` once `fill` has populated it. `fill` works in `<dir>.partial`, renamed to `dir` on
/// success, so an interrupted download is never taken for a finished one.
fn unpacked(dir: &Path, fill: impl FnOnce(&Path) -> anyhow::Result<()>) -> anyhow::Result<PathBuf> {
    if dir.is_dir() {
        return Ok(dir.to_owned());
    }
    let mut partial = dir.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    if partial.exists() {
        fs::remove_dir_all(&partial).with_context(|| format!("removing {}", partial.display()))?;
    }
    fs::create_dir_all(&partial).with_context(|| format!("creating {}", partial.display()))?;
    fill(&partial)?;
    fs::rename(&partial, dir).with_context(|| format!("renaming to {}", dir.display()))?;
    Ok(dir.to_owned())
}

fn get_text(url: &str) -> anyhow::Result<String> {
    agent()
        .get(url)
        .call()
        .with_context(|| format!("GET {url}"))?
        .body_mut()
        .with_config()
        .limit(MAX_TEXT)
        .read_to_string()
        .with_context(|| format!("reading {url}"))
}

/// Downloads `url` (at most [`MAX_DOWNLOAD`] bytes) into `dir` under its last path segment;
/// the file.
fn download_to(url: &str, dir: &Path) -> anyhow::Result<PathBuf> {
    let name = url
        .rsplit('/')
        .next()
        .and_then(path_component)
        .with_context(|| format!("no file name in {url}"))?;
    let path = dir.join(name);
    println!("downloading {url}");
    let mut response = agent()
        .get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut file = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    io::copy(
        &mut response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD)
            .reader(),
        &mut file,
    )
    .with_context(|| format!("downloading {url}"))?;
    Ok(path)
}

/// Unpacks the zip `archive` into `dir` (keeping Unix modes) and deletes it.
fn unzip(archive: &Path, dir: &Path) -> anyhow::Result<()> {
    let file = File::open(archive)?;
    zip::ZipArchive::new(file)
        .and_then(|mut zip| zip.extract(dir))
        .with_context(|| format!("unpacking {}", archive.display()))?;
    fs::remove_file(archive)?;
    Ok(())
}

/// Unpacks the tarball `archive` (any compression `tar` detects) into `dir` and deletes it.
fn untar(archive: &Path, dir: &Path) -> anyhow::Result<()> {
    let status = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dir)
        .status()
        .context("running tar")?;
    if !status.success() {
        bail!("tar -xf {} failed with {status}", archive.display());
    }
    fs::remove_file(archive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cft_stable_picks_linux64() {
        let versions = json!({"channels": {"Stable": {
            "version": "141.0.7390.54",
            "downloads": {
                "chrome": [
                    {"platform": "mac-arm64", "url": "https://x/mac/chrome.zip"},
                    {"platform": "linux64", "url": "https://x/linux64/chrome-linux64.zip"},
                ],
                "chromedriver": [
                    {"platform": "linux64", "url": "https://x/linux64/chromedriver-linux64.zip"},
                ],
            },
        }}});
        assert_eq!(
            cft_stable(&versions).unwrap(),
            (
                "141.0.7390.54".to_owned(),
                "https://x/linux64/chrome-linux64.zip".to_owned(),
                "https://x/linux64/chromedriver-linux64.zip".to_owned(),
            )
        );
        let no_driver = json!({"channels": {"Stable": {"version": "1", "downloads": {
            "chrome": [{"platform": "linux64", "url": "u"}],
        }}}});
        assert!(cft_stable(&no_driver).is_err());
    }

    #[test]
    fn cft_stable_rejects_unexpected_versions_and_urls() {
        let list = |version: &str, url: &str| {
            json!({"channels": {"Stable": {"version": version, "downloads": {
                "chrome": [{"platform": "linux64", "url": url}],
                "chromedriver": [{"platform": "linux64", "url": "https://x/d.zip"}],
            }}}})
        };
        assert!(cft_stable(&list("1.2", "https://x/c.zip")).is_ok());
        for version in ["../../x", "1/2", "", ".1"] {
            assert!(
                cft_stable(&list(version, "https://x/c.zip")).is_err(),
                "{version}"
            );
        }
        for url in ["http://x/c.zip", "https://x/", "https://x/.."] {
            assert!(cft_stable(&list("1.2", url)).is_err(), "{url}");
        }
    }

    #[test]
    fn firefox_sha256_finds_the_tarball() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums = format!(
            "{a}  linux-x86_64/en-US/firefox-158.0.1.tar.xz.asc\n\
             {b}  linux-x86_64/en-US/firefox-158.0.1.tar.xz\n\
             {a}  linux-i686/en-US/firefox-158.0.1.tar.xz\n"
        );
        let file = firefox_tarball("158.0.1");
        assert_eq!(firefox_sha256(&sums, &file), Some(b));
        assert_eq!(firefox_sha256(&sums, &firefox_tarball("1.0")), None);
        assert_eq!(firefox_sha256(&format!("xyz  {file}"), &file), None);
    }

    #[test]
    fn release_tag_from_redirect() {
        assert_eq!(
            release_tag("https://github.com/mozilla/geckodriver/releases/tag/v0.36.0").as_deref(),
            Some("v0.36.0")
        );
        assert_eq!(
            release_tag("https://github.com/mozilla/geckodriver/releases"),
            None
        );
        assert_eq!(
            release_tag("https://github.com/x/releases/tag/../../evil"),
            None
        );
    }

    #[test]
    fn path_components() {
        for good in ["158.0.1", "v0.37.1", "156.0.8078.47", "chrome-linux64.zip"] {
            assert_eq!(path_component(good), Some(good));
        }
        for bad in ["", ".", "..", "a/b", "a b", "a\\b", &"1".repeat(65)] {
            assert_eq!(path_component(bad), None, "{bad}");
        }
    }
}
