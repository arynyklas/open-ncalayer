//! The browsers and their WebDriver drivers: downloaded into `target/browsers/` (`--download`)
//! or taken from `ONCL_CHROME`/`ONCL_CHROMEDRIVER` and `ONCL_FIREFOX`/`ONCL_GECKODRIVER`.
//!
//! - Chromium: Chrome for Testing, the latest Stable with the chromedriver of the same
//!   version (branded Chrome ignores `--load-extension`).
//! - Firefox: the latest release and the latest geckodriver release.
//!
//! Every download lands in a directory named after its version, so a later run reuses it.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail, ensure};
use serde_json::Value;
use ureq::Agent;

/// Chrome for Testing versions with their downloads.
const CFT_VERSIONS: &str = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
/// Firefox release versions.
const FIREFOX_VERSIONS: &str = "https://product-details.mozilla.org/1.0/firefox_versions.json";
/// Redirects to the tag page of the latest geckodriver release.
const GECKODRIVER_LATEST: &str = "https://github.com/mozilla/geckodriver/releases/latest";

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
/// If a version list cannot be read, a download fails or an archive does not unpack.
pub fn download(browser: Browser, dir: &Path) -> anyhow::Result<Binaries> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    match browser {
        Browser::Chromium => download_chrome(dir),
        Browser::Firefox => download_firefox(dir),
    }
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
/// zip URLs.
pub fn cft_stable(versions: &Value) -> anyhow::Result<(String, String, String)> {
    let stable = &versions["channels"]["Stable"];
    let version = stable["version"]
        .as_str()
        .context("no Stable version in the Chrome for Testing list")?;
    let url = |kind: &str| -> anyhow::Result<String> {
        stable["downloads"][kind]
            .as_array()
            .and_then(|downloads| {
                downloads
                    .iter()
                    .find(|d| d["platform"] == "linux64")
                    .and_then(|d| d["url"].as_str())
            })
            .map(str::to_owned)
            .with_context(|| format!("no linux64 {kind} for Chrome for Testing {version}"))
    };
    Ok((version.to_owned(), url("chrome")?, url("chromedriver")?))
}

fn download_firefox(dir: &Path) -> anyhow::Result<Binaries> {
    let versions: Value = serde_json::from_str(&get_text(FIREFOX_VERSIONS)?)
        .with_context(|| format!("{FIREFOX_VERSIONS} is not JSON"))?;
    let version = versions["LATEST_FIREFOX_VERSION"]
        .as_str()
        .context("no LATEST_FIREFOX_VERSION")?
        .to_owned();
    let tag = geckodriver_tag()?;
    let firefox = unpacked(&dir.join(format!("firefox-{version}")), |to| {
        let url = format!(
            "https://ftp.mozilla.org/pub/firefox/releases/{version}/linux-x86_64/en-US/firefox-{version}.tar.xz"
        );
        untar(&download_to(&url, to)?, to)
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

/// The tag of the latest geckodriver release, from where `/releases/latest` redirects
/// (the GitHub API would count against the anonymous rate limit of CI runners).
fn geckodriver_tag() -> anyhow::Result<String> {
    let agent: Agent = Agent::config_builder()
        .max_redirects(0)
        .max_redirects_will_error(false)
        .build()
        .into();
    let response = agent
        .get(GECKODRIVER_LATEST)
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
    let valid = !tag.is_empty()
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    valid.then(|| tag.to_owned())
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
    ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?
        .body_mut()
        .read_to_string()
        .with_context(|| format!("reading {url}"))
}

/// Downloads `url` into `dir` under its last path segment; the file.
fn download_to(url: &str, dir: &Path) -> anyhow::Result<PathBuf> {
    let name = url
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("download");
    let path = dir.join(name);
    println!("downloading {url}");
    let mut response = ureq::get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut file = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    // Browser archives are far above the default body limit.
    io::copy(
        &mut response.body_mut().with_config().limit(u64::MAX).reader(),
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
}
