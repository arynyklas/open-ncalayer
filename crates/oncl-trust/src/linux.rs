//! Linux: NSS databases (Chrome's shared one, every Firefox profile) through `certutil`.
//!
//! Browsers on Linux ignore the system CA bundle, so there is no OS store here: the CA goes
//! into each NSS database the user picks. Reading uses `certutil -L` (read-only) or, without
//! `certutil`, a read-only SQLite query of `cert9.db`; writing needs `certutil`.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{
    Certificate, InstallOutcome, NssDbState, StoreState, TrustReport, TrustStore, hex,
    pem_certificates,
};

const CERTUTIL: &str = "certutil";

/// `certutil` is not installed: the error inside the [`io::Error`] (kind `NotFound`) of
/// every [`NssDb`] operation then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "certutil is not installed; install the libnss3-tools package (Debian, Ubuntu), \
     nss-tools (Fedora, RHEL, openSUSE) or nss (Arch)"
)]
pub struct CertutilMissing;

/// An NSS database directory (with `cert9.db`): Chrome's shared database or a Firefox
/// profile. The browser may need a restart to see a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssDb(pub PathBuf);

impl TrustStore for NssDb {
    fn contains(&self, ca: &Certificate) -> io::Result<bool> {
        Certutil::new(CERTUTIL.as_ref(), &self.0).contains(ca)
    }

    fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
        Certutil::new(CERTUTIL.as_ref(), &self.0).install(ca)
    }

    fn remove(&self, ca: &Certificate) -> io::Result<bool> {
        Certutil::new(CERTUTIL.as_ref(), &self.0).remove(ca)
    }
}

/// The NSS databases of the browsers under `home` that exist (have `cert9.db`):
/// - Chrome/Chromium: `~/.pki/nssdb`, or `~/.local/share/pki/nssdb` when the former is
///   absent (Chrome 146+); snap Chromium's `~/snap/chromium/current/.pki/nssdb`;
/// - every Firefox profile listed in `profiles.ini` under `~/.mozilla/firefox`,
///   `~/.config/mozilla/firefox` (Firefox 147+), snap's `~/snap/firefox/common/.mozilla/firefox`
///   and Flatpak's `~/.var/app/org.mozilla.firefox/.mozilla/firefox`.
///
/// Only the default locations under `home` are looked at (`XDG_*_HOME` are not read).
pub fn nss_databases(home: &Path) -> Vec<NssDb> {
    let classic = home.join(".pki/nssdb");
    let chrome = if classic.is_dir() {
        classic
    } else {
        home.join(".local/share/pki/nssdb")
    };
    let firefox_roots = [
        ".mozilla/firefox",
        ".config/mozilla/firefox",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
    ];
    let candidates = [chrome, home.join("snap/chromium/current/.pki/nssdb")]
        .into_iter()
        .chain(
            firefox_roots
                .into_iter()
                .flat_map(|root| crate::firefox_profiles(&home.join(root))),
        );
    let mut dbs: Vec<NssDb> = Vec::new();
    for dir in candidates {
        if dir.join("cert9.db").is_file() && !dbs.iter().any(|db| db.0 == dir) {
            dbs.push(NssDb(dir));
        }
    }
    dbs
}

/// Read-only check: presence of the CA in the NSS databases under `$HOME`.
pub(crate) fn check(ca: &Certificate, _leaf: &Certificate) -> TrustReport {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    report(ca, home.as_deref(), CERTUTIL.as_ref())
}

fn report(ca: &Certificate, home: Option<&Path>, certutil: &OsStr) -> TrustReport {
    let dbs = home.map(nss_databases).unwrap_or_default();
    TrustReport {
        os_store: StoreState::NotApplicable,
        os_chain_ok: None,
        nss: dbs
            .into_iter()
            .map(|NssDb(path)| {
                let ca_present = presence(ca, &path, certutil);
                NssDbState { path, ca_present }
            })
            .collect(),
        firefox_enterprise_roots: Vec::new(),
    }
}

/// Through `certutil`, else (not installed) through SQLite; `None` if neither can read it.
fn presence(ca: &Certificate, dir: &Path, certutil: &OsStr) -> Option<bool> {
    match Certutil::new(certutil, dir).contains(ca) {
        Ok(present) => Some(present),
        Err(e) if is_certutil_missing(&e) => sqlite_contains(dir, ca).ok(),
        Err(_) => None,
    }
}

fn is_certutil_missing(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<CertutilMissing>())
}

/// Whether `cert9.db` has an object whose `CKA_VALUE` (column `a11`) is the certificate's
/// encoding. Opened read-only: safe while a browser has the database open.
fn sqlite_contains(dir: &Path, ca: &Certificate) -> rusqlite::Result<bool> {
    use rusqlite::{Connection, OpenFlags};
    let db = Connection::open_with_flags(
        dir.join("cert9.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.query_row(
        "SELECT EXISTS (SELECT 1 FROM nssPublic WHERE a11 = ?1)",
        [ca.der()],
        |row| row.get(0),
    )
}

/// The nickname [`NssDb::install`] gives the CA: unique per certificate, because NSS refuses
/// a nickname already used by a certificate with another subject (a previous CA).
fn nickname(ca: &Certificate) -> String {
    format!("OpenNCALayer Local CA {}", &hex(&ca.sha256())[..16])
}

/// `certutil` on one database.
struct Certutil<'a> {
    program: &'a OsStr,
    db: OsString,
}

/// One line of `certutil -L`.
struct Entry {
    nickname: String,
    /// `SSL,S/MIME,JAR/XPI`, like `C,,`.
    trust: String,
}

impl Entry {
    /// Trusted as a CA for TLS servers.
    fn ssl_trusted(&self) -> bool {
        self.trust
            .split(',')
            .next()
            .is_some_and(|ssl| ssl.contains('C'))
    }
}

impl<'a> Certutil<'a> {
    fn new(program: &'a OsStr, dir: &Path) -> Self {
        let mut db = OsString::from("sql:");
        db.push(dir);
        Self { program, db }
    }

    /// Runs `certutil -d sql:<dir> <args>` with `stdin`; its stdout on success.
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> io::Result<Vec<u8>> {
        let mut child = Command::new(self.program)
            .arg("-d")
            .arg(&self.db)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => io::Error::new(io::ErrorKind::NotFound, CertutilMissing),
                _ => e,
            })?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            // A certificate is far smaller than a pipe buffer: no deadlock with the reads.
            pipe.write_all(input)?;
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr.trim();
            Err(io::Error::other(
                if message.contains("SEC_ERROR_TOKEN_NOT_LOGGED_IN") {
                    format!(
                        "the NSS database is protected by a password (Firefox Primary Password); \
                         import the certificate in the browser's certificate manager instead \
                         ({message})"
                    )
                } else {
                    format!("certutil {}: {message}", args[0])
                },
            ))
        }
    }

    /// Writes never prompt: an empty password file makes a password-protected database fail
    /// instead of waiting for input.
    fn write(&self, args: &[&str], stdin: Option<&[u8]>) -> io::Result<()> {
        let mut with_password = args.to_vec();
        with_password.extend(["-f", "/dev/null"]);
        self.run(&with_password, stdin).map(drop)
    }

    fn entries(&self) -> io::Result<Vec<Entry>> {
        let listing = self.run(&["-L"], None)?;
        let listing = String::from_utf8_lossy(&listing);
        // A title line, the `SSL,S/MIME,JAR/XPI` line and a blank line come first.
        let body = listing
            .split_once("SSL,S/MIME,JAR/XPI")
            .map_or("", |(_, body)| body);
        Ok(body
            .lines()
            .filter_map(|line| {
                let (nickname, trust) = line.trim_end().rsplit_once(char::is_whitespace)?;
                let nickname = nickname.trim_end();
                (!nickname.is_empty()).then(|| Entry {
                    nickname: nickname.to_owned(),
                    trust: trust.to_owned(),
                })
            })
            .collect())
    }

    /// The certificates under a nickname (NSS files every certificate of one subject under
    /// one nickname).
    fn certificates(&self, nickname: &str) -> io::Result<Vec<Certificate>> {
        let pem = self.run(&["-L", "-n", nickname, "-a"], None)?;
        pem_certificates(&String::from_utf8_lossy(&pem)).collect()
    }

    /// The `-L` entries whose certificates include `ca`.
    fn entries_of(&self, ca: &Certificate) -> io::Result<Vec<Entry>> {
        let mut found = Vec::new();
        for entry in self.entries()? {
            if self.certificates(&entry.nickname)?.contains(ca) {
                found.push(entry);
            }
        }
        Ok(found)
    }

    fn contains(&self, ca: &Certificate) -> io::Result<bool> {
        Ok(!self.entries_of(ca)?.is_empty())
    }

    fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
        let present = self.entries_of(ca)?;
        if present.iter().any(Entry::ssl_trusted) {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        if let Some(entry) = present.first() {
            // Present without TLS trust (imported without the "identify websites" box, or a
            // failed earlier attempt): add the trust, keep the other flags.
            let (ssl, rest) = entry.trust.split_once(',').unwrap_or((&entry.trust, ","));
            let trust = format!("{ssl}C,{rest}");
            self.write(&["-M", "-n", &entry.nickname, "-t", &trust], None)?;
            return Ok(InstallOutcome::Installed);
        }
        let nickname = nickname(ca);
        if let Err(e) = self.write(&["-A", "-n", &nickname, "-t", "C,,"], Some(ca.der())) {
            // NSS may have stored the certificate before failing to set its trust (a
            // password-protected database): take it out again.
            if self.contains(ca).unwrap_or(false) {
                let _ = self.remove(ca);
            }
            return Err(e);
        }
        Ok(InstallOutcome::Installed)
    }

    fn remove(&self, ca: &Certificate) -> io::Result<bool> {
        let found = self.entries_of(ca)?;
        for entry in &found {
            // `-D` deletes one certificate of the nickname, not necessarily ours: refuse
            // rather than risk another certificate of the same subject.
            if self.certificates(&entry.nickname)? != [ca.clone()] {
                return Err(io::Error::other(format!(
                    "the NSS nickname \"{}\" holds other certificates of the same subject too; \
                     remove the certificate in the browser's certificate manager",
                    entry.nickname
                )));
            }
            self.write(&["-D", "-n", &entry.nickname], None)?;
        }
        Ok(!found.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::ca_and_leaf;

    /// An empty NSS database in a temporary directory, created by `certutil -N`.
    fn new_db(password: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut command = Command::new(CERTUTIL);
        command
            .arg("-N")
            .arg("-d")
            .arg(Certutil::new(CERTUTIL.as_ref(), dir.path()).db);
        match password {
            None => command.arg("--empty-password"),
            Some(password) => {
                let file = dir.path().join("password.txt");
                std::fs::write(&file, password).unwrap();
                command.arg("-f").arg(file)
            }
        };
        let status = command
            .status()
            .expect("certutil (libnss3-tools) is installed");
        assert!(status.success());
        dir
    }

    fn trust_of(dir: &Path, ca: &Certificate) -> Vec<String> {
        Certutil::new(CERTUTIL.as_ref(), dir)
            .entries_of(ca)
            .unwrap()
            .into_iter()
            .map(|e| e.trust)
            .collect()
    }

    #[test]
    fn nss_db_install_contains_remove() {
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (ca, _) = ca_and_leaf("one@host");
        assert!(!db.contains(&ca).unwrap());
        assert!(!sqlite_contains(dir.path(), &ca).unwrap());
        assert!(!db.remove(&ca).unwrap());

        assert_eq!(db.install(&ca).unwrap(), InstallOutcome::Installed);
        assert!(db.contains(&ca).unwrap());
        assert!(sqlite_contains(dir.path(), &ca).unwrap());
        assert_eq!(trust_of(dir.path(), &ca), ["C,,"]);
        assert_eq!(db.install(&ca).unwrap(), InstallOutcome::AlreadyPresent);
        assert_eq!(trust_of(dir.path(), &ca), ["C,,"], "no duplicate");

        assert!(db.remove(&ca).unwrap());
        assert!(!db.contains(&ca).unwrap());
        assert!(!sqlite_contains(dir.path(), &ca).unwrap());
        assert!(!db.remove(&ca).unwrap());
    }

    #[test]
    fn nss_db_remove_leaves_other_certificates() {
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (ours, _) = ca_and_leaf("ours@host");
        let (other, _) = ca_and_leaf("other@host");
        assert_eq!(db.install(&ours).unwrap(), InstallOutcome::Installed);
        assert_eq!(db.install(&other).unwrap(), InstallOutcome::Installed);

        assert!(db.remove(&ours).unwrap());
        assert!(!db.contains(&ours).unwrap());
        assert!(db.contains(&other).unwrap());
    }

    #[test]
    fn nss_db_never_removes_a_same_subject_certificate() {
        // Same label and day: the same subject, which NSS files under one nickname.
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (first, _) = ca_and_leaf("same@host");
        let (second, _) = ca_and_leaf("same@host");
        assert_ne!(first, second);
        db.install(&first).unwrap();
        db.install(&second).unwrap();
        assert!(db.contains(&first).unwrap());

        match db.remove(&first) {
            Ok(removed) => assert!(removed),
            Err(e) => assert!(e.to_string().contains("other certificates"), "{e}"),
        }
        assert!(db.contains(&second).unwrap(), "the other CA stays");
    }

    #[test]
    fn nss_db_install_trusts_a_present_untrusted_certificate() {
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (ca, _) = ca_and_leaf("untrusted@host");
        Certutil::new(CERTUTIL.as_ref(), dir.path())
            .write(&["-A", "-n", "Imported", "-t", ",,"], Some(ca.der()))
            .unwrap();
        assert_eq!(trust_of(dir.path(), &ca), [",,"]);

        assert_eq!(db.install(&ca).unwrap(), InstallOutcome::Installed);
        assert_eq!(trust_of(dir.path(), &ca), ["C,,"]);
        assert_eq!(db.install(&ca).unwrap(), InstallOutcome::AlreadyPresent);
    }

    #[test]
    fn nss_db_with_a_password_fails_clearly_and_leaves_nothing() {
        let dir = new_db(Some("secret"));
        let db = NssDb(dir.path().to_owned());
        let (ca, _) = ca_and_leaf("locked@host");
        let err = db.install(&ca).unwrap_err();
        assert!(err.to_string().contains("protected by a password"), "{err}");
        assert!(!db.contains(&ca).unwrap());
    }

    #[test]
    fn missing_certutil_is_a_clear_error() {
        let dir = new_db(None);
        let (ca, _) = ca_and_leaf("nocertutil@host");
        let missing = Certutil::new("/nonexistent/certutil".as_ref(), dir.path());
        for err in [
            missing.contains(&ca).unwrap_err(),
            missing.install(&ca).unwrap_err(),
            missing.remove(&ca).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
            assert!(is_certutil_missing(&err));
            assert!(err.to_string().contains("libnss3-tools"), "{err}");
        }
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn nss_databases_in_a_sandbox_home() {
        let home = tempfile::tempdir().unwrap();
        let home = home.path();
        assert!(nss_databases(home).is_empty());

        // Chrome's XDG location counts only while `~/.pki/nssdb` is absent.
        touch(&home.join(".local/share/pki/nssdb/cert9.db"));
        assert_eq!(
            nss_databases(home),
            [NssDb(home.join(".local/share/pki/nssdb"))]
        );
        touch(&home.join(".pki/nssdb/cert9.db"));
        touch(&home.join("snap/chromium/current/.pki/nssdb/cert9.db"));

        let classic = home.join(".mozilla/firefox");
        write(
            &classic.join("profiles.ini"),
            "[Profile0]\nName=default-release\nIsRelative=1\nPath=abc.default-release\n\n\
             [Profile1]\nName=never-started\nIsRelative=1\nPath=def.default\n",
        );
        touch(&classic.join("abc.default-release/cert9.db"));
        // A profile directory not listed in profiles.ini is not a profile.
        touch(&classic.join("stray/cert9.db"));
        let xdg = home.join(".config/mozilla/firefox");
        write(
            &xdg.join("profiles.ini"),
            "[Profile0]\nIsRelative=1\nPath=Profiles/xdg.default\n",
        );
        touch(&xdg.join("Profiles/xdg.default/cert9.db"));
        let snap = home.join("snap/firefox/common/.mozilla/firefox");
        write(
            &snap.join("profiles.ini"),
            "[Profile0]\nIsRelative=1\nPath=snap.default\n",
        );
        touch(&snap.join("snap.default/cert9.db"));
        let flatpak = home.join(".var/app/org.mozilla.firefox/.mozilla/firefox");
        write(
            &flatpak.join("profiles.ini"),
            "[Profile0]\nIsRelative=1\nPath=flat.default\n",
        );
        touch(&flatpak.join("flat.default/cert9.db"));

        assert_eq!(
            nss_databases(home),
            [
                NssDb(home.join(".pki/nssdb")),
                NssDb(home.join("snap/chromium/current/.pki/nssdb")),
                NssDb(classic.join("abc.default-release")),
                NssDb(xdg.join("Profiles/xdg.default")),
                NssDb(snap.join("snap.default")),
                NssDb(flatpak.join("flat.default")),
            ]
        );
    }

    /// A sandbox home whose Chrome database is a real NSS database.
    fn home_with_chrome_db() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join(".pki/nssdb");
        std::fs::create_dir_all(&db).unwrap();
        let status = Command::new(CERTUTIL)
            .arg("-N")
            .arg("--empty-password")
            .arg("-d")
            .arg(Certutil::new(CERTUTIL.as_ref(), &db).db)
            .status()
            .unwrap();
        assert!(status.success());
        home
    }

    #[test]
    fn report_on_a_sandbox_home() {
        let home = home_with_chrome_db();
        let chrome = home.path().join(".pki/nssdb");
        let (ca, _) = ca_and_leaf("report@host");
        let certutil: &OsStr = CERTUTIL.as_ref();

        let before = report(&ca, Some(home.path()), certutil);
        assert_eq!(before.os_store, StoreState::NotApplicable);
        assert_eq!(before.os_chain_ok, None);
        assert!(before.firefox_enterprise_roots.is_empty());
        assert_eq!(
            before.nss,
            [NssDbState {
                path: chrome.clone(),
                ca_present: Some(false)
            }]
        );

        NssDb(chrome.clone()).install(&ca).unwrap();
        let after = report(&ca, Some(home.path()), certutil);
        assert_eq!(after.nss[0].ca_present, Some(true));
        // Without certutil the read-only SQLite query gives the same answer.
        let without = report(&ca, Some(home.path()), "/nonexistent/certutil".as_ref());
        assert_eq!(without.nss[0].ca_present, Some(true));
        let (stranger, _) = ca_and_leaf("stranger@host");
        let other = report(
            &stranger,
            Some(home.path()),
            "/nonexistent/certutil".as_ref(),
        );
        assert_eq!(other.nss[0].ca_present, Some(false));

        assert!(report(&ca, None, certutil).nss.is_empty());
    }
}
