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
    Certificate, InstallOutcome, NssDbState, StoreState, TrustReport, TrustStore, hex, pem_blocks,
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

/// Read-only check: the CA in the NSS databases under `$HOME`.
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
            .map(|NssDb(path)| db_state(ca, path, certutil))
            .collect(),
        firefox_enterprise_roots: Vec::new(),
    }
}

/// Through `certutil`, else (not installed) presence only through SQLite.
fn db_state(ca: &Certificate, path: PathBuf, certutil: &OsStr) -> NssDbState {
    let (ca_present, ca_ssl_trusted) = match Certutil::new(certutil, &path).find(ca) {
        Ok(None) => (Some(false), Some(false)),
        Ok(Some(found)) => (Some(true), found.ssl_trusted()),
        Err(e) if is_certutil_missing(&e) => (sqlite_contains(&path, ca).ok(), None),
        Err(_) => (None, None),
    };
    NssDbState {
        path,
        ca_present,
        ca_ssl_trusted,
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

/// What the subject common name of OpenNCALayer's own local CA starts with (`oncl-tls`).
const OWN_CA_NAME: &str = "OpenNCALayer Local CA";

/// The nickname [`NssDb::install`] gives a certificate: unique per certificate, because NSS
/// refuses a nickname already used by a certificate with another subject (a previous own
/// CA; the NCA's 2015 root `rcarsa`, whose CN `rcarsa20` shares). OpenNCALayer's own CA is
/// `OpenNCALayer Local CA <first 16 hex of SHA-256>`; any other CA (the NCA's roots) is
/// `<its subject CN> <first 8 hex of SHA-256>` (`CA <…>` without a CN), so that it never
/// looks like OpenNCALayer's in the browser's certificate manager. Removal finds a
/// certificate by its bytes, whatever its nickname.
fn nickname(ca: &Certificate) -> String {
    let sha256 = hex(&ca.sha256());
    match ca.subject_common_name() {
        Some(name) if name.starts_with(OWN_CA_NAME) => format!("{OWN_CA_NAME} {}", &sha256[..16]),
        Some(name) if !name.trim().is_empty() => format!("{} {}", name.trim(), &sha256[..8]),
        _ => format!("CA {}", &sha256[..8]),
    }
}

/// `certutil` on one database.
struct Certutil<'a> {
    program: &'a OsStr,
    db: OsString,
}

/// One line of `certutil -L`: one certificate.
struct Entry {
    nickname: String,
    /// `SSL,S/MIME,JAR/XPI`, like `C,,`.
    trust: String,
}

/// The CA found in a database.
struct Found {
    /// A nickname that lists the CA.
    nickname: String,
    /// The `-L` trust flags under that nickname.
    trust: Vec<String>,
    /// The subject group of the CA (`-L -n` lists every certificate with the nickname's
    /// subject) holds the CA only. Only then do the trust flags and the nickname-addressed
    /// `-M` and `-D`, which resolve the nickname to one "best" certificate of the group,
    /// certainly concern the CA.
    alone: bool,
}

impl Found {
    /// The SSL `C` flag of the CA; `None` when the subject group makes it ambiguous.
    fn ssl_trusted(&self) -> Option<bool> {
        self.alone.then(|| {
            self.trust
                .iter()
                .any(|t| t.split(',').next().is_some_and(|ssl| ssl.contains('C')))
        })
    }

    /// Refuses a nickname-addressed change to a group holding other certificates too.
    fn require_alone(&self) -> io::Result<()> {
        if self.alone {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "the NSS database holds another certificate with the same subject as \"{}\"; \
                 certutil cannot tell them apart, so change the certificate in the browser's \
                 certificate manager",
                self.nickname
            )))
        }
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
            // certutil may exit without reading it; its status and stderr then tell why.
            match pipe.write_all(input) {
                Err(e) if e.kind() != io::ErrorKind::BrokenPipe => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
                _ => {}
            }
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

    /// The encodings listed under a nickname: its whole subject group. `None` stands for a
    /// block that does not decode: some other certificate.
    fn group(&self, nickname: &str) -> io::Result<Vec<Option<Vec<u8>>>> {
        let pem = self.run(&["-L", "-n", nickname, "-a"], None)?;
        Ok(pem_blocks(&String::from_utf8_lossy(&pem)).collect())
    }

    /// Where the database has exactly `ca`. Our own nickname is tried first (one `certutil`
    /// run after the listing); the other nicknames only when it does not list the CA, for a
    /// CA imported by hand.
    fn find(&self, ca: &Certificate) -> io::Result<Option<Found>> {
        let entries = self.entries()?;
        let ours = nickname(ca);
        let mut nicknames: Vec<&str> = Vec::new();
        for entry in &entries {
            if !nicknames.contains(&entry.nickname.as_str()) {
                nicknames.push(&entry.nickname);
            }
        }
        // A stable sort: ours first, the rest in listing order.
        nicknames.sort_by_key(|n| *n != ours);
        for nickname in nicknames {
            let group = self.group(nickname)?;
            if group.iter().any(|der| ca.is(der.as_deref())) {
                return Ok(Some(Found {
                    nickname: nickname.to_owned(),
                    trust: entries
                        .iter()
                        .filter(|e| e.nickname == nickname)
                        .map(|e| e.trust.clone())
                        .collect(),
                    alone: group.iter().all(|der| ca.is(der.as_deref())),
                }));
            }
        }
        Ok(None)
    }

    fn contains(&self, ca: &Certificate) -> io::Result<bool> {
        Ok(self.find(ca)?.is_some())
    }

    fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
        if let Some(found) = self.find(ca)? {
            found.require_alone()?;
            if found.ssl_trusted() == Some(true) {
                return Ok(InstallOutcome::AlreadyPresent);
            }
            // Present without TLS trust (imported without the "identify websites" box, or a
            // failed earlier attempt): add the trust, keep the other flags.
            let flags = found.trust.first().map_or(",,", String::as_str);
            let (ssl, rest) = flags.split_once(',').unwrap_or((flags, ","));
            let trust = format!("{ssl}C,{rest}");
            self.write(&["-M", "-n", &found.nickname, "-t", &trust], None)?;
            return Ok(InstallOutcome::Installed);
        }
        // `-A` stores the certificate from stdin itself, whatever else the database holds.
        if let Err(e) = self.write(&["-A", "-n", &nickname(ca), "-t", "C,,"], Some(ca.der())) {
            // NSS may have stored the certificate before failing to set its trust (a
            // password-protected database): take it out again when that is unambiguous.
            if let Ok(Some(found)) = self.find(ca)
                && found.alone
            {
                let _ = self.write(&["-D", "-n", &found.nickname], None);
            }
            return Err(e);
        }
        Ok(InstallOutcome::Installed)
    }

    fn remove(&self, ca: &Certificate) -> io::Result<bool> {
        let Some(found) = self.find(ca)? else {
            return Ok(false);
        };
        found.require_alone()?;
        self.write(&["-D", "-n", &found.nickname], None)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::der::Decode as _;

    use super::*;
    use crate::tests::{ca_and_leaf, ca_and_leaf_at, nca_rsa, noncanonical, write};

    /// Creates an empty NSS database in `dir` with `certutil -N`.
    fn create_db(dir: &Path, password: Option<&str>) {
        let mut command = Command::new(CERTUTIL);
        command
            .arg("-N")
            .arg("-d")
            .arg(Certutil::new(CERTUTIL.as_ref(), dir).db);
        match password {
            None => command.arg("--empty-password"),
            Some(password) => {
                let file = dir.join("password.txt");
                std::fs::write(&file, password).unwrap();
                command.arg("-f").arg(file)
            }
        };
        let status = command
            .status()
            .expect("certutil (libnss3-tools) is installed");
        assert!(status.success());
    }

    /// An empty NSS database in a temporary directory.
    fn new_db(password: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        create_db(dir.path(), password);
        dir
    }

    fn certutil(dir: &Path) -> Certutil<'static> {
        Certutil::new(CERTUTIL.as_ref(), dir)
    }

    /// Adds a certificate the way a user's manual import would, with `trust`.
    fn import(dir: &Path, nickname: &str, der: &[u8], trust: &str) {
        certutil(dir)
            .write(&["-A", "-n", nickname, "-t", trust], Some(der))
            .unwrap();
    }

    /// The whole `certutil -L` listing: nicknames and trust flags of every certificate.
    fn listing(dir: &Path) -> String {
        String::from_utf8(certutil(dir).run(&["-L"], None).unwrap()).unwrap()
    }

    fn trust_of(dir: &Path, ca: &Certificate) -> Vec<String> {
        certutil(dir).find(ca).unwrap().unwrap().trust
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
    fn nca_roots_have_their_own_nicknames() {
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (root, issuing) = nca_rsa();
        let (ours, _) = ca_and_leaf("ours@host");
        for ca in [&root, &issuing, &ours] {
            assert_eq!(db.install(ca).unwrap(), InstallOutcome::Installed);
        }
        let named = |ca: &Certificate, cn: &str| {
            assert_eq!(
                certutil(dir.path()).find(ca).unwrap().unwrap().nickname,
                format!("{cn} {}", &hex(&ca.sha256())[..8])
            );
        };
        named(&root, "НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA)");
        named(&issuing, "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (RSA) 2022");
        let own = certutil(dir.path()).find(&ours).unwrap().unwrap().nickname;
        assert_eq!(
            own,
            format!("OpenNCALayer Local CA {}", &hex(&ours.sha256())[..16])
        );
        assert_eq!(listing(dir.path()).matches("OpenNCALayer").count(), 1);

        // Removing the NCA roots leaves the own CA.
        assert!(db.remove(&root).unwrap());
        assert!(db.remove(&issuing).unwrap());
        assert!(!db.contains(&root).unwrap() && !db.contains(&issuing).unwrap());
        assert!(db.contains(&ours).unwrap());
    }

    #[test]
    fn an_nca_root_installs_next_to_one_with_the_same_name() {
        // The 2015 root shares `rcarsa20`'s CN but not its subject, imported by hand under
        // the bare CN: NSS refuses that nickname for another subject.
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (root, _) = nca_rsa();
        let old =
            Certificate::from_der(include_bytes!("../../../fixtures/nca/prod/rcarsa.der").to_vec())
                .unwrap();
        assert_eq!(old.subject_common_name(), root.subject_common_name());
        let cn = old.subject_common_name().unwrap();
        import(dir.path(), &cn, old.der(), "C,,");

        assert_eq!(db.install(&root).unwrap(), InstallOutcome::Installed);
        assert!(db.contains(&root).unwrap() && db.contains(&old).unwrap());
        assert_eq!(trust_of(dir.path(), &root), ["C,,"]);
        assert_eq!(db.install(&root).unwrap(), InstallOutcome::AlreadyPresent);

        // Removal takes exactly the pinned root.
        assert!(db.remove(&root).unwrap());
        assert!(!db.contains(&root).unwrap());
        assert!(db.contains(&old).unwrap());
        assert_eq!(
            certutil(dir.path()).find(&old).unwrap().unwrap().nickname,
            cn
        );
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
        assert_eq!(trust_of(dir.path(), &other), ["C,,"]);
    }

    #[test]
    fn nss_db_never_acts_on_a_same_subject_certificate() {
        // The same label at the same instant: two CAs with the same subject.
        let now = time::OffsetDateTime::now_utc();
        let (ours, _) = ca_and_leaf_at("same@host", now);
        let (sibling, _) = ca_and_leaf_at("same@host", now);
        assert_ne!(ours, sibling);
        let subject = |c: &Certificate| {
            x509_cert::Certificate::from_der(c.der())
                .unwrap()
                .tbs_certificate()
                .subject()
                .clone()
        };
        assert_eq!(subject(&ours), subject(&sibling));

        // The sibling is trusted; ours was imported without trust.
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        assert_eq!(db.install(&sibling).unwrap(), InstallOutcome::Installed);
        import(dir.path(), "Imported by hand", ours.der(), ",,");
        assert!(db.contains(&ours).unwrap());
        let before = listing(dir.path());

        // Neither "already trusted" from the sibling's flags nor a `-M` that may hit it.
        let err = db.install(&ours).unwrap_err();
        assert!(err.to_string().contains("same subject"), "{err}");
        assert_eq!(listing(dir.path()), before);
        for ca in [&ours, &sibling] {
            let err = db.remove(ca).unwrap_err();
            assert!(err.to_string().contains("same subject"), "{err}");
        }
        assert_eq!(listing(dir.path()), before);
        assert!(db.contains(&ours).unwrap());
        assert!(db.contains(&sibling).unwrap());

        let state = db_state(&ours, dir.path().to_owned(), CERTUTIL.as_ref());
        assert_eq!(state.ca_present, Some(true));
        assert_eq!(state.ca_ssl_trusted, None, "ambiguous flags");
    }

    #[test]
    fn nss_db_with_a_certificate_x509_cert_rejects() {
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (stranger, _) = ca_and_leaf("odd@host");
        let odd = noncanonical(&stranger);
        assert!(Certificate::from_der(odd.clone()).is_err());
        import(dir.path(), "Odd", &odd, "C,,");
        assert_eq!(
            certutil(dir.path()).group("Odd").unwrap(),
            [Some(odd.clone())]
        );

        let (ca, _) = ca_and_leaf("ours@host");
        assert!(!db.contains(&ca).unwrap());
        assert_eq!(db.install(&ca).unwrap(), InstallOutcome::Installed);
        assert_eq!(db.install(&ca).unwrap(), InstallOutcome::AlreadyPresent);
        let state = db_state(&ca, dir.path().to_owned(), CERTUTIL.as_ref());
        assert_eq!(state.ca_present, Some(true));
        assert_eq!(state.ca_ssl_trusted, Some(true));
        assert!(db.remove(&ca).unwrap());
        assert!(!db.contains(&ca).unwrap());
        assert_eq!(certutil(dir.path()).group("Odd").unwrap(), [Some(odd)]);
    }

    #[test]
    fn nss_db_install_trusts_a_present_untrusted_certificate() {
        let dir = new_db(None);
        let db = NssDb(dir.path().to_owned());
        let (ca, _) = ca_and_leaf("untrusted@host");
        import(dir.path(), "Imported", ca.der(), ",,");
        assert_eq!(trust_of(dir.path(), &ca), [",,"]);
        let state = db_state(&ca, dir.path().to_owned(), CERTUTIL.as_ref());
        assert_eq!(
            (state.ca_present, state.ca_ssl_trusted),
            (Some(true), Some(false))
        );

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
        // Fails at spawn: no database (and no real certutil) is needed.
        let dir = tempfile::tempdir().unwrap();
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

    /// The trust instructions of oncl-tls name the CA as `install` does.
    #[test]
    fn nickname_matches_the_printed_instructions() {
        let (ca, _) = ca_and_leaf("t@h");
        assert_eq!(nickname(&ca), oncl_tls::nss_nickname(&hex(&ca.sha256())));
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

    #[test]
    fn report_on_a_sandbox_home() {
        let home = tempfile::tempdir().unwrap();
        let chrome = home.path().join(".pki/nssdb");
        std::fs::create_dir_all(&chrome).unwrap();
        create_db(&chrome, None);
        let (ca, _) = ca_and_leaf("report@host");
        let with: &OsStr = CERTUTIL.as_ref();
        let without: &OsStr = "/nonexistent/certutil".as_ref();

        let before = report(&ca, Some(home.path()), with);
        assert_eq!(before.os_store, StoreState::NotApplicable);
        assert_eq!(before.os_chain_ok, None);
        assert!(before.firefox_enterprise_roots.is_empty());
        assert_eq!(
            before.nss,
            [NssDbState {
                path: chrome.clone(),
                ca_present: Some(false),
                ca_ssl_trusted: Some(false),
            }]
        );

        NssDb(chrome.clone()).install(&ca).unwrap();
        let after = report(&ca, Some(home.path()), with);
        assert_eq!(
            (after.nss[0].ca_present, after.nss[0].ca_ssl_trusted),
            (Some(true), Some(true))
        );
        // Without certutil the read-only SQLite query still tells presence, not trust.
        let fallback = report(&ca, Some(home.path()), without);
        assert_eq!(
            (fallback.nss[0].ca_present, fallback.nss[0].ca_ssl_trusted),
            (Some(true), None)
        );
        let (stranger, _) = ca_and_leaf("stranger@host");
        let other = report(&stranger, Some(home.path()), without);
        assert_eq!(other.nss[0].ca_present, Some(false));

        assert!(report(&ca, None, with).nss.is_empty());
    }
}
