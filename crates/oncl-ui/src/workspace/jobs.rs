//! The actions of the tools window, run on a worker thread through the SDK's [`Engine`]:
//! hashing a file, and the public details of a certificate, a signature file, a key store or
//! the tokens plugged in. Nothing here touches Slint, nor a private key.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oncl_core::{Action, Engine, ExecutionGrant, InspectRequest, InspectionKind, OperationPolicy};
use oncl_pki::info::MetadataIntegrity;
use oncl_pki::io::Source;
use oncl_pki::key::HashAlg;
use oncl_token::{ScanProblem, Tokens};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::controller::{JobControl, JobError, MissingField};

/// A hash, as hex.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HashOutput {
    pub(crate) digest: String,
    pub(crate) bytes: u64,
}

/// The digest of `source`.
pub(crate) fn hash(
    engine: &Engine,
    algorithm: HashAlg,
    source: Source<'_>,
    control: &Arc<JobControl>,
) -> Result<HashOutput, JobError> {
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Hash]),
        OperationPolicy::strict_online(),
        control.clone(),
    )?;
    let report = engine.hash(algorithm, source, &mut ctx)?;
    Ok(HashOutput {
        digest: hex(report.digest.as_bytes()),
        bytes: report.bytes_in,
    })
}

/// The digest of the file at `path`, read in pieces: the size is known to the progress at once.
pub(crate) fn hash_file(
    engine: &Engine,
    algorithm: HashAlg,
    path: &Path,
    control: &Arc<JobControl>,
) -> Result<HashOutput, JobError> {
    let mut file = open_regular(path)?;
    let len = file.metadata()?.len();
    control.set_total(len);
    hash(
        engine,
        algorithm,
        Source::seekable(&mut file, Some(len)),
        control,
    )
}

/// Opens `path` only if it is a regular file: a pipe, a device or a FIFO is refused before it is
/// opened, so that no read can block where a cancel cannot reach it.
fn open_regular(path: &Path) -> Result<File, JobError> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(JobError::NotRegular);
    }
    let file = File::open(path)?;
    // The path may have been swapped between the two calls.
    if !file.metadata()?.is_file() {
        return Err(JobError::NotRegular);
    }
    Ok(file)
}

/// What to inspect.
pub(crate) enum Inspect {
    Certificate(PathBuf),
    Signature(PathBuf),
    KeyStore {
        path: PathBuf,
        password: Zeroizing<String>,
        aliases: Vec<String>,
    },
    Tokens,
}

/// A certificate's public facts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) alias: Option<String>,
    pub(crate) subject_cn: Option<String>,
    pub(crate) serial: Option<String>,
    pub(crate) not_before: Option<OffsetDateTime>,
    pub(crate) not_after: Option<OffsetDateTime>,
    pub(crate) signature_oid: Option<String>,
    pub(crate) key_oid: Option<String>,
    /// SHA-256 of the DER, hex.
    pub(crate) fingerprint: Option<String>,
}

/// A token found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TokenFound {
    pub(crate) kind: oncl_token::TokenKind,
    pub(crate) reader: String,
    /// PIN tries left, for the families that report them.
    pub(crate) pin_tries: Option<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InspectOutput {
    Certificates {
        integrity: Option<MetadataIntegrity>,
        entries: Vec<Entry>,
    },
    Signature {
        detached: bool,
        content_len: u64,
        signers: usize,
    },
    Tokens {
        enabled: bool,
        found: Vec<TokenFound>,
        problem: Option<ScanProblem>,
    },
}

/// The public details of `what`; for the files, the SDK's `inspect` with a grant of only that.
pub(crate) fn inspect(
    engine: &Engine,
    tokens: &Tokens,
    what: Inspect,
    control: &Arc<JobControl>,
) -> Result<InspectOutput, JobError> {
    match what {
        Inspect::Tokens => scan_tokens(tokens, control),
        Inspect::Certificate(path) => {
            let report = run(
                engine,
                &InspectRequest::certificate(),
                ExecutionGrant::new([Action::Inspect]),
                &path,
                control,
            )?;
            Ok(certificates(&report))
        }
        Inspect::Signature(path) => {
            let report = run(
                engine,
                &InspectRequest::cms_metadata(),
                ExecutionGrant::new([Action::Inspect]),
                &path,
                control,
            )?;
            let cms = report
                .cms()
                .ok_or(JobError::Operation(oncl_core::ErrorCode::InvalidInput))?;
            Ok(InspectOutput::Signature {
                detached: cms.detached(),
                content_len: cms.content_len(),
                signers: cms.signer_count(),
            })
        }
        Inspect::KeyStore {
            path,
            password,
            aliases,
        } => {
            if aliases.is_empty() {
                return Err(JobError::Input(MissingField::Aliases));
            }
            let grant = ExecutionGrant::new([Action::Inspect]).with_metadata_aliases(aliases);
            let report = run(
                engine,
                &InspectRequest::container(Some(password.as_str())),
                grant,
                &path,
                control,
            )?;
            debug_assert_eq!(report.kind(), InspectionKind::Container);
            let out = certificates(&report);
            // A name the store does not hold is told, not shown as an empty list.
            if matches!(&out, InspectOutput::Certificates { entries, .. } if entries.is_empty()) {
                return Err(JobError::Operation(oncl_core::ErrorCode::KeyNotFound));
            }
            Ok(out)
        }
    }
}

fn run(
    engine: &Engine,
    request: &InspectRequest<'_>,
    grant: ExecutionGrant,
    path: &Path,
    control: &Arc<JobControl>,
) -> Result<oncl_core::InspectionReport, JobError> {
    let mut file = open_regular(path)?;
    let len = file.metadata()?.len();
    control.set_total(len);
    let mut ctx = engine.begin(grant, OperationPolicy::strict_online(), control.clone())?;
    Ok(engine.inspect(
        request,
        Some(Source::seekable(&mut file, Some(len))),
        &mut ctx,
    )?)
}

fn certificates(report: &oncl_core::InspectionReport) -> InspectOutput {
    InspectOutput::Certificates {
        integrity: report.container_integrity(),
        entries: report
            .entries()
            .iter()
            .map(|e| Entry {
                alias: e.alias().map(str::to_owned),
                subject_cn: e.subject_cn().map(str::to_owned),
                serial: e.serial_hex().map(str::to_owned),
                not_before: e.not_before(),
                not_after: e.not_after(),
                signature_oid: e.signature_algorithm_oid().map(str::to_owned),
                key_oid: e.public_key_algorithm_oid().map(str::to_owned),
                fingerprint: e.fingerprint().map(|f| hex(f.as_bytes())),
            })
            .collect(),
    }
}

/// The tokens plugged in and their PIN tries: no PIN is asked, no key is opened. A call to the
/// smart card service cannot be interrupted; a cancel is seen between the tokens.
fn scan_tokens(tokens: &Tokens, control: &Arc<JobControl>) -> Result<InspectOutput, JobError> {
    if !tokens.is_enabled() {
        return Ok(InspectOutput::Tokens {
            enabled: false,
            found: Vec::new(),
            problem: None,
        });
    }
    if control.is_cancelled() {
        return Err(JobError::Cancelled);
    }
    let scan = tokens.scan();
    let mut found = Vec::with_capacity(scan.present.len());
    for present in scan.present {
        if control.is_cancelled() {
            return Err(JobError::Cancelled);
        }
        let pin_tries = tokens
            .pin_tries(&present.reader, present.kind)
            .ok()
            .flatten();
        found.push(TokenFound {
            kind: present.kind,
            reader: present.reader,
            pin_tries,
        });
    }
    Ok(InspectOutput::Tokens {
        enabled: true,
        found,
        problem: scan.problem,
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use oncl_core::EngineServices;
    use oncl_pki::resource::ResourceLimits;

    use super::*;
    use oncl_core::ErrorCode;

    fn engine() -> Engine {
        Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap()
    }

    /// The public facts of a certificate come from the file, and nothing else is asked.
    #[test]
    fn a_certificate_file_gives_its_public_facts() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Subject");
        let cert = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert.der");
        std::fs::write(&path, cert.der()).unwrap();
        let out = inspect(
            &engine(),
            &Tokens::disabled(),
            Inspect::Certificate(path),
            &Arc::new(JobControl::default()),
        )
        .unwrap();
        let InspectOutput::Certificates { entries, .. } = out else {
            panic!("{out:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].subject_cn.as_deref(), Some("Test Subject"));
        assert_eq!(entries[0].fingerprint.as_ref().map(String::len), Some(64));
    }

    #[test]
    fn a_key_store_needs_the_names_to_show() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.p12");
        std::fs::write(&path, b"not a store").unwrap();
        let result = inspect(
            &engine(),
            &Tokens::disabled(),
            Inspect::KeyStore {
                path,
                password: Zeroizing::new("x".to_owned()),
                aliases: Vec::new(),
            },
            &Arc::new(JobControl::default()),
        );
        assert_eq!(result, Err(JobError::Input(MissingField::Aliases)));
    }

    /// Garbage is refused as input, not mistaken for a certificate and not a panic.
    #[test]
    fn a_file_that_is_no_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junk");
        std::fs::write(&path, b"junk junk junk").unwrap();
        let result = inspect(
            &engine(),
            &Tokens::disabled(),
            Inspect::Certificate(path),
            &Arc::new(JobControl::default()),
        );
        assert!(matches!(result, Err(JobError::Operation(_))), "{result:?}");
    }

    #[test]
    fn a_directory_is_not_a_file_to_read() {
        let dir = tempfile::tempdir().unwrap();
        let result = hash_file(
            &engine(),
            HashAlg::Sha256,
            dir.path(),
            &Arc::new(JobControl::default()),
        );
        assert_eq!(result, Err(JobError::NotRegular));
    }

    fn key_store(fixture: &str, password: &str, alias: &str) -> Result<InspectOutput, JobError> {
        inspect(
            &engine(),
            &Tokens::disabled(),
            Inspect::KeyStore {
                path: oncl_testkit::fixture(fixture),
                password: Zeroizing::new(password.to_owned()),
                aliases: vec![alias.to_owned()],
            },
            &Arc::new(JobControl::default()),
        )
    }

    /// The right password and name give the certificate and a verified MAC; no private
    /// material is in the output type at all.
    #[test]
    fn a_pkcs12_store_opens_with_its_password_and_key_name() {
        let out = key_store("openssl/rsa-modern.p12", "Qwerty12", "openssl-rsa").unwrap();
        let InspectOutput::Certificates { integrity, entries } = out else {
            panic!("{out:?}");
        };
        assert_eq!(integrity, Some(MetadataIntegrity::PasswordMacVerified));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias.as_deref(), Some("openssl-rsa"));
        assert!(entries[0].serial.as_deref().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn a_jks_store_opens_with_its_password_and_key_name() {
        let out = key_store("jks/rsa.jks", "Qwerty12", "openncalayer-rsa").unwrap();
        let InspectOutput::Certificates { entries, .. } = out else {
            panic!("{out:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias.as_deref(), Some("openncalayer-rsa"));
    }

    #[test]
    fn a_wrong_password_is_refused_not_shown_as_an_empty_store() {
        for (file, alias) in [
            ("openssl/rsa-modern.p12", "openssl-rsa"),
            ("jks/rsa.jks", "openncalayer-rsa"),
        ] {
            let result = key_store(file, "wrong password", alias);
            assert_eq!(
                result,
                Err(JobError::Operation(ErrorCode::InvalidInput)),
                "{file}"
            );
        }
    }

    #[test]
    fn a_name_the_store_does_not_have_is_a_typed_refusal() {
        for (file, _) in [("openssl/rsa-modern.p12", ()), ("jks/rsa.jks", ())] {
            let result = key_store(file, "Qwerty12", "no-such-key");
            assert_eq!(
                result,
                Err(JobError::Operation(ErrorCode::KeyNotFound)),
                "{file}"
            );
        }
    }

    #[test]
    fn tokens_off_say_so_instead_of_an_empty_list() {
        let out = inspect(
            &engine(),
            &Tokens::disabled(),
            Inspect::Tokens,
            &Arc::new(JobControl::default()),
        )
        .unwrap();
        assert!(matches!(out, InspectOutput::Tokens { enabled: false, .. }));
    }
}
