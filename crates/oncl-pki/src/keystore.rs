//! Key files as Kalkan's `KeyStoreUtil` keeps them: a new key goes into
//! `<dir>/<PREFIX><keyId>.p12` without a certificate; its certificate is installed later into
//! whichever key file of the directory holds the key; passwords follow the PKCS#12 pattern.
//!
//! Files are replaced atomically (a temporary file in the same directory, then a rename) and
//! are private: mode `0600` on Unix, whatever mode the file had before. On Windows a key file
//! gets the ACL its directory passes on (the temporary file is created there); explicit ACLs
//! of a replaced file are not carried over. Errors carry the codes and messages of the
//! original's `ProviderUtilException`.

use crate::cert::Certificate;
use crate::csr::KeyStoreInfo;
use crate::fsutil::{Access, write_atomically};
use crate::info::cert_info;
use crate::key::{PrivateKey, PublicKey};
use crate::keygen::{KeySpec, key_id};
use crate::oid;
use crate::pkcs12::{self, Contents, Pkcs12Error, WriteEntry, WriteOptions};
use der::Encode;
use der::asn1::ObjectIdentifier;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use x509_cert::ext::pkix::SubjectKeyIdentifier;

/// Prefix of the file name an authentication certificate gives its key file.
const AUTH_PREFIX: &str = "AUTH_";

/// Error of a key file operation. [`KeystoreError::provider_code`] is the original's
/// `ProviderUtilExceptionCode`, where the original raises one; the `Display` text is the
/// original's message, which NCALayer sends to pages (Russian, as in the original).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeystoreError {
    /// The signature algorithm OID (or RSA length) is not one NCALayer generates keys for.
    #[error("UNKNOWN_ALGORITHM")]
    UnknownAlgorithm,
    /// No key file of the directory opens with the password and holds the certificate's
    /// key; the message names the directory and the alias.
    #[error("{0}")]
    KeystoreFileNotFound(String),
    /// The certificate's KeyStoreInfo names another storage.
    #[error("Хранилище ключей не соответствует хранилищу указанному в расширении сертификата.")]
    UnsuitedStorage,
    /// The key under the certificate's alias is not the certificate's key.
    #[error(
        "Хранилище ключей не содержит открытый ключ, который соответствует сертификату для установки."
    )]
    InappropriateCert,
    /// The key file does not open with the password.
    #[error("Неверный пароль.")]
    WrongPassword,
    /// The new password is empty or does not match the PKCS#12 pattern.
    #[error("{}", wrong_password_pattern(*.empty))]
    WrongPasswordPattern {
        /// The password is empty.
        empty: bool,
    },
    /// The key file holds no key.
    #[error(
        "Для данного типа носителя невозможно сменить пароль до установки соответствующего сертификата."
    )]
    ChangePasswordConstraint,
    /// The certificate has no SubjectKeyIdentifier, which names its key.
    #[error("Расширение «Идентификатор ключа субъекта» не найдено.")]
    ExtensionNotFound,
    /// Only PKCS#12 key files are written.
    #[error("UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION")]
    UnsupportedStorage,
    /// A subject name value or alternative name cannot be encoded as its ASN.1 type.
    #[error("invalid certificate request: {0}")]
    InvalidRequest(String),
    /// A certificate extension (SubjectKeyIdentifier, KeyStoreInfo) does not parse, or a
    /// value does not encode.
    #[error("{0}")]
    Malformed(String),
    /// A file cannot be read, written or renamed.
    #[error("{0}")]
    Io(String),
    /// The key file is not a readable PKCS#12 key store.
    #[error(transparent)]
    Pkcs12(Pkcs12Error),
}

impl KeystoreError {
    /// The original's `ProviderUtilExceptionCode` name, or `None` where the original throws
    /// a plain exception ([`KeystoreError::InvalidRequest`], [`KeystoreError::Malformed`],
    /// [`KeystoreError::Io`], [`KeystoreError::Pkcs12`]): the calling module reports its
    /// own generic failure then (e.g. basics `CSR_GENERATING_FAILURE`,
    /// `CERTIFICATE_IMPORTING_FAILURE`).
    pub fn provider_code(&self) -> Option<&'static str> {
        Some(match self {
            KeystoreError::UnknownAlgorithm => "UNKNOWN_ALGORITHM",
            KeystoreError::KeystoreFileNotFound(_) => "KEYSTORE_FILE_NOT_FOUND",
            KeystoreError::UnsuitedStorage => "UNSUITED_STORAGE",
            KeystoreError::InappropriateCert => "INAPPROPRIATE_CERT",
            KeystoreError::WrongPassword => "WRONG_KEYSTORE_PASSWORD",
            KeystoreError::WrongPasswordPattern { .. } => "WRONG_PASSWORD_PATTERN",
            KeystoreError::ChangePasswordConstraint => "CHANGE_PASSWORD_CONSTRAINT",
            KeystoreError::ExtensionNotFound => "EXTENSION_NOT_FOUND",
            KeystoreError::UnsupportedStorage => "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
            KeystoreError::InvalidRequest(_)
            | KeystoreError::Malformed(_)
            | KeystoreError::Io(_)
            | KeystoreError::Pkcs12(_) => return None,
        })
    }
}

impl From<Pkcs12Error> for KeystoreError {
    fn from(e: Pkcs12Error) -> Self {
        match e {
            Pkcs12Error::WrongPassword => KeystoreError::WrongPassword,
            e => KeystoreError::Pkcs12(e),
        }
    }
}

fn wrong_password_pattern(empty: bool) -> &'static str {
    if empty {
        "Пустой пароль не допускается."
    } else {
        "Пароль должен содержать латинские буквы, а также цифры. Максимальная длина для указанного носителя ключей - 32 символов."
    }
}

fn io_error(path: &Path, e: &std::io::Error) -> KeystoreError {
    KeystoreError::Io(format!("{}: {e}", path.display()))
}

fn malformed(e: impl std::fmt::Display) -> KeystoreError {
    KeystoreError::Malformed(e.to_string())
}

/// Writes `key` alone (no certificate) into `<dir>/<PREFIX><keyId>.p12` with the Kalkan
/// profile, `friendlyName` = `localKeyId` = the key identifier, encrypted with `password`.
/// The prefix follows `spec`: `GOST512_`, `GOSTKNCA_`, `RSA256_` or `RSA_`. An existing
/// file of that name (the same key) is replaced.
///
/// # Errors
///
/// [`KeystoreError::UnknownAlgorithm`] if `key` is not a key of `spec`,
/// [`KeystoreError::Io`] if the file cannot be written (e.g. `dir` does not exist).
///
/// # Panics
///
/// If the operating system RNG fails.
pub fn create_key_file(
    dir: &Path,
    key: &PrivateKey,
    spec: KeySpec,
    password: &str,
) -> Result<PathBuf, KeystoreError> {
    if spec.sig_alg().key_alg() != key.alg() {
        return Err(KeystoreError::UnknownAlgorithm);
    }
    let alias = key_id(&key.public_key());
    let path = dir.join(format!("{}{alias}.p12", spec.file_prefix()));
    let entry = WriteEntry {
        alias,
        pkcs8_der: std::mem::take(&mut *key.to_pkcs8_der()),
        cert_der: None,
    };
    store(&path, &[entry], &[], password)?;
    Ok(path)
}

/// Installs `cert` next to its key, as the original's `setX509Certificate` does for file
/// storages:
/// 1. the alias is the certificate's SubjectKeyIdentifier (hex);
/// 2. a KeyStoreInfo extension naming another storage than `storage_oid` is refused;
/// 3. the key file is the first `*.p12` / `*.jks` file of the directory `dir_or_file` (by
///    name) that opens as PKCS#12 with `password` and holds a key under the alias, or
///    `dir_or_file` itself when it is a file;
/// 4. the key must be the certificate's key (Kalkan pairs by alias alone);
/// 5. the file is rewritten with the certificate, then renamed `AUTH_<name>` when the
///    certificate is an authentication certificate whose signature algorithm is not
///    GOST 2015-512 (those keys are dual-use).
///
/// Returns the path of the key file.
///
/// # Errors
///
/// [`KeystoreError::ExtensionNotFound`], [`KeystoreError::UnsuitedStorage`],
/// [`KeystoreError::UnsupportedStorage`] unless `storage_oid` is PKCS#12,
/// [`KeystoreError::KeystoreFileNotFound`], [`KeystoreError::InappropriateCert`],
/// [`KeystoreError::Malformed`], [`KeystoreError::Io`].
///
/// # Panics
///
/// If the operating system RNG fails.
pub fn install_certificate(
    dir_or_file: &Path,
    password: &str,
    cert: &Certificate,
    storage_oid: &ObjectIdentifier,
) -> Result<PathBuf, KeystoreError> {
    let alias = match cert
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
    {
        Ok(Some((_, ski))) => pkcs12::hex(ski.0.as_bytes()),
        Ok(None) => return Err(KeystoreError::ExtensionNotFound),
        Err(e) => return Err(malformed(format!("SubjectKeyIdentifier: {e}"))),
    };
    if let Some(info) = KeyStoreInfo::of_certificate(cert)?
        && info.storage_oid != *storage_oid
    {
        return Err(KeystoreError::UnsuitedStorage);
    }
    if *storage_oid != oid::STORAGE_PKCS12 {
        return Err(KeystoreError::UnsupportedStorage);
    }

    let (path, contents) = find_key_file(dir_or_file, password, &alias)?;
    let public = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
        .map_err(|_| KeystoreError::InappropriateCert)?;
    let key = contents
        .keys
        .iter()
        .find(|k| k.alias == alias)
        .expect("find_key_file returns a file with the alias");
    if key.key.public_key() != public {
        return Err(KeystoreError::InappropriateCert);
    }
    let cert_der = cert.to_der().map_err(malformed)?;
    rewrite(&path, &contents, password, Some((&alias, cert_der)))?;

    if !needs_auth_name(cert) {
        return Ok(path);
    }
    let name = path.file_name().expect("a key file path has a file name");
    let lossy = name.to_string_lossy();
    if lossy.starts_with(AUTH_PREFIX) || lossy.starts_with("auth_") {
        return Ok(path);
    }
    let mut auth_name = OsString::from(AUTH_PREFIX);
    auth_name.push(name);
    let renamed = path.with_file_name(auth_name);
    fs::rename(&path, &renamed).map_err(|e| io_error(&path, &e))?;
    Ok(renamed)
}

/// Re-encrypts the key file `file` from `old` to `new`, as the original's `changePassword`
/// does for PKCS#12: the new password is checked against the pattern first (see
/// [`check_password_pattern`]), then the file must open with `old` and hold a key. Keys
/// without a certificate are kept and allowed (the original's check never sees them).
///
/// # Errors
///
/// [`KeystoreError::WrongPasswordPattern`], [`KeystoreError::WrongPassword`],
/// [`KeystoreError::ChangePasswordConstraint`] for a file without keys,
/// [`KeystoreError::Io`], [`KeystoreError::Pkcs12`], [`KeystoreError::Malformed`].
///
/// # Panics
///
/// If the operating system RNG fails.
pub fn change_password(file: &Path, old: &str, new: &str) -> Result<(), KeystoreError> {
    check_password_pattern(new)?;
    let bytes = fs::read(file).map_err(|e| io_error(file, &e))?;
    let contents = pkcs12::load_contents(&bytes, old)?;
    if contents.keys.is_empty() {
        return Err(KeystoreError::ChangePasswordConstraint);
    }
    rewrite(file, &contents, new, None)
}

/// Checks a new PKCS#12 password: not empty, 6 to 32 characters of `0-9 a-z A-Z` and
/// `.?#$^+=!*()@%&_-`, at least one digit and one Latin letter.
///
/// # Errors
///
/// [`KeystoreError::WrongPasswordPattern`].
pub fn check_password_pattern(password: &str) -> Result<(), KeystoreError> {
    if password.is_empty() {
        return Err(KeystoreError::WrongPasswordPattern { empty: true });
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || ".?#$^+=!*()@%&_-".contains(c);
    let matches = password.chars().all(allowed)
        && (6..=32).contains(&password.len())
        && password.bytes().any(|b| b.is_ascii_digit())
        && password.bytes().any(|b| b.is_ascii_alphabetic());
    if matches {
        Ok(())
    } else {
        Err(KeystoreError::WrongPasswordPattern { empty: false })
    }
}

/// The key file holding a key under `alias`, opened.
fn find_key_file(
    dir_or_file: &Path,
    password: &str,
    alias: &str,
) -> Result<(PathBuf, Contents), KeystoreError> {
    let candidates = if dir_or_file.is_dir() {
        let mut files: Vec<PathBuf> = fs::read_dir(dir_or_file)
            .map_err(|e| io_error(dir_or_file, &e))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("p12") || ext.eq_ignore_ascii_case("jks")
                    })
            })
            .collect();
        files.sort();
        files
    } else {
        vec![dir_or_file.to_path_buf()]
    };
    for path in candidates {
        // As the original: a file that does not open with the password is skipped.
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(contents) = pkcs12::load_contents(&bytes, password) else {
            continue;
        };
        if contents.keys.iter().any(|k| k.alias == alias) {
            return Ok((path, contents));
        }
    }
    Err(KeystoreError::KeystoreFileNotFound(format!(
        "По указанному пути \"{}\" отсутствует файл, предназначенный для хранения ключей с алиасом - {alias}.",
        dir_or_file.display()
    )))
}

/// Writes `contents` back to `path` with `password`; `install` puts a certificate on the
/// key with that alias.
fn rewrite(
    path: &Path,
    contents: &Contents,
    password: &str,
    install: Option<(&str, Vec<u8>)>,
) -> Result<(), KeystoreError> {
    let mut entries = Vec::with_capacity(contents.keys.len());
    for stored in &contents.keys {
        let cert_der = match &install {
            Some((alias, cert_der)) if *alias == stored.alias => Some(cert_der.clone()),
            _ => stored
                .cert
                .as_ref()
                .map(Encode::to_der)
                .transpose()
                .map_err(malformed)?,
        };
        entries.push(WriteEntry {
            alias: stored.alias.clone(),
            pkcs8_der: std::mem::take(&mut *stored.key.to_pkcs8_der()),
            cert_der,
        });
    }
    let other_certs = contents
        .other_certs
        .iter()
        .map(Encode::to_der)
        .collect::<Result<Vec<_>, _>>()
        .map_err(malformed)?;
    store(path, &entries, &other_certs, password)
}

/// Writes a key store with the Kalkan profile and fresh salts to `path`, atomically and
/// private ([`Access::Private`]).
fn store(
    path: &Path,
    entries: &[WriteEntry],
    other_certs: &[Vec<u8>],
    password: &str,
) -> Result<(), KeystoreError> {
    let p12 = pkcs12::write(
        entries,
        other_certs,
        password,
        &WriteOptions::default(),
        &mut |buf| getrandom::fill(buf).expect("operating system RNG failed"),
    )?;
    write_atomically(path, &p12, Access::Private).map_err(|e| io_error(path, &e))
}

/// Whether installing `cert` renames its key file: an AUTHENTICATION certificate in the
/// original's classification (digitalSignature + nonRepudiation with a sha256WithRSA
/// signature and keyAgreement, or digitalSignature + keyEncipherment + clientAuth) whose
/// signature algorithm is not GOST 2015-512.
fn needs_auth_name(cert: &Certificate) -> bool {
    let info = cert_info(cert);
    let ku = &info.key_usage;
    let sig = info.signature_alg_oid.as_str();
    if sig == oid::GOST_2015_512_SIGNATURE.to_string() {
        return false;
    }
    let legacy = ku.digital_signature
        && ku.non_repudiation
        && ku.key_agreement
        && sig == oid::SHA256_WITH_RSA.to_string();
    let client_auth = ku.digital_signature
        && ku.key_encipherment
        && info.ext_key_usages.contains(&oid::CLIENT_AUTH.to_string());
    legacy || client_auth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs12::{
        ContentInfo, EncryptedData, EncryptedPrivateKeyInfo, Pfx, Pkcs12PbeParams, SafeBag,
    };
    use der::Decode;
    use der::asn1::OctetString;
    use oncl_testkit::{fixture, read};
    use spki::AlgorithmIdentifierOwned;

    /// Checks a PKCS#12 PBE `AlgorithmIdentifier`: `oid`, a 20-byte salt, 1024 iterations.
    fn assert_kalkan_pbe(alg: &AlgorithmIdentifierOwned, oid: ObjectIdentifier) {
        assert_eq!(alg.oid, oid);
        let params: Pkcs12PbeParams = alg.parameters.as_ref().unwrap().decode_as().unwrap();
        assert_eq!(params.salt.as_bytes().len(), 20);
        assert_eq!(params.iterations, 1024);
    }

    /// The safes of a key file, after checking its MAC (HMAC-SHA1, 20-byte salt, 1024
    /// iterations).
    fn kalkan_safes(p12: &[u8]) -> Vec<ContentInfo> {
        let pfx = Pfx::from_der(p12).unwrap();
        assert_eq!(pfx.version, 3);
        let mac = pfx.mac_data.unwrap();
        assert_eq!(mac.mac.algorithm.oid, oid::SHA1);
        assert_eq!(mac.mac.digest.as_bytes().len(), 20);
        assert_eq!(mac.mac_salt.as_bytes().len(), 20);
        assert_eq!(mac.iterations, 1024);
        assert_eq!(pfx.auth_safe.content_type, oid::DATA);
        let auth_safe: OctetString = pfx.auth_safe.content.unwrap().decode_as().unwrap();
        Vec::<ContentInfo>::from_der(auth_safe.as_bytes()).unwrap()
    }

    /// The key safe: one 3DES-shrouded key bag.
    fn assert_kalkan_key_safe(safe: &ContentInfo) {
        assert_eq!(safe.content_type, oid::DATA);
        let bags: OctetString = safe.content.as_ref().unwrap().decode_as().unwrap();
        let bags = Vec::<SafeBag>::from_der(bags.as_bytes()).unwrap();
        assert_eq!(bags.len(), 1);
        assert_eq!(bags[0].bag_id, oid::PKCS8_SHROUDED_KEY_BAG);
        let shrouded: EncryptedPrivateKeyInfo = bags[0].bag_value.decode_as().unwrap();
        assert_kalkan_pbe(&shrouded.encryption_algorithm, oid::PBE_SHA_3DES);
    }

    #[test]
    fn key_files_have_the_kalkan_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let rsa = read(fixture("openssl/rsa.pk8.der"));
        let key = PrivateKey::from_pkcs8_der(&rsa, None).unwrap();
        let path = create_key_file(dir.path(), &key, KeySpec::RsaSha256(2048), "Default1").unwrap();
        let safes = kalkan_safes(&fs::read(&path).unwrap());
        assert_eq!(safes.len(), 1, "no certificate safe without certificates");
        assert_kalkan_key_safe(&safes[0]);

        // With a certificate: an RC2-40 encrypted certificate safe follows.
        let entry = WriteEntry {
            alias: "rsa".to_owned(),
            pkcs8_der: rsa,
            cert_der: Some(read(fixture("openssl/rsa.cer"))),
        };
        store(&path, &[entry], &[], "Default1").unwrap();
        let safes = kalkan_safes(&fs::read(&path).unwrap());
        assert_eq!(safes.len(), 2);
        assert_kalkan_key_safe(&safes[0]);
        assert_eq!(safes[1].content_type, oid::ENCRYPTED_DATA);
        let data: EncryptedData = safes[1].content.as_ref().unwrap().decode_as().unwrap();
        assert_kalkan_pbe(
            &data.encrypted_content_info.content_encryption_algorithm,
            oid::PBE_SHA_RC2_40,
        );
    }
}
