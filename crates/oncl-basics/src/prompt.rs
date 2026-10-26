//! What the module asks the user, and the [`Prompter`] that asks: the original's
//! `StorageStage` (storage, file, password) and `KeystoreStage` (key choice) of the signing
//! flow, `CsrStage` (storage, folder, password) of `generateCsr`, `ImportCertStage`
//! (folder, new password) of `importCertificate`, the file chooser other modules hand
//! paths to pages with, and the legacy Applet's password dialog.

use crate::filter::Availability;
use oncl_pki::info::CertInfo;
use oncl_pki::jks::{self, JksError};
use oncl_pki::pkcs12::{self, KeyEntry, Pkcs12Error};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Dialog language, from the request's `locale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    /// Kazakh.
    Kk,
    /// Russian.
    Ru,
    /// English.
    En,
}

impl Locale {
    /// `None` (no `locale`) → Kazakh, `"kk"` → Kazakh, `"ru"` → Russian, anything else →
    /// English. Case is ignored, as Java's `new Locale(…)` lower-cases the language.
    pub fn from_arg(v: Option<&str>) -> Self {
        match v {
            None => Locale::Kk,
            Some(v) if v.eq_ignore_ascii_case("kk") => Locale::Kk,
            Some(v) if v.eq_ignore_ascii_case("ru") => Locale::Ru,
            Some(_) => Locale::En,
        }
    }
}

/// What the chosen key is for, as the dialog words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Signing.
    Sign,
    /// Authentication: the request asks for the clientAuth extended key usage.
    Authenticate,
    /// Handing the key's certificate details to the page; nothing is signed.
    KeyInfo,
}

/// A key storage of Kalkan's `Storage` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    /// A PKCS#12 file (`PKCS12`).
    Pkcs12,
    /// A Java key store file (`JKS`).
    Jks,
    /// A hardware token or cloud storage, by its Kalkan name (e.g. `AKKaztokenStore`).
    Token(&'static str),
}

/// Kalkan's `Storage` values in declaration order.
const ALL: [StorageKind; 9] = [
    StorageKind::Token("AKKaztokenStore"),
    StorageKind::Token("AKKZIDCardStore"),
    StorageKind::Token("AKEToken72KStore"),
    StorageKind::Token("AKEToken5110Store"),
    StorageKind::Token("AKJaCartaStore"),
    StorageKind::Token("AKAKEYStore"),
    StorageKind::Pkcs12,
    StorageKind::Jks,
    StorageKind::Token("ABCloudServiceStore"),
];

impl StorageKind {
    /// The storage named `s` (exact, case-sensitive, as Kalkan's `Storage.get`).
    pub fn from_name(s: &str) -> Option<Self> {
        ALL.into_iter().find(|k| k.name() == s)
    }

    /// Every storage, in Kalkan's order.
    pub fn all() -> Vec<Self> {
        ALL.to_vec()
    }

    /// Kalkan name of the storage.
    pub fn name(&self) -> &'static str {
        match self {
            StorageKind::Pkcs12 => "PKCS12",
            StorageKind::Jks => "JKS",
            StorageKind::Token(name) => name,
        }
    }

    /// Whether OpenNCALayer can open it to sign: PKCS#12 and JKS files.
    pub fn readable(&self) -> bool {
        matches!(self, StorageKind::Pkcs12 | StorageKind::Jks)
    }

    /// Whether OpenNCALayer can write keys and certificates into it: PKCS#12 files only
    /// (JKS is read-only).
    pub fn writable(&self) -> bool {
        *self == StorageKind::Pkcs12
    }
}

/// Why the previous storage answer could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The password does not open the key store.
    WrongPassword,
    /// The file cannot be read.
    FileNotFound,
    /// The file is not a PKCS#12 key store (or uses an unsupported feature).
    NotPkcs12,
    /// The file is not a JKS key store (or uses an unsupported feature).
    NotJks,
    /// The key store holds no keys (of the requested type, for a type other than signing
    /// and authentication).
    NoKeys,
    /// The key store holds no signing keys (of the requested `SIGNATURE` type).
    NoSigningKeys,
    /// The key store holds no authentication keys (of the requested `AUTHENTICATION` type).
    NoAuthKeys,
    /// The chosen storage is not supported (or not allowed by the request).
    UnsupportedStorage,
    /// No password was entered (the legacy Applet's `signXml`).
    EmptyPassword,
    /// The password does not match the policy for keys of internal systems (the legacy
    /// Applet's `signXml` with `INAUTH`/`INSIGN`).
    InnerPasswordPolicy,
}

/// The storage dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePrompt {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// Signing or authentication.
    pub action: Action,
    /// Storages to offer, in order.
    pub storages: Vec<StorageKind>,
    /// Path to pre-fill: the last opened file, or the one just tried on a retry.
    pub recent_path: Option<PathBuf>,
    /// Why the previous answer failed, on a retry.
    pub error: Option<OpenError>,
    /// A line the dialog shows besides the request, e.g. the file to be signed.
    pub detail: Option<String>,
}

/// The user's answer to a [`StoragePrompt`].
pub struct StorageAnswer {
    /// Chosen storage.
    pub storage: StorageKind,
    /// Key store file.
    pub path: PathBuf,
    /// Key store password.
    pub password: Zeroizing<String>,
}

impl StorageAnswer {
    /// Opens the answer's key store, which must be one of `offered` and readable: its keys
    /// that have a certificate, in store order.
    ///
    /// # Errors
    ///
    /// Why it cannot be opened: [`OpenError::UnsupportedStorage`],
    /// [`OpenError::FileNotFound`], [`OpenError::WrongPassword`], [`OpenError::NotPkcs12`],
    /// [`OpenError::NotJks`], or [`OpenError::NoKeys`] for a store without such keys.
    pub fn open(&self, offered: &[StorageKind]) -> Result<Vec<KeyEntry>, OpenError> {
        if !self.storage.readable() || !offered.contains(&self.storage) {
            return Err(OpenError::UnsupportedStorage);
        }
        let data = std::fs::read(&self.path).map_err(|_| OpenError::FileNotFound)?;
        self.open_data(&data)
    }

    /// [`StorageAnswer::open`] of the key store file's contents `data`, read by the caller:
    /// the keys that have a certificate, in store order.
    ///
    /// # Errors
    ///
    /// [`OpenError::UnsupportedStorage`] unless the storage is readable,
    /// [`OpenError::WrongPassword`], [`OpenError::NotPkcs12`], [`OpenError::NotJks`], or
    /// [`OpenError::NoKeys`].
    pub fn open_data(&self, data: &[u8]) -> Result<Vec<KeyEntry>, OpenError> {
        let entries = match self.storage {
            StorageKind::Jks => jks::load(data, &self.password).map_err(|e| match e {
                JksError::WrongPassword => OpenError::WrongPassword,
                JksError::Malformed(_) | JksError::Unsupported(_) => OpenError::NotJks,
            })?,
            StorageKind::Pkcs12 => pkcs12::load(data, &self.password).map_err(|e| match e {
                Pkcs12Error::WrongPassword => OpenError::WrongPassword,
                Pkcs12Error::Malformed(_) | Pkcs12Error::Unsupported(_) => OpenError::NotPkcs12,
            })?,
            StorageKind::Token(_) => return Err(OpenError::UnsupportedStorage),
        };
        if entries.is_empty() {
            return Err(OpenError::NoKeys);
        }
        Ok(entries)
    }
}

/// A key the user may pick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCandidate {
    /// Key store alias.
    pub alias: String,
    /// Certificate details.
    pub info: CertInfo,
    /// Whether it may be picked, and why not.
    pub availability: Availability,
}

/// The key dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPrompt {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// Signing or authentication.
    pub action: Action,
    /// Keys of the opened store, in store order.
    pub candidates: Vec<KeyCandidate>,
    /// A line the dialog shows besides the request, e.g. the file to be signed.
    pub detail: Option<String>,
    /// Why the previous choice failed, on a retry (e.g. the document did not sign).
    pub error: Option<String>,
}

/// The `generateCsr` dialog: where the new key files go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrPrompt {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// Storages to offer, in order.
    pub storages: Vec<StorageKind>,
    /// Whether to ask for the key file password (with a confirmation): the page gave no
    /// `defaultPassword`. Otherwise the page's password is used and the dialog has no
    /// password field.
    pub ask_password: bool,
}

/// The user's answer to a [`CsrPrompt`].
pub struct CsrAnswer {
    /// Chosen storage.
    pub storage: StorageKind,
    /// Folder for the key files.
    pub dir: PathBuf,
    /// The key file password; empty unless [`CsrPrompt::ask_password`].
    pub password: Zeroizing<String>,
}

/// The `importCertificate` dialog: which key files get the certificates, and their new
/// password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPrompt {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// The storage the page names (`allowedStorage`).
    pub storage: StorageKind,
    /// Folder to pre-fill: the page's `keystorePath`, if any.
    pub path: Option<PathBuf>,
    /// The certificates to install, in request order.
    pub certificates: Vec<CertInfo>,
}

/// The user's answer to an [`ImportPrompt`].
pub struct ImportAnswer {
    /// Folder (or key file) holding the keys of the certificates.
    pub dir: PathBuf,
    /// The password the key files get once their certificate is installed.
    pub new_password: Zeroizing<String>,
}

/// What a file chooser accepts: the original's `FileChooser.FileType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A folder (`DIRECTORY`).
    Directory,
    /// `.crl` files (`CRL`).
    Crl,
    /// `.der` and `.cer` files (`CER`).
    Cer,
    /// `.p12` files (`P12`).
    P12,
    /// `.pfx`, `.p12`, `.bin` and `.jks` files (`KEYSTORE`).
    Keystore,
    /// `.jks` files (`JKS`).
    Jks,
    /// Any file (`ALL`).
    All,
}

impl FileKind {
    /// Every kind, in the original's declaration order.
    pub const ALL: [FileKind; 7] = [
        FileKind::Directory,
        FileKind::Crl,
        FileKind::Cer,
        FileKind::P12,
        FileKind::Keystore,
        FileKind::Jks,
        FileKind::All,
    ];

    /// The original's constant name, e.g. `KEYSTORE`.
    pub fn name(self) -> &'static str {
        match self {
            FileKind::Directory => "DIRECTORY",
            FileKind::Crl => "CRL",
            FileKind::Cer => "CER",
            FileKind::P12 => "P12",
            FileKind::Keystore => "KEYSTORE",
            FileKind::Jks => "JKS",
            FileKind::All => "ALL",
        }
    }

    /// The kind named `name` exactly (Java's `valueOf`, case-sensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// File name extensions shown, lowercase without the dot; empty for a folder and for any
    /// file.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            FileKind::Directory | FileKind::All => &[],
            FileKind::Crl => &["crl"],
            FileKind::Cer => &["der", "cer"],
            FileKind::P12 => &["p12"],
            FileKind::Keystore => &["pfx", "p12", "bin", "jks"],
            FileKind::Jks => &["jks"],
        }
    }
}

/// The file chooser: a file or folder whose path goes to the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePrompt {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// What may be chosen.
    pub kind: FileKind,
    /// Folder to start in, if the page names one.
    pub directory: Option<PathBuf>,
}

/// The password dialog of the legacy Applet's `setPassword`: a password the module keeps
/// for later operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPrompt {
    /// The requesting page's origin, or `"UNIDENTIFIED"`.
    pub origin: String,
    /// Dialog language.
    pub locale: Locale,
    /// The page's text for the dialog; `None` shows the default request for the key store
    /// password.
    pub message: Option<String>,
}

/// The outcome of a dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt<T> {
    /// The user answered.
    Answer(T),
    /// The user cancelled or closed the dialog.
    Cancelled,
}

/// Shows the module's dialogs. Calls block until the user answers; the module never shows
/// two dialogs at once.
pub trait Prompter: Send + Sync {
    /// Asks for a storage, file and password.
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer>;
    /// Asks for a key: the index of a candidate.
    fn key(&self, p: &KeyPrompt) -> Prompt<usize>;
    /// Asks where `generateCsr` puts the new keys.
    fn csr(&self, p: &CsrPrompt) -> Prompt<CsrAnswer>;
    /// Asks where the keys of the certificates `importCertificate` installs are, and for
    /// their new password.
    fn import_cert(&self, p: &ImportPrompt) -> Prompt<ImportAnswer>;
    /// Asks for a file, or a folder for [`FileKind::Directory`].
    fn file(&self, p: &FilePrompt) -> Prompt<PathBuf>;
    /// Asks for a password.
    fn password(&self, p: &PasswordPrompt) -> Prompt<Zeroizing<String>>;
}

/// Where the last opened key store path is kept (`recentPath` of settings.json).
pub trait RecentPathStore: Send + Sync {
    /// The last saved path.
    fn load(&self) -> Option<PathBuf>;
    /// Remembers `p`.
    fn save(&self, p: &Path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_kinds_by_name() {
        for kind in FileKind::ALL {
            assert_eq!(FileKind::from_name(kind.name()), Some(kind));
        }
        for other in ["", "p12", "Keystore", "PFX", " ALL"] {
            assert_eq!(FileKind::from_name(other), None, "{other:?}");
        }
        assert_eq!(
            FileKind::Keystore.extensions(),
            ["pfx", "p12", "bin", "jks"]
        );
        assert!(FileKind::Directory.extensions().is_empty());
        assert!(FileKind::All.extensions().is_empty());
    }
}
