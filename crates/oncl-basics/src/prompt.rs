//! What the signing flow asks the user, and the [`Prompter`] that asks: the original's
//! `StorageStage` (storage, file, password) and `KeystoreStage` (key choice).

use crate::filter::Availability;
use oncl_pki::info::CertInfo;
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

/// What the signature is for, as the dialog words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Signing.
    Sign,
    /// Authentication: the request asks for the clientAuth extended key usage.
    Authenticate,
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

    /// Whether OpenNCALayer can open it: in P1 only PKCS#12.
    pub fn supported(&self) -> bool {
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
    /// The key store holds no keys.
    NoKeys,
    /// The chosen storage is not supported (or not allowed by the request).
    UnsupportedStorage,
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
}

/// The outcome of a dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt<T> {
    /// The user answered.
    Answer(T),
    /// The user cancelled or closed the dialog.
    Cancelled,
}

/// Shows the signing dialogs. Calls block until the user answers; the signing flow never
/// shows two dialogs at once.
pub trait Prompter: Send + Sync {
    /// Asks for a storage, file and password.
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer>;
    /// Asks for a key: the index of a candidate.
    fn key(&self, p: &KeyPrompt) -> Prompt<usize>;
}

/// Where the last opened key store path is kept (`recentPath` of settings.json).
pub trait RecentPathStore: Send + Sync {
    /// The last saved path.
    fn load(&self) -> Option<PathBuf>;
    /// Remembers `p`.
    fn save(&self, p: &Path);
}
