//! The public methods of the original's `Applet` (`genKeyPairAndGetPKCS10` is in
//! [`crate::keygen`]). Each answers with its `ResultWrapper`, or throws where the original
//! throws (a `null` it dereferences, an unknown file chooser type).
//!
//! Storage names are Kalkan's `Storage` names (exact). A name Kalkan does not know is
//! `UNKNOWN_STORAGE`. Hardware tokens answer as with no device connected: `EMPTY_SLOT`, or
//! the original's own code for a missing device (`browseKeyStore`: `TOKEN_CHOOSE_CANCEL`;
//! `deleteEntry`, `resetStorage`: `COMMON`; `getPublicPartInfo`:
//! `GETPUBLICPART_EXCEPTION`), without a dialog. `JKS` is read, never written.
//!
//! Paths a page names are never logged. A key file the page names is read only if it is a
//! regular disk file of at most [`oncl_commonutils::MAX_PAGE_FILE`] bytes
//! ([`PageFile::read`]); a folder the page names is used only if it is a folder.

use crate::Applet;
use crate::dispatch::{Args, NPE, Outcome, Thrown, Wrapper};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::{
    Action, Availability, FileKind, FilePrompt, KeyCandidate, KeyPrompt, Locale, OpenError,
    PasswordPrompt, Prompt, StorageAnswer, StorageKind, StoragePrompt, lock_dialog_flow,
};
use oncl_commonutils::{PageFile, is_device_path};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::info::{CertInfo, KncaCertType, cert_info, kcert_types};
use oncl_pki::keystore::{
    KeystoreError, change_password as change_file_password, check_password_pattern,
    install_certificate,
};
use oncl_pki::oid;
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::xmldsig;
use oncl_protocol::AddInfo;
use serde_json::Value;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// The original's `AECodes` this module answers with.
pub(crate) const COMMON: &str = "COMMON";
pub(crate) const UNKNOWN_STORAGE: &str = "UNKNOWN_STORAGE";
pub(crate) const UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION: &str =
    "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION";
pub(crate) const EMPTY_SLOT: &str = "EMPTY_SLOT";
const TOKEN_CHOOSE_CANCEL: &str = "TOKEN_CHOOSE_CANCEL";
const GETPUBLICPART_EXCEPTION: &str = "GETPUBLICPART_EXCEPTION";
const SETCERT_WRONG_PASSWORD: &str = "SETCERT_WRONG_PASSWORD";
const SETCERT_COMMON: &str = "SETCERT_COMMON";
const INAPPROPRIATE_CERT: &str = "INAPPROPRIATE_CERT";
const KEYSTORE_FILE_NOT_FOUND: &str = "KEYSTORE_FILE_NOT_FOUND";
const CHANGEPASS_WRONG_PASSWORD: &str = "CHANGEPASS_WRONG_PASSWORD";
const CHANGEPASS_COMMON: &str = "CHANGEPASS_COMMON";
const CHANGEPASS_INCORRECT_NEWPASS_PATTERN: &str = "CHANGEPASS_INCORRECT_NEWPASS_PATTERN";
const CHANGEPASS_CONTAINS_EMPTY_ALIAS: &str = "CHANGEPASS_CONTAINS_EMPTY_ALIAS";
const SIGN_WRONG_PASSWORD: &str = "SIGN_WRONG_PASSWORD";
const SIGN_CANCEL: &str = "SIGN_CANCEL";

/// `<@>`: the original's separator of key details and installed key files.
const DETAILS_SEPARATOR: &str = "<@>";
/// Origin shown when the connection sent none.
const UNIDENTIFIED: &str = "UNIDENTIFIED";
/// The applet's dialogs are Russian: no request changes their language.
const LOCALE: Locale = Locale::Ru;
/// The PIN tries left that a wrong key file password reports (Kalkan's `-1`).
const FILE_TRY_COUNT: i32 = -1;

/// `showFileChooser(fileExtension, currentDirectory)`: the path of a chosen file (or
/// folder for an empty `fileExtension`), starting in `currentDirectory` if given; nothing
/// if cancelled or if the path does not exist.
pub(crate) fn show_file_chooser(a: &Applet, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    choose_file(a, args.str(0), args.str(1), add_info)
}

/// `browseKeyStore(storageName, fileExtension, currentDirectory)`: the file chooser for a
/// file storage, `KEYSTORE` becoming `P12` or `JKS` after the storage; a token is the
/// token chooser cancelled (no token is connected).
pub(crate) fn browse_key_store(a: &Applet, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    let extension = match storage {
        StorageKind::Token(_) => return Ok(Wrapper::error(TOKEN_CHOOSE_CANCEL)),
        StorageKind::Pkcs12 | StorageKind::Jks => match args.str(1).ok_or(NPE)? {
            "KEYSTORE" if storage == StorageKind::Pkcs12 => "P12",
            "KEYSTORE" => "JKS",
            other => other,
        },
    };
    choose_file(a, Some(extension), args.str(2), add_info)
}

/// The original's `FileChooserDialog`: a `null` type throws, an unknown one too
/// (`FileType.valueOf`).
fn choose_file(
    a: &Applet,
    extension: Option<&str>,
    directory: Option<&str>,
    add_info: &AddInfo,
) -> Outcome {
    let extension = extension.ok_or(NPE)?;
    let kind = if extension.is_empty() {
        FileKind::Directory
    } else {
        FileKind::from_name(extension).ok_or(Thrown("java.lang.IllegalArgumentException"))?
    };
    let prompt = FilePrompt {
        origin: origin(add_info),
        locale: LOCALE,
        kind,
        directory: directory.filter(|d| !d.is_empty()).map(PathBuf::from),
    };
    let answer = {
        let _flow = lock_dialog_flow();
        a.prompter.file(&prompt)
    };
    Ok(match answer {
        Prompt::Answer(path) if path.exists() => Wrapper::ok(path.to_string_lossy().into_owned()),
        Prompt::Answer(_) | Prompt::Cancelled => Wrapper::none(),
    })
}

/// `setPassword()`: [`set_password_with_message`] with the default text.
pub(crate) fn set_password(a: &Applet, _: &Args<'_>, add_info: &AddInfo) -> Outcome {
    ask_password(a, None, add_info)
}

/// `setPassword(message)`: the password dialog showing `message` (the default text for
/// `null` or an empty one); `true` and the password kept if answered, `false` (and the kept
/// password unchanged) if cancelled.
pub(crate) fn set_password_with_message(
    a: &Applet,
    args: &Args<'_>,
    add_info: &AddInfo,
) -> Outcome {
    ask_password(a, args.str(0), add_info)
}

fn ask_password(a: &Applet, message: Option<&str>, add_info: &AddInfo) -> Outcome {
    let prompt = PasswordPrompt {
        origin: origin(add_info),
        locale: LOCALE,
        message: message.filter(|m| !m.is_empty()).map(str::to_owned),
    };
    let answer = {
        let _flow = lock_dialog_flow();
        a.prompter.password(&prompt)
    };
    let answered = match answer {
        Prompt::Answer(password) => {
            a.set_password(Some(password));
            true
        }
        Prompt::Cancelled => false,
    };
    Ok(Wrapper::ok(answered))
}

/// `loadSlotList(storageName)`: the readers with a card of that storage; there are none,
/// whatever the name (the original looks the name up only for a present card).
pub(crate) fn load_slot_list(_: &Applet, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Ok(Wrapper::error(EMPTY_SLOT))
}

/// `getPublicPartInfo(terminalName)`: the owner of an ID card in the reader; there is
/// none.
pub(crate) fn get_public_part_info(_: &Applet, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Ok(Wrapper::error(GETPUBLICPART_EXCEPTION))
}

/// `getTryCount()`: the PIN tries left after the last wrong password.
pub(crate) fn get_try_count(a: &Applet, _: &Args<'_>, _: &AddInfo) -> Outcome {
    Ok(Wrapper::ok(a.try_count()))
}

/// `setX509CertToKeyStore(storageName, container, newDefaultPassword, certPems)`.
pub(crate) fn set_x509_cert_to_key_store(a: &Applet, args: &Args<'_>, _: &AddInfo) -> Outcome {
    set_certificates(a, args.str(0), args.str(1), args.str(2), args.str(3))
}

/// `setX509CertToKeyStoreAndChangePassword(storageName, container, newDefaultPassword,
/// newPassword, certPems)`: the same; as in the original, `newPassword` is not used.
pub(crate) fn set_x509_cert_to_key_store_and_change_password(
    a: &Applet,
    args: &Args<'_>,
    _: &AddInfo,
) -> Outcome {
    set_certificates(a, args.str(0), args.str(1), args.str(2), args.str(4))
}

/// Installs each certificate of `cert_pems` (PEM, separated by `<@>`) next to its key in a
/// key file of the folder `container` that opens with `default_password` (Kalkan's
/// `setX509Certificate`, [`install_certificate`]): the key files' paths, separated by
/// `<@>`. The first failure ends it; earlier certificates stay installed.
fn set_certificates(
    a: &Applet,
    storage_name: Option<&str>,
    container: Option<&str>,
    default_password: Option<&str>,
    cert_pems: Option<&str>,
) -> Outcome {
    let pems = java_split(cert_pems.ok_or(NPE)?, DETAILS_SEPARATOR);
    let Some(storage) = storage(storage_name) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    let storage_oid = match storage {
        StorageKind::Token(_) => return Ok(Wrapper::error(EMPTY_SLOT)),
        StorageKind::Pkcs12 => oid::STORAGE_PKCS12,
        // Refused by `install_certificate`: JKS is not written.
        StorageKind::Jks => oid::STORAGE_JKS,
    };
    let password = Zeroizing::new(default_password.ok_or(NPE)?.to_owned());
    a.set_password(Some(password.clone()));

    let mut paths = Vec::with_capacity(pems.len());
    for pem in pems {
        let Some(cert) = parse_pem_certificate(pem) else {
            return Ok(Wrapper::error(SETCERT_COMMON));
        };
        // The original looks for key files only under a non-null folder; a path it cannot
        // list fails on a NullPointerException.
        let Some(dir) = container.filter(|c| !is_device_path(c)) else {
            return Ok(Wrapper::error(KEYSTORE_FILE_NOT_FOUND));
        };
        let dir = Path::new(dir);
        if !dir.is_dir() {
            return Ok(Wrapper::error(SETCERT_COMMON));
        }
        match install_certificate(dir, &password, &cert, &storage_oid) {
            Ok(path) => paths.push(std::path::absolute(&path).unwrap_or(path)),
            Err(e) => {
                if e == KeystoreError::WrongPassword {
                    a.set_try_count(FILE_TRY_COUNT);
                }
                return Ok(Wrapper::error(match e {
                    KeystoreError::WrongPassword => SETCERT_WRONG_PASSWORD,
                    KeystoreError::InappropriateCert => INAPPROPRIATE_CERT,
                    KeystoreError::KeystoreFileNotFound(_) => KEYSTORE_FILE_NOT_FOUND,
                    _ => SETCERT_COMMON,
                }));
            }
        }
    }
    tracing::info!(certificates = paths.len(), "Applet: certificates installed");
    Ok(if paths.is_empty() {
        Wrapper::none()
    } else {
        let joined: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        Wrapper::ok(joined.join(DETAILS_SEPARATOR))
    })
}

/// `changePassword(storageName, container, oldPassword, newPassword)`: re-encrypts the key
/// file `container`, without a dialog, as the original.
pub(crate) fn change_password(a: &Applet, args: &Args<'_>, _: &AddInfo) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    // `oldPassword.toCharArray()` and `newPassword.toCharArray()` inside the original's
    // `try`: its generic `catch` answers.
    let (Some(old), Some(new)) = (args.str(2), args.str(3)) else {
        return Ok(Wrapper::error(CHANGEPASS_COMMON));
    };
    let code = match storage {
        StorageKind::Token(_) => EMPTY_SLOT,
        // The original checks JKS passwords for their characters alone, then writes the
        // file; JKS is not written here.
        StorageKind::Jks if !jks_password_ok(new) => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
        StorageKind::Jks => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
        StorageKind::Pkcs12 => match change_pkcs12_password(args.str(1), old, new) {
            Ok(()) => {
                tracing::info!("Applet: key file password changed");
                return Ok(Wrapper::none());
            }
            Err(KeystoreError::WrongPassword) => {
                a.set_try_count(FILE_TRY_COUNT);
                CHANGEPASS_WRONG_PASSWORD
            }
            Err(KeystoreError::WrongPasswordPattern { .. }) => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
            Err(KeystoreError::ChangePasswordConstraint) => CHANGEPASS_CONTAINS_EMPTY_ALIAS,
            Err(KeystoreError::UnsupportedStorage) => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
            Err(_) => CHANGEPASS_COMMON,
        },
    };
    Ok(Wrapper::error(code))
}

/// The pattern first, then the page's key file (a regular disk file, else an I/O error).
fn change_pkcs12_password(
    container: Option<&str>,
    old: &str,
    new: &str,
) -> Result<(), KeystoreError> {
    check_password_pattern(new)?;
    let not_found = || KeystoreError::Io("the key file cannot be read".to_owned());
    let container = container.ok_or_else(not_found)?;
    PageFile::read(container).map_err(|_| not_found())?;
    change_file_password(Path::new(container), old, new)
}

/// Kalkan's JKS password check: not empty, at most 32 characters of `0-9 a-z A-Z` and
/// `.?#$^+=!*()@%&_-`.
fn jks_password_ok(password: &str) -> bool {
    !password.is_empty()
        && password.chars().count() <= 32
        && password
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".?#$^+=!*()@%&_-".contains(c))
}

/// `signXml(storageName, container, keyType, xml)`: the storage dialog for the key file
/// `container` (pre-filled; the user may pick another) and its password, the key dialog
/// with the keys of `keyType`, then the enveloped signature of the whole document. Success
/// is the signed document with the key's alias as `secondResult`; cancelling either dialog
/// is `SIGN_CANCEL`. A wrong password or a store without such keys asks again, as the
/// original's dialog does; a signing failure afterwards is the original dialog's
/// `SIGN_WRONG_PASSWORD`.
pub(crate) fn sign_xml(a: &Applet, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    // `inKeyType.toUpperCase()` in the dialog's constructor.
    let key_type = KeyType::of(args.str(2).ok_or(NPE)?);
    if let StorageKind::Token(_) = storage {
        return Ok(Wrapper::error(EMPTY_SLOT));
    }
    let Some(entry) = choose_key(a, storage, args.str(1), key_type, add_info) else {
        return Ok(Wrapper::error(SIGN_CANCEL));
    };
    // `SignatureUtil.signXml` parses the document after the dialogs; its failures leave
    // the dialog's `SIGN_WRONG_PASSWORD` without a try count.
    let Some(xml) = args.str(3) else {
        return Ok(Wrapper::error(SIGN_WRONG_PASSWORD));
    };
    let signed = xmldsig::sign_enveloped(xml.as_bytes(), &entry.key, &entry.cert)
        .ok()
        .and_then(|signed| String::from_utf8(signed).ok());
    let Some(signed) = signed else {
        return Ok(Wrapper::error(SIGN_WRONG_PASSWORD));
    };
    Ok(Wrapper {
        second_result: Some(Value::String(entry.alias)),
        ..Wrapper::ok(signed)
    })
}

/// The keys `signXml` offers (the original dialog's `keyType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyType {
    /// The certificate type wanted; `None` for any.
    wanted: Option<KncaCertType>,
    /// The original's text for a store without such keys.
    empty: OpenError,
}

impl KeyType {
    /// `AUTH`, `INAUTH`, `SIGN`, `INSIGN` (any case), anything else all keys. Only `AUTH`
    /// and `SIGN` have their own text for a store without such keys.
    fn of(name: &str) -> KeyType {
        let (wanted, empty) = match name.to_uppercase().as_str() {
            "AUTH" => (Some(KncaCertType::Authentication), OpenError::NoAuthKeys),
            "INAUTH" => (Some(KncaCertType::Authentication), OpenError::NoKeys),
            "SIGN" => (Some(KncaCertType::Signature), OpenError::NoSigningKeys),
            "INSIGN" => (Some(KncaCertType::Signature), OpenError::NoKeys),
            _ => (None, OpenError::NoKeys),
        };
        KeyType { wanted, empty }
    }

    fn action(self) -> Action {
        if self.wanted == Some(KncaCertType::Authentication) {
            Action::Authenticate
        } else {
            Action::Sign
        }
    }
}

/// The storage dialog then the key dialog, under the process-wide dialog-flow turn;
/// `None` if either is cancelled.
fn choose_key(
    a: &Applet,
    storage: StorageKind,
    container: Option<&str>,
    key_type: KeyType,
    add_info: &AddInfo,
) -> Option<KeyEntry> {
    let origin = origin(add_info);
    let _flow = lock_dialog_flow();
    let mut prompt = StoragePrompt {
        origin: origin.clone(),
        locale: LOCALE,
        action: key_type.action(),
        storages: vec![storage],
        recent_path: container.filter(|c| !c.is_empty()).map(PathBuf::from),
        error: None,
        detail: None,
    };
    let mut keys = loop {
        let Prompt::Answer(answer) = a.prompter.storage(&prompt) else {
            return None;
        };
        match open_keys(&answer, storage, key_type) {
            Ok(keys) => break keys,
            Err(e) => {
                prompt.error = Some(e);
                prompt.recent_path = Some(answer.path);
            }
        }
    };
    let prompt = KeyPrompt {
        origin,
        locale: LOCALE,
        action: key_type.action(),
        candidates: keys
            .iter()
            .map(|(entry, info)| KeyCandidate {
                alias: entry.alias.clone(),
                info: info.clone(),
                availability: Availability::Enabled,
            })
            .collect(),
        detail: None,
    };
    loop {
        match a.prompter.key(&prompt) {
            Prompt::Answer(i) if i < keys.len() => return Some(keys.swap_remove(i).0),
            Prompt::Answer(_) => {}
            Prompt::Cancelled => return None,
        }
    }
}

/// The keys of `key_type` in the answer's key store, oldest certificate first (the
/// original dialog's order). The file is read as a page-named file: the path may be the
/// page's.
fn open_keys(
    answer: &StorageAnswer,
    storage: StorageKind,
    key_type: KeyType,
) -> Result<Vec<(KeyEntry, CertInfo)>, OpenError> {
    if answer.storage != storage {
        return Err(OpenError::UnsupportedStorage);
    }
    let path = answer.path.to_str().ok_or(OpenError::FileNotFound)?;
    let file = PageFile::read(path).map_err(|_| OpenError::FileNotFound)?;
    let entries = match answer.open_data(&file.data) {
        Err(OpenError::NoKeys) => Vec::new(),
        opened => opened?,
    };
    let mut keys: Vec<(KeyEntry, CertInfo)> = entries
        .into_iter()
        .map(|entry| {
            let info = cert_info(&entry.cert);
            (entry, info)
        })
        .filter(|(_, info)| {
            key_type
                .wanted
                .is_none_or(|t| kcert_types(info).contains(&t))
        })
        .collect();
    if keys.is_empty() {
        return Err(key_type.empty);
    }
    keys.sort_by_key(|(_, info)| info.not_before);
    Ok(keys)
}

/// `deleteEntry(storageName, container, alias)`: only token keys are deleted; no token is
/// connected yet.
pub(crate) fn delete_entry(_: &Applet, args: &Args<'_>, _: &AddInfo) -> Outcome {
    Ok(Wrapper::error(match storage(args.str(0)) {
        None => UNKNOWN_STORAGE,
        Some(StorageKind::Token(name)) if name != "AKKZIDCardStore" => COMMON,
        Some(_) => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
    }))
}

/// `resetStorage(storageName, container)`: formats an eToken or JaCarta; no token is
/// connected yet.
pub(crate) fn reset_storage(_: &Applet, args: &Args<'_>, _: &AddInfo) -> Outcome {
    Ok(Wrapper::error(match storage(args.str(0)) {
        None => UNKNOWN_STORAGE,
        Some(StorageKind::Token("AKEToken72KStore" | "AKJaCartaStore" | "AKEToken5110Store")) => {
            COMMON
        }
        Some(_) => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
    }))
}

/// Kalkan's `Storage.get`: the storage of that exact name; `null` names none.
pub(crate) fn storage(name: Option<&str>) -> Option<StorageKind> {
    name.and_then(StorageKind::from_name)
}

/// A certificate as Kalkan's `CertificateFactory` reads a PEM string: the base64 lines
/// between a `-----BEGIN CERTIFICATE` (or `X509 CERTIFICATE`) line and the `-----END`
/// line.
fn parse_pem_certificate(pem: &str) -> Option<Certificate> {
    let start = pem
        .find("-----BEGIN CERTIFICATE")
        .or_else(|| pem.find("-----BEGIN X509 CERTIFICATE"))?;
    let rest = &pem[start..];
    let body = &rest[rest.find('\n')? + 1..];
    let body = &body[..body.find("-----END")?];
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    cert::parse(&STANDARD.decode(base64).ok()?).ok()
}

/// Java's `String.split` with a literal separator: no match is the string itself;
/// otherwise trailing empty parts are dropped (a leading one is kept).
pub(crate) fn java_split<'a>(s: &'a str, separator: &str) -> Vec<&'a str> {
    let mut parts: Vec<&str> = s.split(separator).collect();
    if parts.len() > 1 {
        while parts.last() == Some(&"") {
            parts.pop();
        }
    }
    parts
}

fn origin(add_info: &AddInfo) -> String {
    add_info
        .origin
        .clone()
        .unwrap_or_else(|| UNIDENTIFIED.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_split_drops_trailing_empty_parts() {
        assert_eq!(java_split("", "<@>"), [""]);
        assert_eq!(java_split("a", "<@>"), ["a"]);
        assert_eq!(java_split("a<@>b", "<@>"), ["a", "b"]);
        assert_eq!(java_split("a<@><@>", "<@>"), ["a"]);
        assert_eq!(java_split("<@>a", "<@>"), ["", "a"]);
        assert_eq!(java_split("a<@><@>b", "<@>"), ["a", "", "b"]);
        assert!(java_split("<@>", "<@>").is_empty());
    }

    #[test]
    fn key_types() {
        let auth = KeyType::of("auth");
        assert_eq!(auth.wanted, Some(KncaCertType::Authentication));
        assert_eq!(auth.empty, OpenError::NoAuthKeys);
        assert_eq!(auth.action(), Action::Authenticate);
        assert_eq!(KeyType::of("INAUTH").empty, OpenError::NoKeys);
        assert_eq!(KeyType::of("InSign").wanted, Some(KncaCertType::Signature));
        assert_eq!(KeyType::of("SIGN").empty, OpenError::NoSigningKeys);
        assert_eq!(KeyType::of("SIGN").action(), Action::Sign);
        let all = KeyType::of("ALL");
        assert_eq!((all.wanted, all.empty), (None, OpenError::NoKeys));
        assert_eq!(KeyType::of("").action(), Action::Sign);
    }

    #[test]
    fn jks_passwords() {
        assert!(jks_password_ok("abc"));
        assert!(jks_password_ok(&"a".repeat(32)));
        assert!(!jks_password_ok(&"a".repeat(33)));
        assert!(!jks_password_ok(""));
        assert!(!jks_password_ok("пароль1"));
        assert!(!jks_password_ok("a b"));
    }
}
