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
//! local regular disk file of at most [`oncl_basics::MAX_PAGE_FILE`] bytes
//! ([`PageFile::read`]); a folder the page names is used only if it is a local folder
//! ([`local_page_path`]): device and network paths are refused before they are looked up.

use crate::Applet;
use crate::dispatch::{Args, NPE, Outcome, Thrown, Wrapper};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::{
    Action, Availability, FileKind, FilePrompt, KeyCandidate, KeyPrompt, Locale, OpenError,
    PageFile, PasswordPrompt, Prompt, StorageAnswer, StorageKind, StoragePrompt, local_page_path,
    lock_dialog_flow,
};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::info::{CertInfo, KncaCertType, cert_info, kcert_types};
use oncl_pki::keystore::{
    KeystoreError, MAX_CERTIFICATES_PER_REQUEST, certificate_alias, change_password_data,
    check_password_pattern, install_certificate_in_page_folder,
};
use oncl_pki::oid;
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::xmldsig;
use oncl_protocol::AddInfo;
use serde_json::Value;
use std::path::Path;
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
        // A network folder is not opened: the system dialog would connect to its host.
        directory: directory
            .and_then(local_page_path)
            .filter(|d| !d.as_os_str().is_empty())
            .map(Path::to_path_buf),
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
/// `setX509Certificate`, [`install_certificate_in_page_folder`]: the page names the folder,
/// so at most its first 4096 entries are looked at and its first 64 key files tried): the
/// key files' paths, separated by `<@>`. The first failure ends it; earlier certificates
/// stay installed.
///
/// Per certificate, in the original's order: the PEM, its SubjectKeyIdentifier and
/// KeyStoreInfo (`SETCERT_COMMON`), then the folder: none, or one a page may not name (a
/// device or network path, refused unlooked), is `KEYSTORE_FILE_NOT_FOUND`; not a folder
/// is `SETCERT_COMMON`. Unlike the original, more than [`MAX_CERTIFICATES_PER_REQUEST`]
/// certificates are `SETCERT_COMMON` before any file is touched.
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
        // Refused by `certificate_alias`: JKS is not written.
        StorageKind::Jks => oid::STORAGE_JKS,
    };
    // Unlike the original, at most `MAX_CERTIFICATES_PER_REQUEST` certificates, checked
    // before any file is touched: these run without a window.
    if pems.len() > MAX_CERTIFICATES_PER_REQUEST {
        return Ok(Wrapper::error(SETCERT_COMMON));
    }
    let password = Zeroizing::new(default_password.ok_or(NPE)?.to_owned());
    a.set_password(Some(password.clone()));

    let mut paths = Vec::with_capacity(pems.len());
    for pem in pems {
        let Some(cert) = parse_pem_certificate(pem) else {
            return Ok(Wrapper::error(SETCERT_COMMON));
        };
        if certificate_alias(&cert, &storage_oid).is_err() {
            return Ok(Wrapper::error(SETCERT_COMMON));
        }
        let Some(dir) = container.and_then(local_page_path) else {
            return Ok(Wrapper::error(KEYSTORE_FILE_NOT_FOUND));
        };
        // The original lists the folder: a path that is none fails on a
        // NullPointerException.
        if !dir.is_dir() {
            return Ok(Wrapper::error(SETCERT_COMMON));
        }
        match install_certificate_in_page_folder(dir, &password, &cert, &storage_oid) {
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
/// file `container`, without a dialog, as the original. The new password is checked first,
/// by the storage's rule (provider `validatePasswordPattern`); then the file is read once,
/// as a page-named file, and replaced.
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
        _ => match other_password_rule(storage) {
            None if new.is_empty() => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
            None => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
            Some(max) if !pin_pattern_ok(new, max) => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
            // JKS is not written.
            Some(_) if storage == StorageKind::Jks => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
            // The token cannot be opened: no device is connected.
            Some(_) => CHANGEPASS_COMMON,
        },
    };
    Ok(Wrapper::error(code))
}

/// The pattern first, then the page's key file, read once ([`PageFile::read`]; a file it
/// does not read is an I/O error) and re-encrypted from those bytes.
fn change_pkcs12_password(
    container: Option<&str>,
    old: &str,
    new: &str,
) -> Result<(), KeystoreError> {
    check_password_pattern(new)?;
    let not_found = || KeystoreError::Io("the key file cannot be read".to_owned());
    let container = container.ok_or_else(not_found)?;
    let file = PageFile::read(container).map_err(|_| not_found())?;
    change_password_data(Path::new(container), &file.data, old, new)
}

/// The longest new password of a storage other than PKCS#12 (provider
/// `validatePasswordPattern`); `None` where the password cannot be changed (ID cards,
/// cloud storage).
fn other_password_rule(storage: StorageKind) -> Option<usize> {
    match storage.name() {
        "AKKaztokenStore" | "AKEToken72KStore" | "AKAKEYStore" | "JKS" => Some(32),
        "AKJaCartaStore" | "AKEToken5110Store" => Some(10),
        _ => None,
    }
}

/// The provider's password rule for storages other than PKCS#12: not empty, at most `max`
/// characters of `0-9 a-z A-Z` and `.?#$^+=!*()@%&_-`.
fn pin_pattern_ok(password: &str, max: usize) -> bool {
    !password.is_empty()
        && password.chars().count() <= max
        && password
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".?#$^+=!*()@%&_-".contains(c))
}

/// `signXml(storageName, container, keyType, xml)`: the storage dialog for the key file
/// `container` (pre-filled; the user may pick another) and its password, the key dialog
/// with the keys of `keyType`, then the enveloped signature of the whole document. Success
/// is the signed document with the key's alias as `secondResult`; cancelling either dialog
/// is `SIGN_CANCEL`. A wrong password or a store without such keys asks again, as the
/// original's dialog does. A document that does not sign keeps the key dialog open with
/// the error, as the original's dialog stays open; the user can only cancel then.
pub(crate) fn sign_xml(a: &Applet, args: &Args<'_>, add_info: &AddInfo) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    // `inKeyType.toUpperCase()` in the dialog's constructor.
    let key_type = KeyType::of(args.str(2).ok_or(NPE)?);
    if let StorageKind::Token(_) = storage {
        return Ok(Wrapper::error(EMPTY_SLOT));
    }
    let origin = origin(add_info);
    let _flow = lock_dialog_flow();
    let Some(mut keys) = open_store(a, storage, args.str(1), key_type, &origin) else {
        return Ok(Wrapper::error(SIGN_CANCEL));
    };
    let mut prompt = KeyPrompt {
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
        error: None,
    };
    loop {
        let i = match a.prompter.key(&prompt) {
            Prompt::Answer(i) if i < keys.len() => i,
            Prompt::Answer(_) => continue,
            Prompt::Cancelled => return Ok(Wrapper::error(SIGN_CANCEL)),
        };
        match sign_document(&keys[i].0, args.str(3)) {
            Ok(signed) => {
                let alias = keys.swap_remove(i).0.alias;
                return Ok(Wrapper {
                    second_result: Some(Value::String(alias)),
                    ..Wrapper::ok(signed)
                });
            }
            Err(e) => prompt.error = Some(format!("Не удалось подписать документ: {e}")),
        }
    }
}

/// `SignatureUtil.signXml`: the enveloped signature of the whole document `xml`.
fn sign_document(entry: &KeyEntry, xml: Option<&str>) -> Result<String, String> {
    let xml = xml.ok_or_else(|| "документ не передан".to_owned())?;
    let signed = xmldsig::sign_enveloped(xml.as_bytes(), &entry.key, &entry.cert)
        .map_err(|e| e.to_string())?;
    // The input was UTF-8 text and only ASCII markup and base64 were spliced in.
    String::from_utf8(signed).map_err(|e| e.to_string())
}

/// The keys `signXml` offers (the original dialog's `keyType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyType {
    /// The certificate type wanted; `None` for any.
    wanted: Option<KncaCertType>,
    /// The original's text for a store without such keys.
    empty: OpenError,
    /// `INAUTH`/`INSIGN`: keys of internal systems, whose password must match
    /// [`inner_password_ok`].
    inner: bool,
}

impl KeyType {
    /// `AUTH`, `INAUTH`, `SIGN`, `INSIGN` (any case), anything else all keys. Only `AUTH`
    /// and `SIGN` have their own text for a store without such keys.
    fn of(name: &str) -> KeyType {
        let (wanted, empty, inner) = match name.to_uppercase().as_str() {
            "AUTH" => (
                Some(KncaCertType::Authentication),
                OpenError::NoAuthKeys,
                false,
            ),
            "INAUTH" => (Some(KncaCertType::Authentication), OpenError::NoKeys, true),
            "SIGN" => (
                Some(KncaCertType::Signature),
                OpenError::NoSigningKeys,
                false,
            ),
            "INSIGN" => (Some(KncaCertType::Signature), OpenError::NoKeys, true),
            _ => (None, OpenError::NoKeys, false),
        };
        KeyType {
            wanted,
            empty,
            inner,
        }
    }

    fn action(self) -> Action {
        if self.wanted == Some(KncaCertType::Authentication) {
            Action::Authenticate
        } else {
            Action::Sign
        }
    }
}

/// The original dialog's password policy for `INAUTH`/`INSIGN`:
/// `^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#$^+=!*()@%&_-]).{8,32}$` — 8 to 32
/// characters (code points, as `java.util.regex` `.` takes a supplementary character
/// whole) without line terminators, with a Latin capital, a Latin small letter, a digit and
/// one of `#$^+=!*()@%&_-`.
fn inner_password_ok(password: &str) -> bool {
    (8..=32).contains(&password.chars().count())
        && !password.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
        && password.chars().any(|c| c.is_ascii_uppercase())
        && password.chars().any(|c| c.is_ascii_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| "#$^+=!*()@%&_-".contains(c))
}

/// The storage dialog until a key store with keys of `key_type` opens; `None` if it is
/// cancelled. The page's `container` pre-fills it unless a page may not name it (a device
/// or network path).
fn open_store(
    a: &Applet,
    storage: StorageKind,
    container: Option<&str>,
    key_type: KeyType,
    origin: &str,
) -> Option<Vec<(KeyEntry, CertInfo)>> {
    let mut prompt = StoragePrompt {
        origin: origin.to_owned(),
        locale: LOCALE,
        action: key_type.action(),
        storages: vec![storage],
        recent_path: container
            .and_then(local_page_path)
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf),
        error: None,
        detail: None,
    };
    loop {
        let Prompt::Answer(answer) = a.prompter.storage(&prompt) else {
            return None;
        };
        match open_keys(&answer, storage, key_type) {
            Ok(keys) => return Some(keys),
            Err(e) => {
                prompt.error = Some(e);
                prompt.recent_path = Some(answer.path);
            }
        }
    }
}

/// The keys of `key_type` in the answer's key store, oldest certificate first (the
/// original dialog's order). The password is checked first, as the original dialog does.
/// The file is the user's choice (pre-filled with a local page path at most), read as
/// [`PageFile::read_chosen`]: a regular disk file of at most 64 MiB, on a network share
/// too.
fn open_keys(
    answer: &StorageAnswer,
    storage: StorageKind,
    key_type: KeyType,
) -> Result<Vec<(KeyEntry, CertInfo)>, OpenError> {
    if answer.password.is_empty() {
        return Err(OpenError::EmptyPassword);
    }
    if key_type.inner && !inner_password_ok(&answer.password) {
        return Err(OpenError::InnerPasswordPolicy);
    }
    if answer.storage != storage {
        return Err(OpenError::UnsupportedStorage);
    }
    let file = PageFile::read_chosen(&answer.path).map_err(|_| OpenError::FileNotFound)?;
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
        assert!(!auth.inner);
        assert_eq!(auth.action(), Action::Authenticate);
        let inauth = KeyType::of("INAUTH");
        assert_eq!((inauth.empty, inauth.inner), (OpenError::NoKeys, true));
        assert_eq!(KeyType::of("InSign").wanted, Some(KncaCertType::Signature));
        assert!(KeyType::of("InSign").inner);
        assert_eq!(KeyType::of("SIGN").empty, OpenError::NoSigningKeys);
        assert_eq!(KeyType::of("SIGN").action(), Action::Sign);
        let all = KeyType::of("ALL");
        assert_eq!(
            (all.wanted, all.empty, all.inner),
            (None, OpenError::NoKeys, false)
        );
        assert_eq!(KeyType::of("").action(), Action::Sign);
    }

    #[test]
    fn inner_passwords() {
        assert!(inner_password_ok("Abcdef1#"));
        assert!(inner_password_ok(&format!("Ab1#{}", "x".repeat(28))));
        assert!(!inner_password_ok(&format!("Ab1#{}", "x".repeat(29))));
        assert!(!inner_password_ok("Abcde1#"));
        assert!(!inner_password_ok("abcdef1#"));
        assert!(!inner_password_ok("ABCDEF1#"));
        assert!(!inner_password_ok("Abcdefg#"));
        assert!(!inner_password_ok("Abcdefg1"));
        // `.` is not a special character of the policy; other characters are allowed.
        assert!(!inner_password_ok("Abcdef1."));
        assert!(inner_password_ok("Абвгд Ab1#"));
        // Code points, not UTF-16 units.
        assert!(!inner_password_ok("Ab1#😀😀"));
        assert!(inner_password_ok(&format!("Ab1#{}", "😀".repeat(28))));
        assert!(!inner_password_ok("Abcdef1#\n"));
    }

    #[test]
    fn pin_patterns() {
        assert!(pin_pattern_ok("abc", 32));
        assert!(pin_pattern_ok(&"a".repeat(32), 32));
        assert!(!pin_pattern_ok(&"a".repeat(33), 32));
        assert!(!pin_pattern_ok(&"a".repeat(11), 10));
        assert!(!pin_pattern_ok("", 32));
        assert!(!pin_pattern_ok("пароль1", 32));
        assert!(!pin_pattern_ok("a b", 32));
    }
}
