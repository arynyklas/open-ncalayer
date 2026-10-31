//! The public methods of the original's `Applet` (`genKeyPairAndGetPKCS10` is in
//! [`crate::keygen`]). Each answers with its `ResultWrapper`, or throws where the original
//! throws (a `null` it dereferences, an unknown file chooser type).
//!
//! Storage names are Kalkan's `Storage` names (exact). A name Kalkan does not know is
//! `UNKNOWN_STORAGE`. With token support off, hardware tokens answer as with no device
//! connected: `EMPTY_SLOT`, or the original's own code for a missing device
//! (`browseKeyStore`: `TOKEN_CHOOSE_CANCEL`; `deleteEntry`, `resetStorage`: `COMMON`;
//! `getPublicPartInfo`: `GETPUBLICPART_EXCEPTION`), without a dialog. With it on,
//! `loadSlotList` lists the readers holding a token of the storage, `browseKeyStore` asks
//! for one of them, `getPublicPartInfo` reads an ID card's holder and `signXml` signs on
//! the token; the methods that would write to a connected token answer the original's
//! generic codes without a command to the card. `JKS` is read, never written.
//!
//! Paths a page names are never logged. The core uses a key file or folder the page names
//! only if a page may name it (a local path, or a network path the user chose in the file
//! chooser); it reads a key file only if it is a regular disk file of at most the size of a
//! page's file.

use crate::Core;
use crate::dispatch::{Args, NPE, Outcome, Thrown, Wrapper};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pdk::abi::{
    Action, ChangePasswordArgs, ErrorCode, FlowArgs, FlowChecks, FlowFile, FlowNone, FlowOrder,
    FlowReader, FlowReaders, FlowStart, Folder, HostError, InstallCertArgs, Password, cause,
};
use serde_json::Value;

// The original's `AECodes` this module answers with.
pub(crate) const COMMON: &str = "COMMON";
pub(crate) const UNKNOWN_STORAGE: &str = "UNKNOWN_STORAGE";
pub(crate) const UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION: &str =
    "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION";
pub(crate) const EMPTY_SLOT: &str = "EMPTY_SLOT";
const TOKEN_CHOOSE_CANCEL: &str = "TOKEN_CHOOSE_CANCEL";
const GETPUBLICPART_EXCEPTION: &str = "GETPUBLICPART_EXCEPTION";
const LOAD_SLOT_LIST_EXCEPTION: &str = "LOAD_SLOT_LIST_EXCEPTION";
const UNKNOWN_SMARTCARD: &str = "UNKNOWN_SMARTCARD";
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
/// `<:>`: the original's separator of readers.
const SLOT_SEPARATOR: &str = "<:>";
/// The PIN tries left that a wrong key file password reports (Kalkan's `-1`); so does a
/// wrong PIN of a token that does not tell its tries.
pub(crate) const FILE_TRY_COUNT: i32 = -1;
/// The most certificates a request installs (the original has no limit): they are
/// installed without a window.
const MAX_CERTIFICATES_PER_REQUEST: usize = 16;

/// The storages Kalkan knows, in its order: `PKCS12` and `JKS` are files, the six before
/// them tokens of a family, the last the cloud storage, which no reader holds.
const STORAGES: [&str; 9] = [
    "AKKaztokenStore",
    "AKKZIDCardStore",
    "AKEToken72KStore",
    "AKEToken5110Store",
    "AKJaCartaStore",
    "AKAKEYStore",
    "PKCS12",
    "JKS",
    "ABCloudServiceStore",
];
pub(crate) const PKCS12: &str = "PKCS12";
pub(crate) const JKS: &str = "JKS";
const CLOUD: &str = "ABCloudServiceStore";
/// The storage OIDs of the KeyStoreInfo extension.
const STORAGE_PKCS12_OID: &str = "1.2.398.3.3.5.1.1";
const STORAGE_JKS_OID: &str = "1.2.398.3.3.5.1.2";

/// Kalkan's `Storage.get`: the storage of that exact name; `null` names none.
pub(crate) fn storage(name: Option<&str>) -> Option<&'static str> {
    let name = name?;
    STORAGES.into_iter().find(|s| *s == name)
}

/// A hardware token or the cloud storage (not a file).
pub(crate) fn is_token(storage: &str) -> bool {
    storage != PKCS12 && storage != JKS
}

/// A storage of a hardware token family (not a file, not the cloud storage).
fn has_token_kind(storage: &str) -> bool {
    is_token(storage) && storage != CLOUD
}

/// The readers holding a token of `storage`'s family: none with token support off, for the
/// cloud storage, or when the service fails.
fn token_readers(core: &impl Core, storage: &str) -> Vec<String> {
    core.readers(storage).unwrap_or_default()
}

/// A token of `storage`'s family is connected (with token support on).
pub(crate) fn token_connected(core: &impl Core, storage: &str) -> bool {
    is_token(storage) && !token_readers(core, storage).is_empty()
}

/// `showFileChooser(fileExtension, currentDirectory)`: the path of a chosen file (or
/// folder for an empty `fileExtension`), starting in `currentDirectory` if given; nothing
/// if cancelled or if the path does not exist.
pub(crate) fn show_file_chooser<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    choose_file(core, args.str(0), args.str(1))
}

/// `browseKeyStore(storageName, fileExtension, currentDirectory)`: the file chooser for a
/// file storage, `KEYSTORE` becoming `P12` or `JKS` after the storage. For a token, with
/// token support on, the reader dialog: the chosen reader; with it off (and for the cloud
/// storage) the token chooser cancelled.
pub(crate) fn browse_key_store<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    if is_token(storage) {
        if has_token_kind(storage) && core.tokens().enabled {
            // Opened even without a token: the dialog scans again on request.
            return Ok(match core.choose_reader(storage) {
                Some(reader) => Wrapper::ok(reader),
                None => Wrapper::error(TOKEN_CHOOSE_CANCEL),
            });
        }
        return Ok(Wrapper::error(TOKEN_CHOOSE_CANCEL));
    }
    let extension = match args.str(1).ok_or(NPE)? {
        "KEYSTORE" if storage == PKCS12 => "P12",
        "KEYSTORE" => "JKS",
        other => other,
    };
    choose_file(core, Some(extension), args.str(2))
}

/// The original's `FileChooserDialog`: a `null` type throws, an unknown one too
/// (`FileType.valueOf`). The path given to the page may be named by it later, even on a
/// network share.
fn choose_file(core: &impl Core, extension: Option<&str>, directory: Option<&str>) -> Outcome {
    let extension = extension.ok_or(NPE)?;
    match core.choose_kind(extension, directory) {
        Ok(Some(path)) => Ok(Wrapper::ok(path)),
        Ok(None) => Ok(Wrapper::none()),
        Err(e) if e.cause.as_deref() == Some(cause::FILE_UNKNOWN_KIND) => {
            Err(Thrown("java.lang.IllegalArgumentException"))
        }
        Err(e) => unanswered("file_choose_kind", &e),
    }
}

/// `setPassword()`: [`set_password_with_message`] with the default text.
pub(crate) fn set_password<C: Core>(core: &C, _: &Args<'_>) -> Outcome {
    Ok(Wrapper::ok(core.password(None)))
}

/// `setPassword(message)`: the password dialog showing `message` (the default text for
/// `null` or an empty one); `true` if answered, `false` if cancelled. Nothing reads the
/// password: only the original's token writes did.
pub(crate) fn set_password_with_message<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    let message = args.str(0).filter(|m| !m.is_empty());
    Ok(Wrapper::ok(core.password(message)))
}

/// `loadSlotList(storageName)`: the readers holding a token of that storage, separated by
/// `<:>`; `EMPTY_SLOT` without one, and always with token support off.
pub(crate) fn load_slot_list<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    let tokens = core.tokens();
    if !tokens.enabled {
        return Ok(Wrapper::error(EMPTY_SLOT));
    }
    let Some(storage) = storage(args.str(0)).filter(|s| has_token_kind(s)) else {
        // Unverified against the original: a name of no token family with a card of any
        // kind in some reader is taken for an unknown card.
        return Ok(Wrapper::error(if tokens.any_card {
            UNKNOWN_SMARTCARD
        } else {
            EMPTY_SLOT
        }));
    };
    Ok(match core.readers(storage) {
        Ok(readers) if readers.is_empty() => Wrapper::error(EMPTY_SLOT),
        Ok(readers) => Wrapper::ok(readers.join(SLOT_SEPARATOR)),
        Err(e) => {
            core.warn(&format!("Applet: the readers cannot be listed: {e}"));
            Wrapper::error(LOAD_SLOT_LIST_EXCEPTION)
        }
    })
}

/// `getPublicPartInfo(terminalName)`: the holder of the ID card in the reader, read without
/// the PIN: `IIN<iin> <full name>`; `GETPUBLICPART_EXCEPTION` without one, and always with
/// token support off.
pub(crate) fn get_public_part_info<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    let Some(reader) = args.str(0) else {
        return Ok(Wrapper::error(GETPUBLICPART_EXCEPTION));
    };
    match core.id_card(reader) {
        // Unverified against the original: the layout of the holder's name.
        Ok(holder) => Ok(Wrapper::ok(format!(
            "IIN{} {}",
            holder.iin, holder.full_name
        ))),
        Err(e) => {
            core.debug(&format!("Applet: no ID card details: {}", e.message));
            Ok(Wrapper::error(GETPUBLICPART_EXCEPTION))
        }
    }
}

/// `getTryCount()`: the PIN tries left after the last wrong password.
pub(crate) fn get_try_count<C: Core>(core: &C, _: &Args<'_>) -> Outcome {
    Ok(Wrapper::ok(core.try_count()))
}

/// `setX509CertToKeyStore(storageName, container, newDefaultPassword, certPems)`.
pub(crate) fn set_x509_cert_to_key_store<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    set_certificates(core, args.str(0), args.str(1), args.str(2), args.str(3))
}

/// `setX509CertToKeyStoreAndChangePassword(storageName, container, newDefaultPassword,
/// newPassword, certPems)`: the same; as in the original, `newPassword` is not used.
pub(crate) fn set_x509_cert_to_key_store_and_change_password<C: Core>(
    core: &C,
    args: &Args<'_>,
) -> Outcome {
    set_certificates(core, args.str(0), args.str(1), args.str(2), args.str(4))
}

/// Installs each certificate of `cert_pems` (PEM, separated by `<@>`) next to its key in a
/// key file of the folder `container` that opens with `default_password` (Kalkan's
/// `setX509Certificate`: the page names the folder, so the core looks at most at its first
/// 4096 entries and tries its first 64 key files): the key files' paths, separated by
/// `<@>`. The first failure ends it; earlier certificates stay installed.
///
/// Per certificate, in the original's order: the PEM, its SubjectKeyIdentifier and
/// KeyStoreInfo (`SETCERT_COMMON`), then the folder: none, or one a page may not name (a
/// device path or a network path the user did not choose, refused unlooked), is
/// `KEYSTORE_FILE_NOT_FOUND`; not a folder is `SETCERT_COMMON`. Unlike the original, more
/// than [`MAX_CERTIFICATES_PER_REQUEST`] certificates are `SETCERT_COMMON` before any file
/// is touched.
fn set_certificates(
    core: &impl Core,
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
        PKCS12 => STORAGE_PKCS12_OID,
        // Refused by the core's certificate checks: JKS is not written.
        JKS => STORAGE_JKS_OID,
        token if token_connected(core, token) => {
            core.info("Applet: installing certificates is not supported for tokens");
            return Ok(Wrapper::error(SETCERT_COMMON));
        }
        _ => return Ok(Wrapper::error(EMPTY_SLOT)),
    };
    // Unlike the original, at most `MAX_CERTIFICATES_PER_REQUEST` certificates, checked
    // before any file is touched: these run without a window.
    if pems.len() > MAX_CERTIFICATES_PER_REQUEST {
        return Ok(Wrapper::error(SETCERT_COMMON));
    }
    let password = default_password.ok_or(NPE)?;

    let mut paths = Vec::with_capacity(pems.len());
    for pem in pems {
        let Some(der) = pem_certificate(pem).filter(|der| core.is_certificate(der)) else {
            return Ok(Wrapper::error(SETCERT_COMMON));
        };
        let installed = core.install_cert(InstallCertArgs {
            folder: container.map_or(Folder::Unnamed, |c| Folder::Page(c.to_owned())),
            password: Password::Text(password.to_owned()),
            cert: der.into(),
            storage_oid: storage_oid.to_owned(),
            new_password: None,
        });
        match installed {
            Ok(installed) => paths.push(installed.path),
            Err(e) => {
                let code = match keystore_cause(&e, "keystore_install_cert") {
                    cause::KEYSTORE_FOLDER_REFUSED | cause::KEYSTORE_KEYSTORE_FILE_NOT_FOUND => {
                        KEYSTORE_FILE_NOT_FOUND
                    }
                    cause::KEYSTORE_WRONG_PASSWORD => {
                        core.set_try_count(FILE_TRY_COUNT);
                        SETCERT_WRONG_PASSWORD
                    }
                    cause::KEYSTORE_INAPPROPRIATE_CERT => INAPPROPRIATE_CERT,
                    _ => SETCERT_COMMON,
                };
                return Ok(Wrapper::error(code));
            }
        }
    }
    core.info(&format!("Applet: certificates installed: {}", paths.len()));
    Ok(if paths.is_empty() {
        Wrapper::none()
    } else {
        Wrapper::ok(paths.join(DETAILS_SEPARATOR))
    })
}

/// `changePassword(storageName, container, oldPassword, newPassword)`: re-encrypts the key
/// file `container`, without a dialog, as the original. The core checks the new password
/// first, by the storage's rule (provider `validatePasswordPattern`); then it reads the file
/// once, as a page-named file, and replaces it.
pub(crate) fn change_password<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    // `oldPassword.toCharArray()` and `newPassword.toCharArray()` inside the original's
    // `try`: its generic `catch` answers.
    let (Some(old), Some(new)) = (args.str(2), args.str(3)) else {
        return Ok(Wrapper::error(CHANGEPASS_COMMON));
    };
    let code = match storage {
        PKCS12 => {
            let changed = core.change_password(ChangePasswordArgs {
                // No file is a file the core cannot read: an I/O failure after the pattern.
                file: args.str(1).unwrap_or_default().to_owned(),
                old: Password::Text(old.to_owned()),
                new: Password::Text(new.to_owned()),
            });
            match changed {
                Ok(()) => {
                    core.info("Applet: key file password changed");
                    return Ok(Wrapper::none());
                }
                Err(e) => match keystore_cause(&e, "keystore_change_password") {
                    cause::KEYSTORE_WRONG_PASSWORD => {
                        core.set_try_count(FILE_TRY_COUNT);
                        CHANGEPASS_WRONG_PASSWORD
                    }
                    cause::KEYSTORE_WRONG_PASSWORD_PATTERN => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
                    cause::KEYSTORE_CHANGE_PASSWORD_CONSTRAINT => CHANGEPASS_CONTAINS_EMPTY_ALIAS,
                    cause::KEYSTORE_UNSUPPORTED_STORAGE => {
                        UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION
                    }
                    _ => CHANGEPASS_COMMON,
                },
            }
        }
        _ => match other_password_rule(storage) {
            None if new.is_empty() => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
            None => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
            Some(max) if !pin_pattern_ok(new, max) => CHANGEPASS_INCORRECT_NEWPASS_PATTERN,
            // JKS is not written.
            Some(_) if storage == JKS => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
            // OpenNCALayer does not write to tokens; without one the device is missing.
            Some(_) => {
                refused_on_token(core, storage, "changing the PIN");
                CHANGEPASS_COMMON
            }
        },
    };
    Ok(Wrapper::error(code))
}

/// The `keystore.*` cause of a failure of the core's key files.
///
/// # Panics
///
/// A failure without one: the module sent what the core refuses, which it never does.
pub(crate) fn keystore_cause<'e>(e: &'e HostError, function: &str) -> &'e str {
    match e.cause.as_deref() {
        Some(c) if e.code == ErrorCode::Failed && c.starts_with("keystore.") => c,
        Some(c) if e.code == ErrorCode::Failed && c.starts_with("csr.") => c,
        _ => unanswered(function, e),
    }
}

/// A failure of the core the module has no answer for: the connection is dropped.
///
/// # Panics
///
/// Always.
pub(crate) fn unanswered(function: &str, e: &HostError) -> ! {
    panic!("{function}: {:?} {}", e.code, e.message)
}

/// The longest new password of a storage other than PKCS#12 (provider
/// `validatePasswordPattern`); `None` where the password cannot be changed (ID cards,
/// cloud storage).
fn other_password_rule(storage: &str) -> Option<usize> {
    match storage {
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
///
/// A token (with token support on) is asked for in the readers holding one, `container`
/// first if it names one of them, with its PIN typed in the core's dialog; a wrong PIN sets
/// the try count and asks again; a blocked PIN is not tried again. Without such a reader it
/// is `EMPTY_SLOT`, without a dialog; so is a token that goes, or a smart card service that
/// fails, between listing the readers and opening the dialog.
pub(crate) fn sign_xml<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    let Some(storage) = storage(args.str(0)) else {
        return Ok(Wrapper::error(UNKNOWN_STORAGE));
    };
    // `inKeyType.toUpperCase()` in the dialog's constructor.
    let key_type = KeyType::of(args.str(2).ok_or(NPE)?);
    let (readers, start) = if is_token(storage) {
        let mut readers = token_readers(core, storage);
        if readers.is_empty() {
            return Ok(Wrapper::error(EMPTY_SLOT));
        }
        if let Some(i) = args
            .str(1)
            .and_then(|c| readers.iter().position(|r| r == c))
        {
            let container = readers.remove(i);
            readers.insert(0, container);
        }
        let readers = readers
            .into_iter()
            .map(|reader| FlowReader {
                storage: storage.to_owned(),
                reader,
            })
            .collect();
        (FlowReaders::Fixed(readers), FlowStart::Empty)
    } else {
        // A file's dialog starts with the page's `container` unless a page may not name it
        // (a device path, or a network path the user did not choose in the file chooser).
        let start = args
            .str(1)
            .map_or(FlowStart::Empty, |c| FlowStart::Page(c.to_owned()));
        (FlowReaders::None, start)
    };
    let flow = FlowArgs {
        action: key_type.action(),
        storages: vec![storage.to_owned()],
        readers,
        start,
        remember: false,
        detail: None,
        non_empty_password: true,
        inner_password_policy: key_type.inner,
        same_storage: true,
        file: FlowFile::Chosen,
        knca_types: key_type.wanted.map(|t| vec![t.to_owned()]),
        none: key_type.empty,
        empty_is_none: true,
        order: FlowOrder::OldestFirst,
        checks: FlowChecks::Settled,
        skip_blocked_reader: true,
    };
    let Some((opened, wrong_pin)) = core.flow_open(&flow) else {
        return Ok(Wrapper::error(EMPTY_SLOT));
    };
    if let Some(wrong) = wrong_pin {
        core.set_try_count(token_try_count(&wrong.storage, wrong.tries_left));
    }
    let Some(opened) = opened else {
        return Ok(Wrapper::error(SIGN_CANCEL));
    };
    let mut error = None;
    loop {
        let Some(key) = core.pick(&opened, error.take().as_deref()) else {
            return Ok(Wrapper::error(SIGN_CANCEL));
        };
        match sign_document(core, &key, args.str(3)) {
            Ok(signed) => {
                return Ok(Wrapper {
                    second_result: Some(Value::String(core.alias(&key).to_owned())),
                    ..Wrapper::ok(signed)
                });
            }
            Err(e) => error = Some(format!("Не удалось подписать документ: {e}")),
        }
    }
}

/// `SignatureUtil.signXml`: the enveloped signature of the whole document `xml`.
fn sign_document<C: Core>(core: &C, key: &C::Key, xml: Option<&str>) -> Result<String, String> {
    let xml = xml.ok_or_else(|| "документ не передан".to_owned())?;
    match core.sign_xml(key, xml) {
        Ok(signed) => Ok(signed),
        Err(e) if e.code == ErrorCode::Failed => Err(e.message),
        Err(e) => unanswered("keys_sign_xml", &e),
    }
}

/// The keys `signXml` offers (the original dialog's `keyType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyType {
    /// The Kalkan certificate type wanted; `None` for any.
    wanted: Option<&'static str>,
    /// The original's text for a store without such keys.
    empty: FlowNone,
    /// `INAUTH`/`INSIGN`: keys of internal systems, whose password must match the policy
    /// for them.
    inner: bool,
}

/// Kalkan's certificate types `signXml` tells apart.
const AUTHENTICATION: &str = "AUTHENTICATION";
const SIGNATURE: &str = "SIGNATURE";

impl KeyType {
    /// `AUTH`, `INAUTH`, `SIGN`, `INSIGN` (any case), anything else all keys. Only `AUTH`
    /// and `SIGN` have their own text for a store without such keys.
    fn of(name: &str) -> KeyType {
        let (wanted, empty, inner) = match name.to_uppercase().as_str() {
            "AUTH" => (Some(AUTHENTICATION), FlowNone::NoAuthKeys, false),
            "INAUTH" => (Some(AUTHENTICATION), FlowNone::NoKeys, true),
            "SIGN" => (Some(SIGNATURE), FlowNone::NoSigningKeys, false),
            "INSIGN" => (Some(SIGNATURE), FlowNone::NoKeys, true),
            _ => (None, FlowNone::NoKeys, false),
        };
        KeyType {
            wanted,
            empty,
            inner,
        }
    }

    fn action(self) -> Action {
        if self.wanted == Some(AUTHENTICATION) {
            Action::Authenticate
        } else {
            Action::Sign
        }
    }
}

/// `getTryCount` after a wrong PIN: the tries left for Kaztoken and the ID card, else `-1`
/// (AKey tells its tries too, but the original answers `-1` for it).
fn token_try_count(storage: &str, tries_left: Option<u8>) -> i32 {
    match (storage, tries_left) {
        ("AKKaztokenStore" | "AKKZIDCardStore", Some(n)) => i32::from(n),
        _ => FILE_TRY_COUNT,
    }
}

/// `deleteEntry(storageName, container, alias)`: only token keys are deleted, and
/// OpenNCALayer does not write to tokens: the generic failure, connected or not.
pub(crate) fn delete_entry<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    Ok(Wrapper::error(match storage(args.str(0)) {
        None => UNKNOWN_STORAGE,
        Some(token) if is_token(token) && token != "AKKZIDCardStore" => {
            refused_on_token(core, token, "deleting keys");
            COMMON
        }
        Some(_) => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
    }))
}

/// `resetStorage(storageName, container)`: formats an eToken or JaCarta, which OpenNCALayer
/// does not do: the generic failure, connected or not.
pub(crate) fn reset_storage<C: Core>(core: &C, args: &Args<'_>) -> Outcome {
    Ok(Wrapper::error(match storage(args.str(0)) {
        None => UNKNOWN_STORAGE,
        Some(token @ ("AKEToken72KStore" | "AKJaCartaStore" | "AKEToken5110Store")) => {
            refused_on_token(core, token, "formatting");
            COMMON
        }
        Some(_) => UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION,
    }))
}

/// Logs that `what`, a write to a connected token of `storage`, is refused; nothing is sent
/// to the card.
pub(crate) fn refused_on_token(core: &impl Core, storage: &str, what: &str) {
    if token_connected(core, storage) {
        core.info(&format!(
            "Applet: {what} is not supported for tokens ({storage})"
        ));
    }
}

/// A certificate as Kalkan's `CertificateFactory` reads a PEM string: the base64 lines
/// between a `-----BEGIN CERTIFICATE` (or `X509 CERTIFICATE`) line and the `-----END`
/// line, decoded (the core then reads the DER).
fn pem_certificate(pem: &str) -> Option<Vec<u8>> {
    let start = pem
        .find("-----BEGIN CERTIFICATE")
        .or_else(|| pem.find("-----BEGIN X509 CERTIFICATE"))?;
    let rest = &pem[start..];
    let body = &rest[rest.find('\n')? + 1..];
    let body = &body[..body.find("-----END")?];
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).ok()
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use oncl_pdk::Locale;
    use oncl_pdk::abi::{
        FlowWrongPin, HostResult, IdCardHolder, InstalledCert, NewKey, NewKeyArgs, TokenScan,
    };

    /// A core asked for nothing.
    pub(crate) struct NoCore;

    impl Core for NoCore {
        type Flow = ();
        type Key = ();
        fn debug(&self, _: &str) {}
        fn info(&self, _: &str) {}
        fn warn(&self, _: &str) {}
        fn call_locale(&self, _: Locale) {}
        fn try_count(&self) -> i32 {
            unreachable!()
        }
        fn set_try_count(&self, _: i32) {
            unreachable!()
        }
        fn tokens(&self) -> TokenScan {
            unreachable!()
        }
        fn readers(&self, _: &str) -> Result<Vec<String>, String> {
            unreachable!()
        }
        fn choose_reader(&self, _: &str) -> Option<String> {
            unreachable!()
        }
        fn choose_kind(&self, _: &str, _: Option<&str>) -> HostResult<Option<String>> {
            unreachable!()
        }
        fn password(&self, _: Option<&str>) -> bool {
            unreachable!()
        }
        fn id_card(&self, _: &str) -> HostResult<IdCardHolder> {
            unreachable!()
        }
        fn is_certificate(&self, _: &[u8]) -> bool {
            unreachable!()
        }
        fn install_cert(&self, _: InstallCertArgs) -> HostResult<InstalledCert> {
            unreachable!()
        }
        fn new_key(&self, _: NewKeyArgs) -> HostResult<NewKey> {
            unreachable!()
        }
        fn change_password(&self, _: ChangePasswordArgs) -> HostResult<()> {
            unreachable!()
        }
        fn flow_open(&self, _: &FlowArgs) -> Option<(Option<()>, Option<FlowWrongPin>)> {
            unreachable!()
        }
        fn pick(&self, _: &(), _: Option<&str>) -> Option<()> {
            unreachable!()
        }
        fn alias<'k>(&self, _: &'k ()) -> &'k str {
            unreachable!()
        }
        fn sign_xml(&self, _: &(), _: &str) -> HostResult<String> {
            unreachable!()
        }
    }

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
        assert_eq!(auth.wanted, Some(AUTHENTICATION));
        assert_eq!(auth.empty, FlowNone::NoAuthKeys);
        assert!(!auth.inner);
        assert_eq!(auth.action(), Action::Authenticate);
        let inauth = KeyType::of("INAUTH");
        assert_eq!((inauth.empty, inauth.inner), (FlowNone::NoKeys, true));
        assert_eq!(KeyType::of("InSign").wanted, Some(SIGNATURE));
        assert!(KeyType::of("InSign").inner);
        assert_eq!(KeyType::of("SIGN").empty, FlowNone::NoSigningKeys);
        assert_eq!(KeyType::of("SIGN").action(), Action::Sign);
        let all = KeyType::of("ALL");
        assert_eq!(
            (all.wanted, all.empty, all.inner),
            (None, FlowNone::NoKeys, false)
        );
        assert_eq!(KeyType::of("").action(), Action::Sign);
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

    #[test]
    fn try_counts() {
        assert_eq!(token_try_count("AKKaztokenStore", Some(9)), 9);
        assert_eq!(token_try_count("AKKZIDCardStore", Some(2)), 2);
        assert_eq!(token_try_count("AKAKEYStore", Some(9)), -1);
        assert_eq!(token_try_count("AKKaztokenStore", None), -1);
    }

    #[test]
    fn pem_certificates() {
        let pem = "x\n-----BEGIN CERTIFICATE-----\n+/8=\n-----END CERTIFICATE-----";
        assert_eq!(pem_certificate(pem), Some(vec![0xfb, 0xff]));
        assert_eq!(
            pem_certificate("-----BEGIN X509 CERTIFICATE-----\r\n+/ 8=\r\n-----END"),
            Some(vec![0xfb, 0xff])
        );
        assert_eq!(pem_certificate("+/8="), None);
        assert_eq!(
            pem_certificate("-----BEGIN CERTIFICATE-----+/8=-----END"),
            None
        );
        assert_eq!(
            pem_certificate("-----BEGIN CERTIFICATE-----\n!!\n-----END"),
            None
        );
    }

    #[test]
    fn storages() {
        assert_eq!(storage(Some("PKCS12")), Some(PKCS12));
        assert_eq!(storage(Some("pkcs12")), None);
        assert_eq!(storage(None), None);
        assert!(is_token("ABCloudServiceStore") && !has_token_kind("ABCloudServiceStore"));
        assert!(has_token_kind("AKKZIDCardStore"));
        assert!(!is_token(JKS));
    }
}
