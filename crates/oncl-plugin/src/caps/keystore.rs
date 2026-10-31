//! `builtin`: the key files of the built-in modules and the windows that ask for them. A new
//! key goes into a PKCS#12 key file of a folder the user chose in a window of the call, or
//! of one the page names; a certificate goes next to its key; a key file the page names is
//! re-encrypted. The private keys never reach the guest. Passwords and paths are not
//! logged.

use super::{DialogTurn, failed, invalid, limit, origin};
use crate::cause;
use crate::host::HostState;
use der::asn1::ObjectIdentifier;
use oncl_basics::{CsrPrompt, ImportPrompt, PageFile, Prompt, StorageKind, page_path};
use oncl_pdk::abi::cause as causes;
use oncl_pdk::abi::{
    ChangePasswordArgs, CsrChoice, CsrDialogArgs, Folder, HostError, HostResult, IdCardHolder,
    ImportChoice, ImportDialogArgs, InstallCertArgs, InstalledCert, NewKey, NewKeyArgs, Password,
    ReaderName, RequestForm, SecretRef,
};
use oncl_pki::csr::{CsrRequest, KeyStoreInfo, LegacyCsrRequest, build_csr, build_legacy_csr};
use oncl_pki::keygen::{KeySpec, MAX_KEYS_PER_REQUEST, applet_key_id, generate, key_id};
use oncl_pki::keystore::{
    KeystoreError, MAX_CERTIFICATES_PER_REQUEST, certificate_alias, change_password,
    change_password_data, check_password_pattern, create_applet_key_file, create_key_file,
    install_certificate, install_certificate_in_page_folder,
};
use oncl_pki::{cert, oid};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// What a call did with key files so far: the folders its windows answered, and how many
/// keys and certificates it asked for.
#[derive(Default)]
pub(crate) struct KeyFiles {
    folders: Vec<PathBuf>,
    keys: usize,
    certificates: usize,
}

impl KeyFiles {
    /// Keeps the folder of a window's answer: its handle.
    fn keep(&mut self, folder: PathBuf) -> u32 {
        self.folders.push(folder);
        // One folder a window, and a call shows far fewer than u32::MAX windows.
        (self.folders.len() - 1) as u32
    }
}

/// The failure `e` of a key file, with its message and cause.
fn failure(e: &KeystoreError) -> HostError {
    failed(e).with_cause(cause::keystore(e))
}

/// The failure `e` of `keystore_new_key` at `step`.
fn step_failure(step: &str, e: &KeystoreError) -> HostError {
    failed(e).with_cause(&cause::new_key(step, e))
}

fn storage(name: &str) -> HostResult<StorageKind> {
    StorageKind::from_name(name).ok_or_else(|| invalid(format!("{name:?} is not a storage")))
}

/// The password of `password`.
fn password(state: &HostState, password: &Password) -> HostResult<Zeroizing<String>> {
    Ok(Zeroizing::new(match password {
        Password::Text(text) => text.clone(),
        Password::Secret(id) => state.secrets.get(*id)?.to_owned(),
    }))
}

/// How a folder the page names must be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PageFolder {
    /// An existing folder by an absolute path (new key files).
    Absolute,
    /// An existing folder (as the Applet installs certificates: a relative path is the
    /// process's).
    Existing,
}

/// The folder of `folder`: a window's answer of this call, or a folder the page may name
/// (none named is refused as one it may not).
fn folder(state: &HostState, folder: &Folder, page: PageFolder) -> HostResult<PathBuf> {
    match folder {
        Folder::Chosen(id) => state
            .call
            .key_files
            .folders
            .get(*id as usize)
            .cloned()
            .ok_or_else(|| invalid(format!("no window of this call answered the folder {id}"))),
        Folder::Page(path) => {
            let dir = page_path(path).ok_or_else(|| {
                failed("a page may not name this folder")
                    .with_cause(causes::KEYSTORE_FOLDER_REFUSED)
            })?;
            if (page == PageFolder::Absolute && !dir.is_absolute()) || !dir.is_dir() {
                return Err(
                    failed("not an existing folder").with_cause(causes::KEYSTORE_FOLDER_MISSING)
                );
            }
            Ok(dir.to_path_buf())
        }
        Folder::Unnamed => {
            Err(failed("the page named no folder").with_cause(causes::KEYSTORE_FOLDER_REFUSED))
        }
    }
}

/// Subject attributes with their OIDs parsed.
fn subject(dn: &[(String, String)]) -> HostResult<Vec<(ObjectIdentifier, String)>> {
    dn.iter()
        .map(|(oid, value)| {
            let oid = ObjectIdentifier::new(oid)
                .map_err(|_| invalid(format!("{oid:?} is not an OID")))?;
            Ok((oid, value.clone()))
        })
        .collect()
}

/// `dialog_csr`: where `generateCsr` puts the new key files. The answer is checked as the
/// basics module did: a storage not offered or other than PKCS#12, and a folder that is not
/// an existing one by an absolute path, are failures.
pub(crate) fn dialog_csr(
    state: &mut HostState,
    args: CsrDialogArgs,
) -> HostResult<Option<CsrChoice>> {
    let storages = args
        .storages
        .iter()
        .map(|name| storage(name))
        .collect::<HostResult<Vec<_>>>()?;
    if args.ask_password {
        state.secrets.has_room()?;
    }
    let prompt = CsrPrompt {
        origin: origin(state),
        locale: state.call.locale,
        storages,
        ask_password: args.ask_password,
    };
    DialogTurn::hold();
    let answer = match state.services.prompter.csr(&prompt) {
        Prompt::Answer(answer) => answer,
        Prompt::Cancelled => return Ok(None),
    };
    if answer.storage != StorageKind::Pkcs12 || !prompt.storages.contains(&answer.storage) {
        return Err(failure(&KeystoreError::UnsupportedStorage));
    }
    // Key files go into a folder the user picked, never next to the daemon's working
    // directory.
    if !answer.dir.is_absolute() || !answer.dir.is_dir() {
        return Err(failure(&KeystoreError::Io(format!(
            "{}: not a folder",
            answer.dir.display()
        ))));
    }
    let password = if args.ask_password {
        Some(SecretRef {
            id: state.secrets.insert(answer.password)?,
        })
    } else {
        None
    };
    Ok(Some(CsrChoice {
        folder: state.call.key_files.keep(answer.dir),
        storage: answer.storage.name().to_owned(),
        password,
    }))
}

/// `dialog_import`: where the keys of the certificates `importCertificate` installs are,
/// and the password their key files get.
pub(crate) fn dialog_import(
    state: &mut HostState,
    args: ImportDialogArgs,
) -> HostResult<Option<ImportChoice>> {
    let storage = storage(&args.storage)?;
    if args.certificates.len() > MAX_CERTIFICATES_PER_REQUEST {
        return Err(limit(format!(
            "at most {MAX_CERTIFICATES_PER_REQUEST} certificates"
        )));
    }
    let certificates = args
        .certificates
        .iter()
        .map(|der| {
            cert::parse(der)
                .map(|c| oncl_pki::info::cert_info(&c))
                .map_err(|e| invalid(format!("not a certificate: {e}")))
        })
        .collect::<HostResult<Vec<_>>>()?;
    state.secrets.has_room()?;
    let prompt = ImportPrompt {
        origin: origin(state),
        locale: state.call.locale,
        storage,
        // Like every path a page names: a device path, or a network path the user did not
        // choose in the file chooser, is not shown, so the window never browses or opens a
        // host the page chose.
        path: args
            .path
            .as_deref()
            .and_then(page_path)
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf),
        certificates,
    };
    DialogTurn::hold();
    let answer = match state.services.prompter.import_cert(&prompt) {
        Prompt::Answer(answer) => answer,
        Prompt::Cancelled => return Ok(None),
    };
    let new_password = SecretRef {
        id: state.secrets.insert(answer.new_password)?,
    };
    Ok(Some(ImportChoice {
        folder: state.call.key_files.keep(answer.dir),
        new_password,
    }))
}

/// `keystore_new_key`: a new key alone in a PKCS#12 key file of a folder, and its request;
/// the key, then the request (a subject that does not encode leaves no file), then the
/// file.
pub(crate) fn keystore_new_key(state: &mut HostState, args: NewKeyArgs) -> HostResult<NewKey> {
    if state.call.key_files.keys >= MAX_KEYS_PER_REQUEST {
        return Err(limit(format!(
            "at most {MAX_KEYS_PER_REQUEST} keys in a call"
        )));
    }
    let dn = match &args.form {
        RequestForm::Essentials { dn, .. } | RequestForm::Applet { dn, .. } => subject(dn)?,
    };
    let password = password(state, &args.password)?;
    state.call.key_files.keys += 1;
    let dir = folder(state, &args.folder, PageFolder::Absolute)?;
    let spec = KeySpec::from_oid_len(&args.alg, args.bits.unwrap_or(0))
        .map_err(|e| step_failure(causes::KEYSTORE_GENERATE, &e))?;
    let key = generate(spec).map_err(|e| step_failure(causes::KEYSTORE_GENERATE, &e))?;
    let new_key = match args.form {
        RequestForm::Essentials {
            dns_names, email, ..
        } => {
            let pem = build_csr(
                &key,
                spec,
                &CsrRequest {
                    dn: &dn,
                    dns_names: &dns_names,
                    email: email.as_deref(),
                    keystore_info: KeyStoreInfo {
                        storage_oid: oid::STORAGE_PKCS12,
                        path: Some(dir.display().to_string()),
                    },
                },
            )
            .map_err(|e| step_failure(causes::CSR, &e))?;
            create_key_file(&dir, &key, spec, &password)
                .map_err(|e| step_failure(causes::KEYSTORE_WRITE, &e))?;
            NewKey {
                der: pem_der(&pem).into(),
                pem: Some(pem),
                key_id: key_id(&key.public_key()),
            }
        }
        RequestForm::Applet { dns_names, .. } => {
            let key_id = applet_key_id(&key.public_key());
            let der = build_legacy_csr(
                &key,
                spec,
                &LegacyCsrRequest {
                    dn: &dn,
                    key_id: &hex_decode(&key_id),
                    dns_names: dns_names.as_deref(),
                },
            )
            .map_err(|e| step_failure(causes::CSR, &e))?;
            create_applet_key_file(&dir, &key, spec, &password)
                .map_err(|e| step_failure(causes::KEYSTORE_WRITE, &e))?;
            NewKey {
                der: der.into(),
                pem: None,
                key_id,
            }
        }
    };
    tracing::info!(builtin = %state.session.plugin_id, "a key file created");
    Ok(new_key)
}

/// `keystore_install_cert`: the certificate next to its key in a key file of the folder,
/// then, with a new password, that key file re-encrypted with it. A folder the user chose
/// is searched whole, after the new password's pattern; a folder the page names is
/// searched within bounds, after the certificate's own checks (as the Applet orders them).
pub(crate) fn keystore_install_cert(
    state: &mut HostState,
    args: InstallCertArgs,
) -> HostResult<InstalledCert> {
    if state.call.key_files.certificates >= MAX_CERTIFICATES_PER_REQUEST {
        return Err(limit(format!(
            "at most {MAX_CERTIFICATES_PER_REQUEST} certificates in a call"
        )));
    }
    let certificate =
        cert::parse(&args.cert).map_err(|e| invalid(format!("not a certificate: {e}")))?;
    let storage_oid = ObjectIdentifier::new(&args.storage_oid)
        .map_err(|_| invalid(format!("{:?} is not an OID", args.storage_oid)))?;
    let old = password(state, &args.password)?;
    let new = args
        .new_password
        .as_ref()
        .map(|p| password(state, p))
        .transpose()?;
    state.call.key_files.certificates += 1;
    let check_new = || match &new {
        Some(new) => check_password_pattern(new).map_err(|e| failure(&e)),
        None => Ok(()),
    };
    let path = match &args.folder {
        Folder::Chosen(_) => {
            let dir = folder(state, &args.folder, PageFolder::Existing)?;
            check_new()?;
            install_certificate(&dir, &old, &certificate, &storage_oid).map_err(|e| failure(&e))?
        }
        Folder::Page(_) | Folder::Unnamed => {
            certificate_alias(&certificate, &storage_oid).map_err(|e| failure(&e))?;
            let dir = folder(state, &args.folder, PageFolder::Existing)?;
            check_new()?;
            install_certificate_in_page_folder(&dir, &old, &certificate, &storage_oid)
                .map_err(|e| failure(&e))?
        }
    };
    if let Some(new) = &new {
        change_password(&path, &old, new).map_err(|e| failure(&e))?;
    }
    tracing::info!(builtin = %state.session.plugin_id, "a certificate installed");
    let path = std::path::absolute(&path).unwrap_or(path);
    Ok(InstalledCert {
        path: path.display().to_string(),
    })
}

/// `keystore_change_password`: the new password's pattern first, then the key file the
/// page names, read once as a page's file ([`PageFile::read`]; a file it does not read is
/// an I/O failure) and replaced.
pub(crate) fn keystore_change_password(
    state: &mut HostState,
    args: ChangePasswordArgs,
) -> HostResult<()> {
    let old = password(state, &args.old)?;
    let new = password(state, &args.new)?;
    check_password_pattern(&new).map_err(|e| failure(&e))?;
    let file = PageFile::read(&args.file)
        .map_err(|_| failure(&KeystoreError::Io("the key file cannot be read".to_owned())))?;
    change_password_data(Path::new(&args.file), &file.data, &old, &new).map_err(|e| failure(&e))?;
    tracing::info!(builtin = %state.session.plugin_id, "a key file password changed");
    Ok(())
}

/// `tokens_id_card`: the holder of the ID card in the reader, read without the PIN.
pub(crate) fn tokens_id_card(state: &mut HostState, args: ReaderName) -> HostResult<IdCardHolder> {
    let info = state
        .services
        .tokens
        .id_card_info(&args.reader)
        .map_err(failed)?;
    Ok(IdCardHolder {
        full_name: info.full_name(),
        iin: info.iin,
    })
}

/// The DER of a request's PEM.
fn pem_der(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("the core's PEM is base64")
}

/// The bytes of a lowercase hex key identifier.
fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("a hex key identifier"))
        .collect()
}
