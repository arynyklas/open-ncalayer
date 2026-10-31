//! The built-in modules' key files and their windows (`dialog_csr`, `dialog_import`,
//! `keystore_new_key`, `keystore_install_cert`, `keystore_change_password`) and the holder
//! of an ID card (`tokens_id_card`), through guests in WebAssembly text that call them with
//! fixed arguments.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use oncl_basics::StorageKind;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_pdk::abi::{
    self, ChangePasswordArgs, CsrChoice, CsrDialogArgs, ErrorCode, Folder, HostResult,
    IdCardHolder, Import, ImportChoice, ImportDialogArgs, InstallCertArgs, InstalledCert, NewKey,
    NewKeyArgs, Password, ReaderName, RequestForm,
};
use oncl_pki::key::{PrivateKey, PublicKey};
use oncl_pki::keygen::{KeySpec, MAX_KEYS_PER_REQUEST, applet_key_id, generate, key_id};
use oncl_pki::keystore::{
    KeystoreError, MAX_CERTIFICATES_PER_REQUEST, MAX_KEY_FILES, create_key_file,
};
use oncl_pki::oid;
use oncl_pki::pkcs12::{Pkcs12Error, load, load_contents};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_plugin::{
    Engine, HostServices, Instance, LoadError, Manifest, SessionContext, Trust, cause,
};
use oncl_testkit::{read, synthetic};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{IdCardInfo, TokenKind, Tokens};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use x509_cert::ext::Extension;
use x509_cert::request::CertReq;

const ORIGIN: &str = "https://idp.egov.kz";
const PASSWORD: &str = "Default123";
const NEW_PASSWORD: &str = "NewPass456";
const GOST2015: &str = "1.2.398.3.10.1.1.2.3.2";
const GOST2004: &str = "1.2.398.3.10.1.1.1.2";
const R0: &str = "OpenNCALayer Emulated Reader 0";

/// The six host functions of this file.
const KEYSTORE_IMPORTS: [Import; 6] = [
    Import::DialogCsr,
    Import::DialogImport,
    Import::KeystoreNewKey,
    Import::KeystoreInstallCert,
    Import::KeystoreChangePassword,
    Import::TokensIdCard,
];

fn context() -> SessionContext {
    SessionContext {
        trust: Trust::Builtin,
        ..session(1)
    }
}

/// A built-in module making the calls of `stages` (one stage a request).
fn builtin(services: &HostServices, stages: &[Vec<(Import, Vec<u8>)>]) -> Instance {
    let manifest = Manifest::from_toml_builtin(&builtin_manifest("builtin = true")).unwrap();
    Engine::new()
        .compile(&manifest, &wasm(&staged_probe(stages)))
        .unwrap()
        .instantiate(services, context())
        .unwrap()
}

/// The last call's result of one request to `instance`.
fn run<T: DeserializeOwned>(instance: &mut Instance) -> HostResult<T> {
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    probe_result(reply.text().unwrap())
}

/// One request making `calls`, its last result.
fn once<T: DeserializeOwned>(
    services: &HostServices,
    calls: Vec<(Import, Vec<u8>)>,
) -> HostResult<T> {
    run(&mut builtin(services, &[calls]))
}

fn scripted(steps: Vec<Step>) -> (Arc<ScriptedPrompter>, HostServices) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let services = services_with(prompter.clone(), Arc::new(Offline));
    (prompter, services)
}

fn call(import: Import, args: &impl Serialize) -> (Import, Vec<u8>) {
    (import, abi::encode(args))
}

fn csr_dialog(ask_password: bool) -> (Import, Vec<u8>) {
    call(
        Import::DialogCsr,
        &CsrDialogArgs {
            storages: vec!["PKCS12".to_owned(), "AKKaztokenStore".to_owned()],
            ask_password,
        },
    )
}

fn csr_step(dir: &Path, password: &str) -> Step {
    Step::Csr {
        dir: dir.to_path_buf(),
        password: password.to_owned(),
    }
}

/// A GOST 2015 key with `generateCsr`'s request.
fn essentials(folder: Folder, password: Password) -> NewKeyArgs {
    NewKeyArgs {
        folder,
        password,
        alg: GOST2015.to_owned(),
        bits: None,
        form: RequestForm::Essentials {
            dn: vec![
                ("2.5.4.3".to_owned(), "ТЕСТОВ ТЕСТ".to_owned()),
                ("2.5.4.5".to_owned(), "IIN123456789012".to_owned()),
            ],
            dns_names: Vec::new(),
            email: Some("test@example.kz".to_owned()),
        },
    }
}

fn new_key(args: &NewKeyArgs) -> (Import, Vec<u8>) {
    call(Import::KeystoreNewKey, args)
}

fn page(path: &Path) -> Folder {
    Folder::Page(path.display().to_string())
}

/// The file names of `dir`, sorted.
fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A GOST 2015 key alone in a key file of `dir` with [`PASSWORD`].
fn key_file(dir: &Path) -> (PathBuf, PrivateKey) {
    let key = generate(KeySpec::Gost2015_512).unwrap();
    let file = create_key_file(dir, &key, KeySpec::Gost2015_512, PASSWORD).unwrap();
    (file, key)
}

/// A certificate for `key` with `serial`, issued by a synthetic key: with its key
/// identifier as SubjectKeyIdentifier (`ski`), or without one.
fn certificate(key: &PrivateKey, serial: &[u8], ski: bool) -> Vec<u8> {
    let k = synthetic("user-gost2015-sign");
    let issuer = load(&read(&k.path), &k.password).unwrap().remove(0);
    let public = key.public_key();
    let mut extensions = Vec::new();
    if ski {
        let id: Vec<u8> = hex(&key_id(&public));
        extensions.push(Extension {
            extn_id: ObjectIdentifier::new_unwrap("2.5.29.14"),
            critical: false,
            extn_value: OctetString::new(OctetString::new(id).unwrap().to_der().unwrap()).unwrap(),
        });
    }
    let cert = issue_cert(
        &issuer,
        TestCertSpec {
            public_key: public.to_spki(),
            serial: serial.to_vec(),
            extensions,
            ..TestCertSpec::from_cert(&issuer.cert)
        },
    );
    cert.to_der().unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn install(folder: Folder, cert: &[u8], new_password: Option<Password>) -> (Import, Vec<u8>) {
    call(
        Import::KeystoreInstallCert,
        &InstallCertArgs {
            folder,
            password: Password::Text(PASSWORD.to_owned()),
            cert: cert.to_vec().into(),
            storage_oid: oid::STORAGE_PKCS12.to_string(),
            new_password,
        },
    )
}

fn import_dialog(dir: &Path, certs: &[&[u8]]) -> (Import, Vec<u8>) {
    call(
        Import::DialogImport,
        &ImportDialogArgs {
            storage: "PKCS12".to_owned(),
            path: Some(dir.display().to_string()),
            certificates: certs.iter().map(|c| c.to_vec().into()).collect(),
        },
    )
}

/// A path a page may not name.
const NETWORK: &str = "//host/share/keys";

#[track_caller]
fn assert_cause<T: std::fmt::Debug>(result: HostResult<T>, expected: &str) {
    let e = result.unwrap_err();
    assert_eq!(e.code, ErrorCode::Failed, "{e:?}");
    assert_eq!(e.cause(), Some(expected), "{e:?}");
}

// --- new keys -------------------------------------------------------------------------------

#[test]
fn csr_dialog_then_new_key_writes_kalkan_file() {
    let dir = tempfile::tempdir().unwrap();
    let (prompter, services) = scripted(vec![csr_step(dir.path(), "")]);
    let choice: Option<CsrChoice> = once(&services, vec![csr_dialog(false)]).unwrap();
    assert_eq!(
        choice,
        Some(CsrChoice {
            folder: 0,
            storage: "PKCS12".to_owned(),
            password: None,
        })
    );
    let prompt = &prompter.csr_prompts()[0];
    assert_eq!(prompt.origin, ORIGIN);
    assert_eq!(
        prompt.storages,
        [
            StorageKind::Pkcs12,
            StorageKind::from_name("AKKaztokenStore").unwrap()
        ]
    );
    assert!(!prompt.ask_password);
    assert!(files(dir.path()).is_empty(), "the window writes nothing");

    let (_, services) = scripted(vec![csr_step(dir.path(), "")]);
    let made: NewKey = once(
        &services,
        vec![
            csr_dialog(false),
            new_key(&essentials(
                Folder::Chosen(0),
                Password::Text(PASSWORD.to_owned()),
            )),
        ],
    )
    .unwrap();
    let pem = made.pem.expect("generateCsr's request is PEM");
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
        "{pem}"
    );
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert_eq!(STANDARD.decode(body).unwrap(), made.der.to_vec());
    let request = CertReq::from_der(&made.der).unwrap();
    let public = PublicKey::from_spki(&request.info.public_key).unwrap();
    assert_eq!(made.key_id, key_id(&public));
    // The Kalkan key file: named and aliased by the key identifier, no certificate.
    let name = format!("GOST512_{}.p12", made.key_id);
    assert_eq!(files(dir.path()), std::slice::from_ref(&name));
    let contents = load_contents(&read(dir.path().join(&name)), PASSWORD).unwrap();
    assert_eq!(contents.keys.len(), 1);
    assert_eq!(contents.keys[0].alias, made.key_id);
    assert!(contents.keys[0].cert.is_none());
    // KeyStoreInfo names the folder.
    let folder = dir.path().display().to_string();
    assert!(
        made.der
            .windows(folder.len())
            .any(|w| w == folder.as_bytes())
    );

    // Without the page's password the window asks for one; it stays in the core.
    let typed = tempfile::tempdir().unwrap();
    let (prompter, services) = scripted(vec![csr_step(typed.path(), "Typed1234")]);
    let choice: Option<CsrChoice> = once(&services, vec![csr_dialog(true)]).unwrap();
    assert!(prompter.csr_prompts()[0].ask_password);
    assert_eq!(choice.unwrap().password.unwrap().id, 1);
    let (_, services) = scripted(vec![csr_step(typed.path(), "Typed1234")]);
    let made: NewKey = once(
        &services,
        vec![
            csr_dialog(true),
            new_key(&essentials(Folder::Chosen(0), Password::Secret(1))),
        ],
    )
    .unwrap();
    let file = typed.path().join(format!("GOST512_{}.p12", made.key_id));
    assert!(load_contents(&read(&file), "Typed1234").is_ok());
}

#[test]
fn new_key_applet_form_and_key_id() {
    let dir = tempfile::tempdir().unwrap();
    let (prompter, services) = scripted(vec![]);
    let args = NewKeyArgs {
        folder: page(dir.path()),
        password: Password::Text(PASSWORD.to_owned()),
        alg: GOST2004.to_owned(),
        bits: None,
        form: RequestForm::Applet {
            dn: vec![
                ("2.5.4.3".to_owned(), "TEST".to_owned()),
                ("2.5.4.6".to_owned(), "KZ".to_owned()),
            ],
            dns_names: Some(vec!["TEST".to_owned()]),
        },
    };
    let made: NewKey = once(&services, vec![new_key(&args)]).unwrap();
    assert!(prompter.timeline().is_empty(), "no window");
    assert_eq!(made.pem, None, "the Applet's PEM is the guest's");
    let request = CertReq::from_der(&made.der).unwrap();
    let public = PublicKey::from_spki(&request.info.public_key).unwrap();
    // The Applet's identifier: of the whole SubjectPublicKeyInfo, in the request too.
    assert_eq!(made.key_id, applet_key_id(&public));
    assert_ne!(made.key_id, key_id(&public));
    let id = hex(&made.key_id);
    assert!(made.der.windows(id.len()).any(|w| w == id.as_slice()));
    let name = format!("GOSTKNCA_{}.p12", made.key_id);
    assert_eq!(files(dir.path()), std::slice::from_ref(&name));
    let contents = load_contents(&read(dir.path().join(&name)), PASSWORD).unwrap();
    assert_eq!(contents.keys[0].alias, made.key_id);
}

#[test]
fn page_folder_must_be_absolute_and_existing() {
    let dir = tempfile::tempdir().unwrap();
    let not_folder = dir.path().join("f.txt");
    fs::write(&not_folder, b"x").unwrap();
    let mut cases = vec![
        ("keys".to_owned(), abi::cause::KEYSTORE_FOLDER_MISSING),
        (
            dir.path().join("missing").display().to_string(),
            abi::cause::KEYSTORE_FOLDER_MISSING,
        ),
        (
            not_folder.display().to_string(),
            abi::cause::KEYSTORE_FOLDER_MISSING,
        ),
        (NETWORK.to_owned(), abi::cause::KEYSTORE_FOLDER_REFUSED),
    ];
    if cfg!(windows) {
        cases.push((
            r"\\host\share\keys".to_owned(),
            abi::cause::KEYSTORE_FOLDER_REFUSED,
        ));
        cases.push((
            r"\\.\pipe\keys".to_owned(),
            abi::cause::KEYSTORE_FOLDER_REFUSED,
        ));
    }
    let (_, services) = scripted(vec![]);
    for (path, expected) in &cases {
        let args = essentials(
            Folder::Page(path.clone()),
            Password::Text(PASSWORD.to_owned()),
        );
        assert_cause(once::<NewKey>(&services, vec![new_key(&args)]), expected);
    }
    assert_eq!(files(dir.path()), ["f.txt"]);

    // Certificates: the certificate's own checks first, then the folder, as the Applet.
    let keys = tempfile::tempdir().unwrap();
    let (_, key) = key_file(keys.path());
    let cert = certificate(&key, &[0x41, 0x01], true);
    let no_ski = certificate(&key, &[0x41, 0x02], false);
    let missing = Folder::Page(keys.path().join("missing").display().to_string());
    let refused = Folder::Page(NETWORK.to_owned());
    assert_cause(
        once::<InstalledCert>(&services, vec![install(refused.clone(), &no_ski, None)]),
        abi::cause::KEYSTORE_EXTENSION_NOT_FOUND,
    );
    assert_cause(
        once::<InstalledCert>(&services, vec![install(refused, &cert, None)]),
        abi::cause::KEYSTORE_FOLDER_REFUSED,
    );
    assert_cause(
        once::<InstalledCert>(&services, vec![install(missing, &cert, None)]),
        abi::cause::KEYSTORE_FOLDER_MISSING,
    );
    // As the Applet did, an existing folder by a relative path (the process's) is searched.
    assert!(Path::new("tests").is_dir());
    assert_cause(
        once::<InstalledCert>(
            &services,
            vec![install(Folder::Page("tests".to_owned()), &cert, None)],
        ),
        abi::cause::KEYSTORE_KEYSTORE_FILE_NOT_FOUND,
    );
}

#[test]
fn chosen_folder_handle_is_per_call() {
    let dir = tempfile::tempdir().unwrap();
    let (_, services) = scripted(vec![csr_step(dir.path(), ""), csr_step(dir.path(), "")]);
    let args = essentials(Folder::Chosen(0), Password::Text(PASSWORD.to_owned()));
    let mut module = builtin(
        &services,
        &[
            vec![csr_dialog(false)],
            vec![new_key(&args)],
            vec![
                csr_dialog(false),
                new_key(&essentials(
                    Folder::Chosen(1),
                    Password::Text(PASSWORD.to_owned()),
                )),
            ],
        ],
    );
    assert!(run::<Option<CsrChoice>>(&mut module).unwrap().is_some());
    // The folder of the last call's window is gone.
    let e = run::<NewKey>(&mut module).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
    // A window answers one folder.
    let e = run::<NewKey>(&mut module).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
    assert!(files(dir.path()).is_empty());
}

// --- certificates and passwords ---------------------------------------------------------------

#[test]
fn install_cert_chosen_changes_password_after_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let (file, key) = key_file(dir.path());
    let cert = certificate(&key, &[0x41, 0x01], true);
    let calls = || {
        vec![
            import_dialog(dir.path(), &[&cert]),
            install(Folder::Chosen(0), &cert, Some(Password::Secret(1))),
        ]
    };

    // Cancelled: nothing.
    let (_, services) = scripted(vec![Step::CancelImport]);
    let choice: Option<ImportChoice> =
        once(&services, vec![import_dialog(dir.path(), &[&cert])]).unwrap();
    assert_eq!(choice, None);

    // A new password off the pattern changes no file.
    let before = read(&file);
    let (prompter, services) = scripted(vec![Step::Import {
        dir: dir.path().to_path_buf(),
        password: "short".to_owned(),
    }]);
    let e = once::<InstalledCert>(&services, calls()).unwrap_err();
    assert_eq!(e.cause(), Some(abi::cause::KEYSTORE_WRONG_PASSWORD_PATTERN));
    assert_eq!(
        e.message,
        KeystoreError::WrongPasswordPattern { empty: false }.to_string()
    );
    assert_eq!(read(&file), before);
    let prompt = &prompter.import_prompts()[0];
    assert_eq!(prompt.origin, ORIGIN);
    assert_eq!(prompt.storage, StorageKind::Pkcs12);
    assert_eq!(prompt.path.as_deref(), Some(dir.path()));
    assert_eq!(prompt.certificates[0].serial_hex, "4101");

    // Installed next to its key, then the file re-encrypted.
    let (_, services) = scripted(vec![Step::Import {
        dir: dir.path().to_path_buf(),
        password: NEW_PASSWORD.to_owned(),
    }]);
    let installed: InstalledCert = once(&services, calls()).unwrap();
    assert_eq!(
        installed.path,
        std::path::absolute(&file).unwrap().display().to_string()
    );
    let entries = load(&read(&file), NEW_PASSWORD).unwrap();
    assert_eq!(entries[0].cert.to_der().unwrap(), cert);
    assert_eq!(
        load(&read(&file), PASSWORD).unwrap_err(),
        Pkcs12Error::WrongPassword
    );
}

#[test]
fn install_cert_page_folder_limits() {
    let dir = tempfile::tempdir().unwrap();
    let (file, key) = key_file(dir.path());
    let cert = certificate(&key, &[0x41, 0x03], true);
    // Key files sorting first that do not open: the page's folder is tried no further.
    for i in 0..MAX_KEY_FILES {
        fs::write(dir.path().join(format!("A{i:03}.p12")), b"not a key store").unwrap();
    }
    let (_, services) = scripted(vec![Step::Import {
        dir: dir.path().to_path_buf(),
        password: NEW_PASSWORD.to_owned(),
    }]);
    assert_cause(
        once::<InstalledCert>(&services, vec![install(page(dir.path()), &cert, None)]),
        abi::cause::KEYSTORE_KEYSTORE_FILE_NOT_FOUND,
    );
    // The folder the user chose is searched whole.
    let installed: InstalledCert = once(
        &services,
        vec![
            import_dialog(dir.path(), &[&cert]),
            install(Folder::Chosen(0), &cert, None),
        ],
    )
    .unwrap();
    assert_eq!(
        installed.path,
        std::path::absolute(&file).unwrap().display().to_string()
    );
    // Within the bounds the page's folder finds it.
    for i in 0..MAX_KEY_FILES {
        fs::remove_file(dir.path().join(format!("A{i:03}.p12"))).unwrap();
    }
    let installed: InstalledCert =
        once(&services, vec![install(page(dir.path()), &cert, None)]).unwrap();
    assert_eq!(
        installed.path,
        std::path::absolute(&file).unwrap().display().to_string()
    );
    assert_eq!(
        load(&read(&file), PASSWORD).unwrap()[0]
            .cert
            .to_der()
            .unwrap(),
        cert
    );
}

#[test]
fn change_password_reads_once_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = key_file(dir.path());
    let name = files(dir.path());
    let change = |file: &str, old: &str, new: &str| {
        call(
            Import::KeystoreChangePassword,
            &ChangePasswordArgs {
                file: file.to_owned(),
                old: Password::Text(old.to_owned()),
                new: Password::Text(new.to_owned()),
            },
        )
    };
    let path = file.display().to_string();
    let before = read(&file);
    let (_, services) = scripted(vec![]);
    // The pattern first, then the password.
    for (old, new, expected) in [
        (
            "Wrong1234",
            "short",
            abi::cause::KEYSTORE_WRONG_PASSWORD_PATTERN,
        ),
        (
            "Wrong1234",
            NEW_PASSWORD,
            abi::cause::KEYSTORE_WRONG_PASSWORD,
        ),
    ] {
        assert_cause(
            once::<()>(&services, vec![change(&path, old, new)]),
            expected,
        );
        assert_eq!(read(&file), before);
    }
    // A file the core does not read as a page's file.
    for unread in [
        dir.path().join("none.p12").display().to_string(),
        format!("{NETWORK}/k.p12"),
    ] {
        let e = once::<()>(&services, vec![change(&unread, PASSWORD, NEW_PASSWORD)]).unwrap_err();
        assert_eq!(e.cause(), Some(abi::cause::KEYSTORE_IO));
        assert_eq!(e.message, "the key file cannot be read");
    }
    once::<()>(&services, vec![change(&path, PASSWORD, NEW_PASSWORD)]).unwrap();
    assert!(load_contents(&read(&file), NEW_PASSWORD).is_ok());
    // Replaced in place: no temporary file left beside it.
    assert_eq!(files(dir.path()), name);
}

// --- ID cards -----------------------------------------------------------------------------------

fn id_card() -> CardSpec {
    let k = synthetic("user-gost2015-sign");
    let mut spec = CardSpec::new(
        TokenKind::KzIdCard,
        "1234",
        vec![EmuKey::load(&k.path, &k.password).unwrap()],
    );
    spec.id_card = Some(IdCardInfo {
        iin: "123456789012".to_owned(),
        last_name: "ТЕСТОВ".to_owned(),
        first_name: "ТЕСТ".to_owned(),
        middle_name: Some("ТЕСТОВИЧ".to_owned()),
    });
    spec
}

#[test]
fn id_card_holder_from_emulator() {
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(R0);
    emu.insert(R0, card(id_card()));
    let reader = |name: &str| {
        call(
            Import::TokensIdCard,
            &ReaderName {
                reader: name.to_owned(),
            },
        )
    };
    let (prompter, services) = scripted(vec![]);
    let on = HostServices {
        tokens: Tokens::new(emu.clone(), true),
        ..services.clone()
    };
    let holder: IdCardHolder = once(&on, vec![reader(R0)]).unwrap();
    assert_eq!(
        holder,
        IdCardHolder {
            iin: "123456789012".to_owned(),
            full_name: "ТЕСТОВ ТЕСТ ТЕСТОВИЧ".to_owned(),
        }
    );
    assert!(prompter.timeline().is_empty(), "no PIN, no window");
    let e = once::<IdCardHolder>(&on, vec![reader("Another reader")]).unwrap_err();
    assert_eq!(e.code, ErrorCode::Failed);
    // Token support off.
    let off = HostServices {
        tokens: Tokens::new(emu, false),
        ..services
    };
    let e = once::<IdCardHolder>(&off, vec![reader(R0)]).unwrap_err();
    assert_eq!(e.code, ErrorCode::Failed);
}

// --- rules ----------------------------------------------------------------------------------------

#[test]
fn keystore_and_data_functions_need_builtin() {
    let engine = Engine::new();
    let without = Manifest::from_toml_builtin(&builtin_manifest("")).unwrap();
    let plugin = manifest("keys = true\ndialogs = true\nfiles = true\npage_files = true");
    let data = [
        Import::DataRead,
        Import::DataDecode,
        Import::DataEncode,
        Import::DataSignCms,
        Import::DataSignXml,
        Import::DataStamp,
        Import::DataPageRead,
    ];
    for import in KEYSTORE_IMPORTS.into_iter().chain(data) {
        assert_eq!(import.capability(), Some(abi::Capability::Builtin));
        assert_eq!(import.since().to_string(), "0.1.0-alpha.5");
        let wasm = wasm(&probe(&[(import, Vec::new())]));
        for manifest in [&without, &plugin] {
            assert!(
                matches!(
                    engine.compile(manifest, &wasm),
                    Err(LoadError::Undeclared(name)) if name == format!("oncl.{}", import.name())
                ),
                "{}",
                import.name()
            );
        }
    }
}

#[test]
fn key_count_limit_per_call() {
    let refused = new_key(&essentials(
        Folder::Page(NETWORK.to_owned()),
        Password::Text(PASSWORD.to_owned()),
    ));
    let (_, services) = scripted(vec![]);
    let mut module = builtin(
        &services,
        &[
            vec![refused.clone(); MAX_KEYS_PER_REQUEST + 1],
            vec![refused.clone()],
        ],
    );
    assert_eq!(
        run::<NewKey>(&mut module).unwrap_err().code,
        ErrorCode::Limit
    );
    // The next call counts again.
    assert_cause(
        run::<NewKey>(&mut module),
        abi::cause::KEYSTORE_FOLDER_REFUSED,
    );

    let keys = tempfile::tempdir().unwrap();
    let (_, key) = key_file(keys.path());
    let cert = certificate(&key, &[0x41, 0x04], true);
    let refused = install(Folder::Page(NETWORK.to_owned()), &cert, None);
    let mut module = builtin(
        &services,
        &[vec![refused; MAX_CERTIFICATES_PER_REQUEST + 1]],
    );
    assert_eq!(
        run::<InstalledCert>(&mut module).unwrap_err().code,
        ErrorCode::Limit
    );
    let (prompter, services) = scripted(vec![]);
    let too_many = vec![cert.as_slice(); MAX_CERTIFICATES_PER_REQUEST + 1];
    let e = once::<Option<ImportChoice>>(&services, vec![import_dialog(keys.path(), &too_many)])
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Limit);
    assert!(prompter.import_prompts().is_empty());
}

#[test]
fn keystore_causes_cover_every_variant() {
    let errors = [
        KeystoreError::UnknownAlgorithm,
        KeystoreError::KeystoreFileNotFound(String::new()),
        KeystoreError::UnsuitedStorage,
        KeystoreError::InappropriateCert,
        KeystoreError::WrongPassword,
        KeystoreError::WrongPasswordPattern { empty: true },
        KeystoreError::ChangePasswordConstraint,
        KeystoreError::ExtensionNotFound,
        KeystoreError::UnsupportedStorage,
        KeystoreError::InvalidRequest(String::new()),
        KeystoreError::Malformed(String::new()),
        KeystoreError::Io(String::new()),
        KeystoreError::Pkcs12(Pkcs12Error::Malformed(String::new())),
    ];
    let causes: Vec<&str> = errors.iter().map(cause::keystore).collect();
    assert_eq!(causes, abi::cause::KEYSTORE, "one cause each, in order");
    for c in abi::cause::KEYSTORE {
        assert!(abi::cause::ALL.contains(&c), "{c}");
    }
    for step in abi::cause::NEW_KEY_STEPS {
        for e in &errors {
            let c = cause::new_key(step, e);
            assert!(abi::cause::is_known(&c), "{c}");
            assert!(!abi::cause::ALL.contains(&c.as_str()), "{c}");
        }
    }
    assert_eq!(
        cause::new_key(abi::cause::CSR, &KeystoreError::Io(String::new())),
        "csr.io"
    );
    for unknown in [
        "keystore.generate.nope",
        "csr.folder.refused",
        "csr",
        "keystore.write.",
    ] {
        assert!(!abi::cause::is_known(unknown), "{unknown}");
    }

    // Through the ABI: each step names itself; the message is the core's.
    let dir = tempfile::tempdir().unwrap();
    let (_, services) = scripted(vec![]);
    let unknown = NewKeyArgs {
        alg: "1.2.3.4".to_owned(),
        ..essentials(page(dir.path()), Password::Text(PASSWORD.to_owned()))
    };
    let e = once::<NewKey>(&services, vec![new_key(&unknown)]).unwrap_err();
    assert_eq!(e.cause(), Some("keystore.generate.unknown_algorithm"));
    assert_eq!(e.message, "UNKNOWN_ALGORITHM");
    let rsa_length = NewKeyArgs {
        alg: "1.2.840.113549.1.1.11".to_owned(),
        bits: Some(1024),
        ..unknown.clone()
    };
    assert_cause(
        once::<NewKey>(&services, vec![new_key(&rsa_length)]),
        "keystore.generate.unknown_algorithm",
    );
    let bad_email = NewKeyArgs {
        form: RequestForm::Essentials {
            dn: vec![("2.5.4.3".to_owned(), "TEST".to_owned())],
            dns_names: Vec::new(),
            email: Some("тест@example.kz".to_owned()),
        },
        ..essentials(page(dir.path()), Password::Text(PASSWORD.to_owned()))
    };
    assert_cause(
        once::<NewKey>(&services, vec![new_key(&bad_email)]),
        "csr.invalid_request",
    );
    assert!(
        files(dir.path()).is_empty(),
        "no key file without a request"
    );
    // An attribute that is no OID is the guest's mistake.
    let bad_oid = NewKeyArgs {
        form: RequestForm::Applet {
            dn: vec![("CN".to_owned(), "TEST".to_owned())],
            dns_names: None,
        },
        ..unknown
    };
    let e = once::<NewKey>(&services, vec![new_key(&bad_oid)]).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
    // A certificate that is none, likewise.
    let e =
        once::<InstalledCert>(&services, vec![install(page(dir.path()), b"x", None)]).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
}
