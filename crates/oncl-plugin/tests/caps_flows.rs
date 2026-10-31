//! Key choice flows (`keys_flow_open`, `keys_flow_pick`), `keys_describe`, `tokens_scan`,
//! `dialog_reader`, `file_choose_kind`, `pkix_path`, `tsp_stamp` of a certificate's signer,
//! the built-in modules' time-stamps and the causes of the core's failures, through guests
//! in WebAssembly text that call them with fixed arguments.

mod common;

use common::*;
use oncl_basics::PageFileError;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_pdk::abi::{
    self, Action, Bytes, Chosen, CmsContent, CmsOutcome, ErrorCode, FileKindArgs, Filter,
    FilterMore, FlowArgs, FlowChecks, FlowFile, FlowNone, FlowOrder, FlowOutcome, FlowReader,
    FlowReaders, FlowStart, FlowWrongPin, Handle, HostResult, Import, KeyDescription, KeySource,
    OpenArgs, Password, PathArgs, PathOutcome, PathTime, PickArgs, ReaderArgs, SignCmsExArgs,
    SignRawArgs, SignXmlArgs, SignedAttrs, SignerSel, StampArgs, StampMode, StampOutcome,
    TokenForm, TokenScan, TsaChoice,
};
use oncl_pki::cms::{self, CmsError, SignOptions};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::key::KeyError;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{MockTsa, TsaProfile, TspError};
use oncl_pki::xmldsig::XmlError;
use oncl_pki::{cert, oid};
use oncl_plugin::{Engine, HostServices, Instance, SessionContext, Trust, cause};
use oncl_testkit::{read, synthetic, synthetic_cert};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

const ORIGIN: &str = "https://idp.egov.kz";
const KEY: &str = "user-gost2015-sign";
const R0: &str = "OpenNCALayer Emulated Reader 0";
const KAZTOKEN: &str = "AKKaztokenStore";
const PIN: &str = "123456";

fn context(trust: Trust) -> SessionContext {
    SessionContext {
        trust,
        ..session(1)
    }
}

/// An instance of a guest making the calls of `stages` (one stage a request), under
/// `capabilities` and `trust`.
fn guest_staged(
    services: &HostServices,
    capabilities: &str,
    trust: Trust,
    stages: &[Vec<(Import, Vec<u8>)>],
) -> Instance {
    Engine::new()
        .compile(&manifest(capabilities), &wasm(&staged_probe(stages)))
        .unwrap()
        .instantiate(services, context(trust))
        .unwrap()
}

/// An instance of a guest making `calls` in each request, with `keys`, as a plugin.
fn guest(services: &HostServices, calls: &[(Import, Vec<u8>)]) -> Instance {
    guest_staged(services, "keys = true", Trust::Installed, &[calls.to_vec()])
}

/// The last call's result of one request to `instance`.
fn run<T: DeserializeOwned>(instance: &mut Instance) -> HostResult<T> {
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    probe_result(reply.text().unwrap())
}

fn scripted(steps: Vec<Step>) -> (Arc<ScriptedPrompter>, HostServices) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let services = services_with(prompter.clone(), Arc::new(Offline));
    (prompter, services)
}

/// The synthetic store `name` with its password.
fn store(name: &str) -> Step {
    let k = synthetic(name);
    Step::Storage {
        path: k.path,
        password: k.password,
    }
}

fn entry(name: &str) -> KeyEntry {
    let k = synthetic(name);
    load(&read(&k.path), &k.password).unwrap().remove(0)
}

fn der(certificate: &cert::Certificate) -> Vec<u8> {
    der::Encode::to_der(certificate).unwrap()
}

/// A flow of the file storages as the basics module asks: live readers, the last path,
/// remembered, every key as stored, no checks.
fn flow_args() -> FlowArgs {
    FlowArgs {
        action: Action::Sign,
        storages: Vec::new(),
        readers: FlowReaders::None,
        start: FlowStart::Empty,
        remember: false,
        detail: None,
        non_empty_password: false,
        inner_password_policy: false,
        same_storage: false,
        file: FlowFile::Open,
        knca_types: None,
        none: FlowNone::NoKeys,
        empty_is_none: false,
        order: FlowOrder::Store,
        checks: FlowChecks::Settled,
        skip_blocked_reader: false,
    }
}

fn open_call(args: &FlowArgs) -> (Import, Vec<u8>) {
    (Import::KeysFlowOpen, abi::encode(args))
}

fn pick_call(flow: u32, error: Option<&str>) -> (Import, Vec<u8>) {
    (
        Import::KeysFlowPick,
        abi::encode(&PickArgs {
            flow,
            error: error.map(str::to_owned),
        }),
    )
}

// --- flows ---------------------------------------------------------------------------------

#[test]
fn flow_open_then_pick_signs() {
    let (prompter, services) = scripted(vec![store(KEY), Step::Key(0)]);
    let args = FlowArgs {
        detail: Some("doc.xml".to_owned()),
        ..flow_args()
    };
    let mut plugin = guest(&services, &[open_call(&args)]);
    let outcome: FlowOutcome = run(&mut plugin).unwrap();
    let opened = outcome.opened.expect("the store opens");
    assert_eq!(opened.flow, 0);
    assert_eq!(opened.keys.len(), 1);
    assert_eq!(opened.keys[0].alias, synthetic(KEY).aliases[0]);
    assert_eq!(opened.keys[0].certificate.to_vec(), der(&entry(KEY).cert));
    assert_eq!(outcome.wrong_pin, None);
    // A plugin's name leads the line.
    assert_eq!(
        prompter.storage_prompts()[0].detail.as_deref(),
        Some("Тестовый плагин: doc.xml")
    );

    let (prompter, services) = scripted(vec![store(KEY), Step::Key(0)]);
    let mut plugin = guest(
        &services,
        &[
            open_call(&flow_args()),
            pick_call(0, None),
            (
                Import::KeysSignRaw,
                abi::encode(&SignRawArgs {
                    handle: 1,
                    data: Bytes::from(b"data".to_vec()),
                }),
            ),
        ],
    );
    let signature: Bytes = run(&mut plugin).unwrap();
    assert!(!signature.is_empty());
    assert_eq!(
        prompter.timeline(),
        ["storage", "busy", "busy closed", "key"]
    );
}

#[test]
fn flow_pick_again_with_error_shows_it() {
    let (prompter, services) = scripted(vec![store(KEY), Step::Key(0), Step::Key(0)]);
    let mut plugin = guest(
        &services,
        &[
            open_call(&flow_args()),
            pick_call(0, None),
            pick_call(0, Some("Не удалось подписать документ: x")),
        ],
    );
    let chosen: Option<Chosen> = run(&mut plugin).unwrap();
    // Each pick is a key of its own.
    assert_eq!(chosen.unwrap().handle, 2);
    let keys = prompter.key_prompts();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].error, None);
    assert_eq!(
        keys[1].error.as_deref(),
        Some("Не удалось подписать документ: x")
    );
    assert_eq!(keys[0].candidates, keys[1].candidates);
}

fn kaztoken() -> CardSpec {
    let k = synthetic(KEY);
    CardSpec::new(
        TokenKind::Kaztoken,
        PIN,
        vec![EmuKey::load(&k.path, &k.password).unwrap()],
    )
}

/// Services with a scripted prompter and the tokens of an emulator with `cards` in the
/// readers R0, R1, … (support on).
fn token_services(cards: Vec<CardSpec>, steps: Vec<Step>) -> (Arc<ScriptedPrompter>, HostServices) {
    let emu = Arc::new(EmulatorBackend::new());
    for (i, spec) in cards.into_iter().enumerate() {
        let reader = format!("OpenNCALayer Emulated Reader {i}");
        emu.add_reader(&reader);
        emu.insert(&reader, card(spec));
    }
    let (prompter, services) = scripted(steps);
    let services = HostServices {
        tokens: Tokens::new(emu, true),
        ..services
    };
    (prompter, services)
}

#[test]
fn flow_fixed_reader_must_be_present() {
    let fixed = |reader: &str| FlowArgs {
        storages: vec![KAZTOKEN.to_owned()],
        readers: FlowReaders::Fixed(vec![FlowReader {
            storage: KAZTOKEN.to_owned(),
            reader: reader.to_owned(),
        }]),
        ..flow_args()
    };
    // No such reader, or not one holding a token of the storage.
    let (prompter, services) = token_services(vec![kaztoken()], vec![]);
    for reader in ["Another reader", "OpenNCALayer Emulated Reader 1"] {
        let mut plugin = guest(&services, &[open_call(&fixed(reader))]);
        let e = run::<FlowOutcome>(&mut plugin).unwrap_err();
        assert_eq!(e.code, ErrorCode::Invalid, "{reader}");
    }
    assert!(prompter.storage_prompts().is_empty());
    // Token support off: no reader holds one.
    let (_, services) = scripted(vec![]);
    let mut plugin = guest(&services, &[open_call(&fixed(R0))]);
    assert_eq!(
        run::<FlowOutcome>(&mut plugin).unwrap_err().code,
        ErrorCode::Invalid
    );
    // The reader holding the token is offered.
    let (prompter, services) = token_services(vec![kaztoken()], vec![Step::CancelStorage]);
    let mut plugin = guest(&services, &[open_call(&fixed(R0))]);
    assert_eq!(run::<FlowOutcome>(&mut plugin).unwrap().opened, None);
    let readers = prompter.storage_prompts()[0].tokens.clone().unwrap();
    assert_eq!(readers.current().0[0].reader, R0);
}

#[test]
fn flow_page_start_respects_page_path() {
    let key = synthetic(KEY);
    let start = |path: &str| {
        let (prompter, services) = scripted(vec![Step::CancelStorage]);
        let args = FlowArgs {
            start: FlowStart::Page(path.to_owned()),
            ..flow_args()
        };
        let mut plugin = guest(&services, &[open_call(&args)]);
        run::<FlowOutcome>(&mut plugin).unwrap();
        prompter.storage_prompts()[0].recent_path.clone()
    };
    let local = key.path.to_str().unwrap();
    assert_eq!(start(local), Some(key.path.clone()));
    // A network path the user did not choose, and a device, are not offered: the dialog
    // starts empty.
    let network = if cfg!(windows) {
        r"\\host\share\k.p12"
    } else {
        "//host/share/k.p12"
    };
    assert_eq!(start(network), None);
    if cfg!(windows) {
        assert_eq!(start(r"\\.\pipe\k.p12"), None);
    }
    assert_eq!(start(""), None);
}

#[test]
fn flow_is_gone_after_the_call() {
    let (prompter, services) = scripted(vec![store(KEY), Step::Key(0)]);
    let mut plugin = guest_staged(
        &services,
        "keys = true",
        Trust::Installed,
        &[vec![open_call(&flow_args())], vec![pick_call(0, None)]],
    );
    let outcome: FlowOutcome = run(&mut plugin).unwrap();
    assert!(outcome.opened.is_some());
    // The busy indicator of the unpicked flow ends with the call.
    assert_eq!(prompter.timeline(), ["storage", "busy", "busy closed"]);
    let e = run::<Option<Chosen>>(&mut plugin).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
    assert!(prompter.key_prompts().is_empty());
}

#[test]
fn fifth_flow_is_limit() {
    // An empty script cancels every storage dialog.
    let (prompter, services) = scripted(vec![]);
    let calls = vec![open_call(&flow_args()); abi::MAX_FLOWS + 1];
    let mut plugin = guest(&services, &calls);
    let e = run::<FlowOutcome>(&mut plugin).unwrap_err();
    assert_eq!(e.code, ErrorCode::Limit);
    assert_eq!(prompter.storage_prompts().len(), abi::MAX_FLOWS);
    // The next call has its own flows.
    let mut plugin = guest(&services, &calls[..abi::MAX_FLOWS]);
    assert_eq!(run::<FlowOutcome>(&mut plugin).unwrap().opened, None);
}

#[test]
fn flow_wrong_pin_reported() {
    let token = |pin: &str| Step::Token {
        storage: oncl_basics::StorageKind::Token(KAZTOKEN),
        reader: R0.to_owned(),
        pin: pin.to_owned(),
    };
    let (prompter, services) =
        token_services(vec![kaztoken()], vec![token("000000"), Step::CancelStorage]);
    let args = FlowArgs {
        storages: vec![KAZTOKEN.to_owned()],
        readers: FlowReaders::Live,
        ..flow_args()
    };
    let mut plugin = guest(&services, &[open_call(&args)]);
    let outcome: FlowOutcome = run(&mut plugin).unwrap();
    assert_eq!(outcome.opened, None);
    let Some(oncl_basics::OpenError::WrongPin { tries_left }) = prompter.storage_prompts()[1].error
    else {
        panic!("the wrong PIN is shown");
    };
    assert_eq!(
        outcome.wrong_pin,
        Some(FlowWrongPin {
            storage: KAZTOKEN.to_owned(),
            tries_left,
        })
    );
}

#[test]
fn describe_reports_key_alg() {
    for (name, alg) in [
        (KEY, "gost2015_512"),
        ("user-gost2004-sign", "gost2004"),
        ("user-rsa-sign", "rsa"),
    ] {
        let (_, services) = scripted(vec![store(name), Step::Key(0)]);
        let mut plugin = guest(
            &services,
            &[
                open_call(&flow_args()),
                pick_call(0, None),
                (Import::KeysDescribe, abi::encode(&Handle { handle: 1 })),
            ],
        );
        let description: KeyDescription = run(&mut plugin).unwrap();
        assert_eq!(description.alg, alg);
        assert_eq!(description.alias, synthetic(name).aliases[0]);
        assert_eq!(description.certificate.to_vec(), der(&entry(name).cert));
    }
    // Only a key of the instance.
    let mut plugin = guest(
        &services(),
        &[(Import::KeysDescribe, abi::encode(&Handle { handle: 1 }))],
    );
    assert_eq!(
        run::<KeyDescription>(&mut plugin).unwrap_err().code,
        ErrorCode::Invalid
    );
}

// --- tokens and readers --------------------------------------------------------------------

#[test]
fn tokens_scan_off_and_on() {
    let scan = |services: &HostServices| {
        let mut plugin = guest(services, &[(Import::TokensScan, abi::encode(&()))]);
        run::<TokenScan>(&mut plugin).unwrap()
    };
    assert_eq!(
        scan(&services()),
        TokenScan {
            enabled: false,
            present: Vec::new(),
            any_card: false,
        }
    );
    let (_, services) = token_services(vec![kaztoken()], vec![]);
    assert_eq!(
        scan(&services),
        TokenScan {
            enabled: true,
            present: vec![KAZTOKEN.to_owned()],
            any_card: true,
        }
    );
}

#[test]
fn dialog_reader_returns_name() {
    let (prompter, services) = token_services(vec![kaztoken()], vec![Step::Reader(R0.to_owned())]);
    let args = |storage: &str| {
        abi::encode(&ReaderArgs {
            storage: storage.to_owned(),
        })
    };
    let mut plugin = guest(&services, &[(Import::DialogReader, args(KAZTOKEN))]);
    assert_eq!(
        run::<Option<String>>(&mut plugin).unwrap(),
        Some(R0.to_owned())
    );
    let prompts = prompter.reader_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].storage.name(), KAZTOKEN);
    assert_eq!(prompts[0].origin, ORIGIN);
    // Cancelled: none. A storage of no token: invalid.
    let mut plugin = guest(&services, &[(Import::DialogReader, args(KAZTOKEN))]);
    assert_eq!(run::<Option<String>>(&mut plugin).unwrap(), None);
    for storage in ["PKCS12", "ABCloudServiceStore", "nope"] {
        let mut plugin = guest(&services, &[(Import::DialogReader, args(storage))]);
        assert_eq!(
            run::<Option<String>>(&mut plugin).unwrap_err().code,
            ErrorCode::Invalid,
            "{storage}"
        );
    }
}

// --- the typed file chooser ----------------------------------------------------------------

fn kind_call(kind: &str, directory: Option<&str>) -> (Import, Vec<u8>) {
    (
        Import::FileChooseKind,
        abi::encode(&FileKindArgs {
            kind: kind.to_owned(),
            directory: directory.map(str::to_owned),
        }),
    )
}

fn files_guest(services: &HostServices, trust: Trust, call: (Import, Vec<u8>)) -> Instance {
    guest_staged(services, "files = true", trust, &[vec![call]])
}

#[test]
fn file_choose_kind_unknown_type_cause() {
    let (prompter, services) = scripted(vec![]);
    let mut plugin = files_guest(&services, Trust::Installed, kind_call("NOPE", None));
    let e = run::<Option<String>>(&mut plugin).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
    assert_eq!(e.cause(), Some(abi::cause::FILE_UNKNOWN_KIND));
    assert!(prompter.file_prompts().is_empty());
}

#[test]
fn file_choose_kind_missing_path_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("k.p12");
    std::fs::write(&existing, b"k").unwrap();
    let missing = dir.path().join("missing.p12");
    let folder = dir.path().to_str().unwrap();
    for (trust, source) in [
        (Trust::Builtin, None),
        (Trust::Installed, Some("Тестовый плагин".to_owned())),
    ] {
        let (prompter, services) = scripted(vec![
            Step::File(missing.clone()),
            Step::File(existing.clone()),
            Step::File(dir.path().to_path_buf()),
        ]);
        let mut plugin = files_guest(&services, trust, kind_call("P12", Some(folder)));
        assert_eq!(run::<Option<String>>(&mut plugin).unwrap(), None);
        assert_eq!(
            run::<Option<String>>(&mut plugin)
                .unwrap()
                .map(PathBuf::from),
            Some(existing.clone())
        );
        let mut plugin = files_guest(&services, trust, kind_call("", None));
        assert_eq!(
            run::<Option<String>>(&mut plugin)
                .unwrap()
                .map(PathBuf::from),
            Some(dir.path().to_path_buf())
        );
        let prompts = prompter.file_prompts();
        assert_eq!(prompts[0].kind, oncl_basics::FileKind::P12);
        assert_eq!(prompts[0].directory.as_deref(), Some(dir.path()));
        assert_eq!(prompts[0].source, source, "{trust:?}");
        assert_eq!(prompts[2].kind, oncl_basics::FileKind::Directory);
        assert_eq!(prompts[2].directory, None);
    }
}

// --- certificate paths ---------------------------------------------------------------------

/// The synthetic CAs of the GOST 2015 keys.
fn synthetic_cas() -> Arc<CaSet> {
    Arc::new(CaSet::new(
        ["root-gost2015", "inter-gost2015"]
            .map(|name| cert::parse(&synthetic_cert(name)).unwrap())
            .to_vec(),
    ))
}

fn path_of(services: &HostServices, name: &str, at: PathTime) -> PathOutcome {
    let args = PathArgs {
        cert: Bytes::from(der(&entry(name).cert)),
        at,
    };
    // A basic function: no capability.
    let mut plugin = guest_staged(
        services,
        "",
        Trust::Installed,
        &[vec![(Import::PkixPath, abi::encode(&args))]],
    );
    run(&mut plugin).unwrap()
}

#[test]
fn pkix_path_issuer_not_found() {
    // The NCA's CAs did not issue the synthetic keys.
    assert_eq!(
        path_of(&services(), KEY, PathTime::Now),
        PathOutcome::IssuerNotFound
    );
    let services = HostServices {
        cas: synthetic_cas(),
        ..services()
    };
    assert_eq!(path_of(&services, KEY, PathTime::Now), PathOutcome::Valid);
    assert_eq!(
        path_of(&services, "inter-user-gost2015-sign", PathTime::Now),
        PathOutcome::Valid
    );
    // Not a certificate.
    let mut plugin = guest_staged(
        &services,
        "",
        Trust::Installed,
        &[vec![(
            Import::PkixPath,
            abi::encode(&PathArgs {
                cert: Bytes::from(vec![1, 2, 3]),
                at: PathTime::Now,
            }),
        )]],
    );
    assert_eq!(
        run::<PathOutcome>(&mut plugin).unwrap_err().code,
        ErrorCode::Invalid
    );
}

#[test]
fn pkix_path_expired_at_not_after() {
    let services = HostServices {
        cas: synthetic_cas(),
        ..services()
    };
    const EXPIRED: &str = "expired-gost2015-sign";
    // Now the key itself has expired.
    let now = path_of(&services, EXPIRED, PathTime::Now);
    assert_eq!(
        now,
        PathOutcome::Invalid(
            "certificate 0 of the path is not valid at the validation time".to_owned()
        )
    );
    // At its notAfter the key is valid: the path is judged then.
    let at_not_after = path_of(&services, EXPIRED, PathTime::NotAfterIfExpired);
    assert_ne!(at_not_after, now);
    let not_after = entry(EXPIRED)
        .cert
        .tbs_certificate()
        .validity()
        .not_after
        .to_unix_duration();
    let at = i64::try_from(not_after.as_millis()).unwrap();
    assert_eq!(
        path_of(&services, EXPIRED, PathTime::UnixMs(at)),
        at_not_after
    );
    // A key that has not expired is judged now.
    assert_eq!(
        path_of(&services, KEY, PathTime::NotAfterIfExpired),
        PathOutcome::Valid
    );
}

// --- time-stamps -----------------------------------------------------------------------------

/// A CMS of `name`'s key over `data`, attached.
fn signed_by(name: &str) -> Vec<u8> {
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: NOW,
    };
    cms::sign(&entry(name), b"data", &opts).unwrap()
}

fn stamp_call(cms: Vec<u8>, signers: SignerSel) -> (Import, Vec<u8>) {
    (
        Import::TspStamp,
        abi::encode(&StampArgs {
            cms: Bytes::from(cms),
            signers,
            tsa: TsaChoice::Kalkan,
            mode: StampMode::Replace,
            token: TokenForm::Token,
        }),
    )
}

/// Services whose network is the mock TSA `tsa`, on the system clock (the TSA's).
fn tsa_services(tsa: &Arc<MockTsa>) -> HostServices {
    HostServices {
        clock: time::OffsetDateTime::now_utc,
        ..services_with(
            Arc::new(ScriptedPrompter::new(vec![])),
            Arc::clone(tsa) as Arc<dyn HttpTransport>,
        )
    }
}

#[test]
fn stamp_of_cert_and_no_signer() {
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let services = tsa_services(&tsa);
    let cms = signed_by(KEY);
    let of = |name: &str| SignerSel::OfCert(Bytes::from(der(&entry(name).cert)));
    let mut plugin = guest(&services, &[stamp_call(cms.clone(), of(KEY))]);
    let StampOutcome::Stamped(stamped) = run(&mut plugin).unwrap() else {
        panic!("stamped");
    };
    assert_eq!(cms::signer_count(&stamped).unwrap(), 1);
    assert_eq!(tsa.calls().len(), 1);
    // Another certificate signs nothing here: nothing is asked.
    let mut plugin = guest(&services, &[stamp_call(cms, of("user-rsa-sign"))]);
    assert_eq!(
        run::<StampOutcome>(&mut plugin).unwrap(),
        StampOutcome::NoSigner
    );
    assert_eq!(tsa.calls().len(), 1);
    // Not a CMS: invalid, with the CMS's cause and the core's text.
    let mut plugin = guest(&services, &[stamp_call(vec![0x30, 0x00], of(KEY))]);
    let e = run::<StampOutcome>(&mut plugin).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
    assert_eq!(e.cause(), Some(abi::cause::CMS_MALFORMED));
    let expected = cms::signer_index_of(&[0x30, 0x00], &entry(KEY).cert).unwrap_err();
    assert_eq!(e.message, expected.to_string());
}

/// A TSA answering HTTP 500.
struct Down;

impl HttpTransport for Down {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let _ = (request.url, request.method == HttpMethod::Get);
        Ok(HttpReply {
            status: 500,
            content_type: None,
            body: Vec::new(),
            location: None,
        })
    }
}

#[test]
fn tsp_failure_detail_is_the_core_error_text() {
    let services = services_with(Arc::new(ScriptedPrompter::new(vec![])), Arc::new(Down));
    let of = SignerSel::OfCert(Bytes::from(der(&entry(KEY).cert)));
    let mut plugin = guest(&services, &[stamp_call(signed_by(KEY), of)]);
    let StampOutcome::Failed(failure) = run(&mut plugin).unwrap() else {
        panic!("the time-stamp fails");
    };
    assert_eq!(failure.stage, abi::NetStage::Tsp);
    assert_eq!(failure.detail, TspError::Status(500).to_string());
}

#[test]
fn builtin_tsa_uses_services_http() {
    let sign = |trust: Trust| {
        let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
        let services = HostServices {
            tsa: TsaProfile {
                url: "http://tsa.example".to_owned(),
                ..TsaProfile::basics_default()
            },
            ..tsa_services(&tsa)
        };
        let key = synthetic(KEY);
        let open = OpenArgs {
            storage: "PKCS12".to_owned(),
            source: KeySource::Bytes(Bytes::from(read(&key.path))),
            password: Password::Text(key.password),
        };
        let sign = SignCmsExArgs {
            handle: 1,
            content: CmsContent::Data(Bytes::from(b"data".to_vec())),
            encapsulate: true,
            cosign: abi::CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: false,
                signing_time: None,
                extra: Vec::new(),
            },
            certificates: abi::CmsCerts::Signer,
            timestamp: Some(TsaChoice::Basics),
        };
        let mut plugin = guest_staged(
            &services,
            "keys = true",
            trust,
            &[vec![
                (Import::KeysOpen, abi::encode(&open)),
                (Import::KeysSignCmsEx, abi::encode(&sign)),
            ]],
        );
        let outcome: CmsOutcome = run(&mut plugin).unwrap();
        (outcome, tsa.calls())
    };
    // A built-in module time-stamps where the core's basics TSA is.
    let (outcome, calls) = sign(Trust::Builtin);
    assert!(matches!(outcome, CmsOutcome::Signed(_)), "{outcome:?}");
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with("http://tsa.example"), "{calls:?}");
    // A plugin asks the NCA's, only through the PKI hosts.
    let (outcome, calls) = sign(Trust::Installed);
    assert!(matches!(outcome, CmsOutcome::Signed(_)), "{outcome:?}");
    assert!(calls[0].starts_with("http://tsp.pki.gov.kz"), "{calls:?}");
}

// --- causes ----------------------------------------------------------------------------------

#[test]
fn causes_cover_every_variant() {
    let key_errors = [
        KeyError::Malformed(String::new()),
        KeyError::UnknownKeyAlgorithm(String::new()),
        KeyError::UnsupportedAlgorithm,
        KeyError::KeyMismatch,
        KeyError::BadSignature,
        KeyError::NotExportable,
        KeyError::Token(String::new()),
    ];
    let cms_errors = [
        CmsError::NoEncapsulatedData,
        CmsError::UnknownAlgorithm(String::new()),
        CmsError::Malformed(String::new()),
        CmsError::CertNotFound(0),
        CmsError::DigestMismatch(0),
        CmsError::BadSignature(0),
        CmsError::SigningCertificateMismatch(0),
        CmsError::Key(KeyError::KeyMismatch),
        CmsError::Constraint(String::new()),
    ];
    let xml_errors = [
        XmlError::Parse(String::new()),
        XmlError::Doctype,
        XmlError::TooLarge,
        XmlError::TooDeep,
        XmlError::XPath(String::new()),
        XmlError::Constraint(String::new()),
        XmlError::UnsupportedAlgorithm(String::new()),
        XmlError::NoSignature,
        XmlError::BadDigest,
        XmlError::BadSignature,
        XmlError::Key(KeyError::UnsupportedAlgorithm),
    ];
    let tsp_errors = [
        TspError::Http(HttpError::other("x")),
        TspError::Status(500),
        TspError::ContentType(None),
        TspError::Rejected(2),
        TspError::NonceMismatch,
        TspError::ImprintMismatch,
        TspError::UnsupportedImprintAlgorithm(oid::SHA256),
        TspError::PolicyMismatch,
        TspError::NoTsaCertificate,
        TspError::ClockSkew,
        TspError::Cms(CmsError::NoEncapsulatedData),
        TspError::Malformed(String::new()),
    ];
    let causes: Vec<&str> = key_errors
        .iter()
        .map(cause::key)
        .chain(cms_errors.iter().map(cause::cms))
        .chain(xml_errors.iter().map(cause::xml))
        .chain(tsp_errors.iter().map(cause::tsp))
        .chain([PageFileError::NotFound, PageFileError::TooLarge].map(cause::page_file))
        .collect();
    for c in &causes {
        assert!(abi::cause::ALL.contains(c), "{c} is not in abi::cause");
    }
    // Each variant has its own; a nested key or CMS error is the key's or the CMS's.
    assert_eq!(
        cause::cms(&CmsError::Key(KeyError::KeyMismatch)),
        abi::cause::KEY_MISMATCH
    );
    assert_eq!(
        cause::xml(&XmlError::Key(KeyError::UnsupportedAlgorithm)),
        abi::cause::KEY_UNSUPPORTED
    );
    assert_eq!(
        cause::tsp(&TspError::Cms(CmsError::NoEncapsulatedData)),
        abi::cause::CMS_NO_ENCAPSULATED_DATA
    );
    let distinct: BTreeSet<&str> = causes.iter().copied().collect();
    let all: BTreeSet<&str> = abi::cause::ALL.iter().copied().collect();
    let produced_by_files: BTreeSet<&str> = [abi::cause::FILE_UNKNOWN_KIND].into();
    assert_eq!(
        distinct
            .union(&produced_by_files)
            .copied()
            .collect::<BTreeSet<_>>(),
        all
    );
    assert_eq!(all.len(), abi::cause::ALL.len(), "causes are distinct");

    // Through the ABI: a document that does not parse.
    let (_, services) = scripted(vec![store(KEY), Step::Key(0)]);
    let mut plugin = guest(
        &services,
        &[
            open_call(&flow_args()),
            pick_call(0, None),
            (
                Import::KeysSignXml,
                abi::encode(&SignXmlArgs {
                    handle: 1,
                    xml: Bytes::from(b"<a>".to_vec()),
                    element: None,
                    parent: None,
                }),
            ),
        ],
    );
    let e = run::<Bytes>(&mut plugin).unwrap_err();
    assert_eq!(e.code, ErrorCode::Failed);
    assert_eq!(e.cause(), Some(abi::cause::XML_PARSE));
}

// Filter conditions of a live flow reach the key dialog.
#[test]
fn flow_live_checks_follow_the_filter() {
    let (prompter, services) = scripted(vec![store("expired-gost2015-sign"), Step::CancelKey]);
    let args = FlowArgs {
        checks: FlowChecks::Live {
            filter: Box::new(Filter {
                chain: Some(Vec::new()),
                allow_expired: false,
                ..Filter::default()
            }),
            more: Box::new(FilterMore::default()),
        },
        ..flow_args()
    };
    let mut plugin = guest(&services, &[open_call(&args), pick_call(0, None)]);
    assert_eq!(run::<Option<Chosen>>(&mut plugin).unwrap(), None);
    assert_ne!(
        prompter.key_prompts()[0].candidates[0].availability,
        oncl_basics::Availability::Enabled
    );
}

#[test]
fn cert_details_name_the_issuer_cn() {
    let args = abi::CertArgs {
        der: Bytes::from(der(&entry(KEY).cert)),
    };
    let mut plugin = guest_staged(
        &services(),
        "",
        Trust::Installed,
        &[vec![(Import::CertDetails, abi::encode(&args))]],
    );
    let details: abi::CertDetails = run(&mut plugin).unwrap();
    let root = cert::parse(&synthetic_cert("root-gost2015")).unwrap();
    assert_eq!(
        details.issuer_cn,
        oncl_pki::info::common_name(root.tbs_certificate().subject())
    );
    assert!(details.issuer_cn.is_some());
    // An older core's details, without it, still decode.
    #[derive(serde::Serialize)]
    struct Older {
        subject_dn: String,
        issuer_dn: String,
        knca_types: Vec<String>,
        ski_hex: Option<String>,
        aki_hex: Option<String>,
        serial_dec: String,
        ocsp_urls: Vec<String>,
        ca_issuers_urls: Vec<String>,
        crl_urls: Vec<String>,
        signing_alg: Option<String>,
    }
    let older = Older {
        subject_dn: details.subject_dn.clone(),
        issuer_dn: details.issuer_dn.clone(),
        knca_types: details.knca_types.clone(),
        ski_hex: details.ski_hex.clone(),
        aki_hex: details.aki_hex.clone(),
        serial_dec: details.serial_dec.clone(),
        ocsp_urls: details.ocsp_urls.clone(),
        ca_issuers_urls: details.ca_issuers_urls.clone(),
        crl_urls: details.crl_urls.clone(),
        signing_alg: details.signing_alg.clone(),
    };
    let decoded: abi::CertDetails = abi::decode(&abi::encode(&older)).unwrap();
    assert_eq!(
        decoded,
        abi::CertDetails {
            issuer_cn: None,
            ..details
        }
    );
}
