//! CMS verification reports and XML signatures by profile for plugins (`cms_verify`,
//! `keys_sign_xml_ex`, `keys_sign_xades`, `xml_verify`): what the core checks, through the
//! ABI.

mod common;

use common::*;
use oncl_pdk::abi::{
    self, Bytes, C14n, Check, ErrorCode, HostResult, Import, KeySource, NetStage, OpenArgs,
    Password, Placement, Problem, Revocation, SignXmlExArgs, Transform, TsaChoice, VerifyArgs,
    VerifyAt, VerifyReport, XadesArgs, XadesLevel, XadesOutcome, XmlOutput, XmlSigReport,
    XmlVerifyArgs,
};
use oncl_pki::cert;
use oncl_pki::cms::{AttrSpec, CertSpec, CoSign, Content, SignSpec, sign_spec};
use oncl_pki::http::{HttpTransport, RouteTransport};
use oncl_pki::ocsp::{CertStatus, MockOcsp};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::xmldsig;
use oncl_plugin::{Engine, HostServices, Instance};
use oncl_testkit::{read, synthetic, synthetic_cert};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use time::macros::datetime;

const ORIGIN: &str = "https://pay.example.kz";
const REVOKED_AT_MS: i64 = 1_768_464_000_000; // 2026-01-15 08:00 UTC

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

/// The services with the synthetic CAs and the real clock (the mock answers now); the PKI
/// hosts the NCA's plus `extra_hosts`.
fn services(http: Arc<dyn HttpTransport>, extra_hosts: &[&str]) -> HostServices {
    let mut services = services_with(
        Arc::new(oncl_flows::testing::ScriptedPrompter::new(Vec::<
            oncl_flows::testing::Step,
        >::new())),
        http,
    );
    services.cas = Arc::new(CaSet::new(
        ["root-gost2015", "inter-gost2015"]
            .map(|name| cert::parse(&synthetic_cert(name)).unwrap())
            .to_vec(),
    ));
    services.clock = time::OffsetDateTime::now_utc;
    services.pki_hosts = oncl_plugin::NCA_PKI_HOSTS
        .iter()
        .chain(extra_hosts)
        .map(|h| (*h).to_owned())
        .collect();
    services
}

/// The synthetic OCSP responder, answering `revoked` for `inter-revoked-gost2015-sign`.
fn responder() -> Arc<dyn HttpTransport> {
    let serial: String = entry("inter-revoked-gost2015-sign")
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ocsp = MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial,
        CertStatus::Revoked {
            time: datetime!(2026-01-15 08:00 UTC),
            reason: Some(1),
        },
    );
    Arc::new(RouteTransport::new(vec![(
        "http://ocsp.synthetic.test".to_owned(),
        Arc::new(ocsp) as Arc<dyn HttpTransport>,
    )]))
}

fn guest(services: &HostServices, calls: &[(Import, Vec<u8>)]) -> Instance {
    Engine::new()
        .compile(&manifest("keys = true"), &wasm(&probe(calls)))
        .unwrap()
        .instantiate(services, session(1))
        .unwrap()
}

/// The last call's result of one request.
fn run<T: DeserializeOwned>(services: &HostServices, calls: &[(Import, Vec<u8>)]) -> HostResult<T> {
    let mut instance = guest(services, calls);
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    probe_result(reply.text().unwrap())
}

/// An attached CAdES of `key` signed at 2026-03-01.
fn cades(key: &str) -> Vec<u8> {
    let spec = SignSpec {
        content: Content::Data(b"verify me"),
        encapsulate: true,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs: AttrSpec::cades(datetime!(2026-03-01 10:00 UTC)),
        certificates: CertSpec::Signer,
    };
    sign_spec(&entry(key), &[], &spec).unwrap()
}

fn verify_args(cms: Vec<u8>, revocation: Revocation) -> VerifyArgs {
    VerifyArgs {
        cms: Bytes::from(cms),
        data: None,
        at: VerifyAt::SigningTime,
        chain: None,
        revocation,
        first_signer_only: false,
        require_key_usage: Vec::new(),
    }
}

fn report(services: &HostServices, args: &VerifyArgs) -> HostResult<VerifyReport> {
    run(services, &[(Import::CmsVerify, abi::encode(args))])
}

#[test]
fn cms_verify_through_abi() {
    let cms = cades("inter-revoked-gost2015-sign");
    let services = services(responder(), &["ocsp.synthetic.test"]);
    let r = report(&services, &verify_args(cms.clone(), Revocation::LiveOcsp)).unwrap();
    assert_eq!(
        r.content.as_deref().map(|c| c.as_slice()),
        Some(&b"verify me"[..])
    );
    let signer = &r.signers[0];
    assert_eq!(signer.signature, Check::Ok);
    assert_eq!(signer.ess_cert_id, Check::Ok);
    assert_eq!(signer.path, Check::Ok);
    assert_eq!(signer.signing_time_ms, Some(1_772_359_200_000));
    assert_eq!(
        signer.certificate.as_deref().map(|c| c.as_slice()),
        Some(&synthetic_cert_of("inter-revoked-gost2015-sign")[..])
    );
    assert_eq!(
        signer.revocation,
        Check::Fail(Problem::Revoked {
            at_ms: REVOKED_AT_MS,
            reason: Some(1)
        })
    );

    // The responder the certificate names is not a PKI host: never asked.
    let nca_only = self::services(responder(), &[]);
    let r = report(&nca_only, &verify_args(cms.clone(), Revocation::LiveOcsp)).unwrap();
    match &r.signers[0].revocation {
        Check::Fail(Problem::Net(failure)) => {
            assert_eq!(failure.stage, NetStage::Ocsp);
            assert_eq!(failure.address, "ocsp.synthetic.test");
        }
        other => panic!("{other:?}"),
    }

    // No path, no revocation; the key usage asked for.
    let mut args = verify_args(cms, Revocation::None);
    args.chain = Some(Vec::new());
    args.require_key_usage = vec![abi::KeyUsageBit::KeyEncipherment];
    let signer = &report(&services, &args).unwrap().signers[0];
    assert_eq!(signer.path, Check::Skipped);
    assert_eq!(signer.revocation, Check::Skipped);
    assert_eq!(signer.signature, Check::Fail(Problem::NoSignerCert));

    // Not a CMS.
    let err = report(&services, &verify_args(b"nope".to_vec(), Revocation::None)).unwrap_err();
    assert_eq!(err.code, ErrorCode::Invalid);
}

fn synthetic_cert_of(key: &str) -> Vec<u8> {
    der::Encode::to_der(&entry(key).cert).unwrap()
}

/// Opens the synthetic key `name` by its bytes: handle 1.
fn open(name: &str) -> (Import, Vec<u8>) {
    let key = synthetic(name);
    (
        Import::KeysOpen,
        abi::encode(&OpenArgs {
            storage: "PKCS12".to_owned(),
            source: KeySource::Bytes(Bytes::from(read(&key.path))),
            password: Password::Text(key.password),
        }),
    )
}

fn xml_args(xml: &[u8]) -> SignXmlExArgs {
    SignXmlExArgs {
        handle: 1,
        xml: Bytes::from(xml.to_vec()),
        element: None,
        parent: None,
        namespaces: Vec::new(),
        other_prefix_uri: None,
        placement: Placement::FirstChildOfDocument,
        signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_owned()),
        digest_method: Some("http://www.w3.org/2001/04/xmlenc#sha256".to_owned()),
        signed_info_c14n: Some(C14n::Inclusive),
        transforms: Some(vec![
            Transform::Enveloped,
            Transform::C14n(C14n::InclusiveWithComments),
        ]),
        signature_id: None,
        signing_time_object: None,
        strip_whitespace: false,
        base64_line_breaks: None,
        output: XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim: false,
        },
    }
}

#[test]
fn xml_sign_ex_through_abi() {
    let services = services(responder(), &[]);
    let args = xml_args(b"<pay><sum>1</sum></pay>");
    let signed: Bytes = run(
        &services,
        &[
            open("user-rsa-sign"),
            (Import::KeysSignXmlEx, abi::encode(&args)),
        ],
    )
    .unwrap();
    let text = std::str::from_utf8(&signed).unwrap();
    assert!(text.starts_with(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><pay><sum>1</sum><ds:Signature"
    ));
    let infos = xmldsig::verify(&signed).unwrap();
    assert_eq!(infos[0].cert, entry("user-rsa-sign").cert);

    // A URI that does not fit the key, an unknown handle.
    let gost: HostResult<Bytes> = run(
        &services,
        &[
            open("user-gost2015-sign"),
            (Import::KeysSignXmlEx, abi::encode(&args)),
        ],
    );
    assert_eq!(gost.unwrap_err().code, ErrorCode::Failed);
    let unknown: HostResult<Bytes> = run(&services, &[(Import::KeysSignXmlEx, abi::encode(&args))]);
    assert_eq!(unknown.unwrap_err().code, ErrorCode::Invalid);
}

#[test]
fn xml_verify_reports_each_signature() {
    let services = services(responder(), &[]);
    let rsa = entry("user-rsa-sign");
    let gost = entry("user-gost2015-sign");
    let once = xmldsig::sign_enveloped(b"<a>1</a>", &rsa.key, &rsa.cert).unwrap();
    let twice = xmldsig::sign_enveloped(&once, &gost.key, &gost.cert).unwrap();
    let check = |xml: &[u8]| -> Vec<XmlSigReport> {
        run(
            &services,
            &[(
                Import::XmlVerify,
                abi::encode(&XmlVerifyArgs {
                    xml: Bytes::from(xml.to_vec()),
                }),
            )],
        )
        .unwrap()
    };
    let reports = check(&twice);
    assert_eq!(reports.len(), 2);
    assert_eq!(
        reports[0].certificate.as_slice(),
        synthetic_cert_of("user-rsa-sign")
    );
    assert_eq!(
        reports[1].certificate.as_slice(),
        synthetic_cert_of("user-gost2015-sign")
    );
    assert!(reports.iter().all(|r| r.valid));
    // The last signature's value spoiled.
    let text = std::str::from_utf8(&twice).unwrap();
    let at = text.rfind("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len() + 2;
    let mut spoiled = twice.clone();
    spoiled[at] = if spoiled[at] == b'A' { b'B' } else { b'A' };
    let reports = check(&spoiled);
    assert!(reports[0].valid && !reports[1].valid);
    assert!(check(b"<a/>").is_empty());
}

fn xades_args(level: XadesLevel) -> XadesArgs {
    XadesArgs {
        handle: 1,
        xml: Bytes::from(b"<doc><a>1</a></doc>".to_vec()),
        level,
        tsa: TsaChoice::Basics,
        chain: ["inter-gost2015", "root-gost2015"]
            .map(|name| Bytes::from(synthetic_cert(name)))
            .to_vec(),
        signature_method: None,
        digest_method: None,
    }
}

/// The synthetic OCSP responder, the root's CRL (of the intermediate CA, which names no
/// responder) and the mock TSA at the basics module's URL.
fn responder_and_tsa() -> Arc<dyn HttpTransport> {
    let tsa = oncl_pki::tsp::MockTsa::new(entry("tsa-gost2015"));
    let root_crl = oncl_pki::crl::MockCrl::new(entry("root-gost2015.key"));
    Arc::new(RouteTransport::new(vec![
        (
            oncl_pki::tsp::TsaProfile::basics_default().url,
            Arc::new(tsa) as Arc<dyn HttpTransport>,
        ),
        ("http://ocsp.synthetic.test".to_owned(), responder()),
        ("http://crl.synthetic.test".to_owned(), Arc::new(root_crl)),
    ]))
}

fn xades(services: &HostServices, key: &str, level: XadesLevel) -> HostResult<XadesOutcome> {
    run(
        services,
        &[
            open(key),
            (Import::KeysSignXades, abi::encode(&xades_args(level))),
        ],
    )
}

#[test]
fn xades_through_abi() {
    let services = services(
        responder_and_tsa(),
        &["ocsp.synthetic.test", "crl.synthetic.test"],
    );
    let signed = match xades(&services, "inter-user-gost2015-sign", XadesLevel::Lt).unwrap() {
        XadesOutcome::Signed(signed) => signed,
        other => panic!("{other:?}"),
    };
    let text = std::str::from_utf8(&signed).unwrap();
    assert!(text.contains("<xades:SignatureTimeStamp"));
    assert!(text.contains("<xades:EncapsulatedOCSPValue>"));
    assert!(text.contains("<xades:EncapsulatedCRLValue>"));
    assert_eq!(
        xmldsig::verify(&signed).unwrap()[0].cert,
        entry("inter-user-gost2015-sign").cert
    );

    // The intermediate's CRL is not on a PKI host: no signature without its status.
    let no_crl = self::services(responder_and_tsa(), &["ocsp.synthetic.test"]);
    match xades(&no_crl, "inter-user-gost2015-sign", XadesLevel::Lt).unwrap() {
        XadesOutcome::Failed(failure) => {
            assert_eq!(failure.stage, NetStage::Crl);
            assert_eq!(failure.address, "crl.synthetic.test");
        }
        other => panic!("{other:?}"),
    }

    // A revoked signer: no signature.
    assert_eq!(
        xades(&services, "inter-revoked-gost2015-sign", XadesLevel::Lt).unwrap(),
        XadesOutcome::Invalid(Problem::Revoked {
            at_ms: REVOKED_AT_MS,
            reason: Some(1)
        })
    );

    // The responder the certificate names is not a PKI host: never asked.
    let nca_only = self::services(responder_and_tsa(), &[]);
    match xades(&nca_only, "inter-user-gost2015-sign", XadesLevel::Lt).unwrap() {
        XadesOutcome::Failed(failure) => {
            assert_eq!(failure.stage, NetStage::Ocsp);
            assert_eq!(failure.address, "ocsp.synthetic.test");
        }
        other => panic!("{other:?}"),
    }

    // B needs no network; T fails without the TSA.
    let offline = self::services(Arc::new(Offline), &[]);
    assert!(matches!(
        xades(&offline, "user-gost2015-sign", XadesLevel::B).unwrap(),
        XadesOutcome::Signed(_)
    ));
    match xades(&offline, "user-gost2015-sign", XadesLevel::T).unwrap() {
        XadesOutcome::Failed(failure) => assert_eq!(failure.stage, NetStage::Tsp),
        other => panic!("{other:?}"),
    }
}
