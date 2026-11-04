//! Shared by the SDK examples: a throwaway RSA PKI issued at run time and the host services
//! (clock, transport, trust, key-use guard, cancellation) an embedding application supplies.
//!
//! Nothing here is part of the SDK and nothing is committed: every run issues a fresh root and
//! a fresh user key. The "certification authority" is an in-process CRL responder
//! (`oncl_pki::crl::MockCrl`, feature `testing` of `oncl-pki`) standing in for the CA's
//! distribution point, so the examples need no network. A real host passes its own trust
//! anchors and an HTTP transport instead.
#![allow(dead_code)]

use oncl_core::keys::{
    KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::{Engine, EngineServices, OperationError, ValidationServices};
use oncl_pki::{
    cert,
    crl::MockCrl,
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    key::PrivateKey,
    keygen::{self, KeySpec},
    pkcs12::{self, KeyEntry},
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    validation::NetworkPolicy,
};
use rcgen::{
    CertificateParams, CrlDistributionPoint, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime};

/// Password of the throwaway PKCS#12 files.
pub const PASSWORD: &str = "sdk-example";
/// Where the demo CA publishes its CRL (never resolved: the transport answers in process).
pub const CRL_ORIGIN: &str = "http://crl.example.invalid";

const ROOT_FILE: &str = "demo-root.p12";
const USER_FILE: &str = "demo-user.p12";

/// The demo PKI of one working directory.
pub struct DemoPki {
    pub root: KeyEntry,
    pub user_p12: Vec<u8>,
}

fn pkcs12_of(entry: &KeyEntry, label: &str) -> Vec<u8> {
    use der::Encode;
    pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: label.to_owned(),
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        &[],
        PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |bytes| getrandom::fill(bytes).expect("system RNG"),
    )
    .unwrap()
}

fn rcgen_key(key: &PrivateKey) -> KeyPair {
    let der = key.to_pkcs8_der().unwrap();
    KeyPair::try_from(der.as_slice()).expect("rcgen accepts the RSA PKCS#8")
}

fn name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(
        DnType::OrganizationName,
        "OpenNCALayer SDK example (synthetic)",
    );
    dn
}

impl DemoPki {
    /// Issues a new root and a user key under it and writes both as PKCS#12 into `dir`.
    pub fn create(dir: &Path) -> DemoPki {
        let now = OffsetDateTime::now_utc();
        let root_key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
        let user_key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
        let root_pair = rcgen_key(&root_key);
        let user_pair = rcgen_key(&user_key);

        let mut root_params = CertificateParams::default();
        root_params.distinguished_name = name("OpenNCALayer SDK example root");
        root_params.serial_number = Some(SerialNumber::from(vec![0x5d, 0x01]));
        root_params.not_before = now - Duration::hours(1);
        root_params.not_after = now + Duration::days(2);
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_cert = root_params.clone().self_signed(&root_pair).unwrap();

        let mut user_params = CertificateParams::default();
        user_params.distinguished_name = name("OpenNCALayer SDK example user");
        user_params.serial_number = Some(SerialNumber::from(vec![0x5d, 0x02]));
        user_params.not_before = now - Duration::hours(1);
        user_params.not_after = now + Duration::days(1);
        user_params.is_ca = IsCa::ExplicitNoCa;
        user_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        user_params.use_authority_key_identifier_extension = true;
        user_params.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![format!("{CRL_ORIGIN}/root.crl")],
        }];
        let user_cert = {
            let issuer = Issuer::new(root_params, &root_pair);
            user_params.signed_by(&user_pair, &issuer).unwrap()
        };

        let root = KeyEntry {
            alias: "root".into(),
            key: root_key,
            cert: cert::parse(root_cert.der()).unwrap(),
        };
        let user = KeyEntry {
            alias: "user".into(),
            key: user_key,
            cert: cert::parse(user_cert.der()).unwrap(),
        };
        let user_p12 = pkcs12_of(&user, "user");
        fs::write(dir.join(ROOT_FILE), pkcs12_of(&root, "root")).unwrap();
        fs::write(dir.join(USER_FILE), &user_p12).unwrap();
        DemoPki { root, user_p12 }
    }

    /// Reads the PKI an earlier run left in `dir`.
    pub fn open(dir: &Path) -> DemoPki {
        let root = pkcs12::load(&fs::read(dir.join(ROOT_FILE)).unwrap(), PASSWORD)
            .unwrap()
            .remove(0);
        DemoPki {
            root,
            user_p12: fs::read(dir.join(USER_FILE)).unwrap(),
        }
    }

    pub fn exists(dir: &Path) -> bool {
        dir.join(ROOT_FILE).is_file() && dir.join(USER_FILE).is_file()
    }

    /// The user's key container, as a selector for `KeyRequest::new(&selector, Some(PASSWORD))`.
    pub fn user_key(&self) -> KeySelector {
        KeySelector::inline(self.user_p12.clone(), None)
    }

    /// The in-process distribution point of the demo CA.
    pub fn crl_responder(&self) -> MockCrl {
        MockCrl::new(self.root.clone())
    }

    /// Trust, status transport and clock for `Engine`: the demo root is the only anchor.
    pub fn validation(&self, transport: Arc<dyn HttpTransport>) -> ValidationServices {
        ValidationServices::new(
            CaSet::new(vec![self.root.cert.clone()]),
            Vec::new(),
            transport,
            NetworkPolicy::only_endpoints([CRL_ORIGIN]).unwrap(),
            Arc::new(OffsetDateTime::now_utc),
        )
    }
}

/// Opens `dir` as the example's working directory, issuing the demo PKI on first use.
pub fn open_or_create(dir: &Path) -> DemoPki {
    fs::create_dir_all(dir).unwrap();
    if DemoPki::exists(dir) {
        DemoPki::open(dir)
    } else {
        DemoPki::create(dir)
    }
}

/// The working directory of an example: the first argument, else a fresh directory under the
/// system temporary directory.
pub fn work_dir(arg: Option<String>, tag: &str) -> PathBuf {
    arg.map(PathBuf::from).unwrap_or_else(|| {
        std::env::temp_dir().join(format!("oncl-sdk-example-{tag}-{}", std::process::id()))
    })
}

/// An embedding application's cancellation/progress hook: here it never cancels.
pub struct NeverCancelled;

impl OperationControl for NeverCancelled {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}

/// An embedding application's key-use guard. `before_use` must record the use durably BEFORE
/// the private key is applied (a failure refuses the use); `finish` records the outcome. This
/// one keeps the lines in memory and prints them; a real host writes its audit log.
#[derive(Default)]
pub struct AuditGuard {
    pub lines: Mutex<Vec<String>>,
}

impl KeyUseGuard for AuditGuard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let line = format!(
            "before_use action={:?} key={:?}",
            event.action, event.key_id
        );
        println!("audit: {line}");
        self.lines.lock().unwrap().push(line);
        Ok(KeyUseReceipt::new(event.clone()))
    }

    fn finish(&self, _: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        let line = format!("finish outcome={outcome:?}");
        println!("audit: {line}");
        self.lines.lock().unwrap().push(line);
        Ok(())
    }
}

/// The engine of the examples: key sources, guard, trust and transport, default limits.
pub fn engine(pki: &DemoPki, guard: Arc<AuditGuard>, transport: Arc<dyn HttpTransport>) -> Engine {
    let services = EngineServices::hash_only(ResourceLimits::default())
        .with_keys(Arc::new(KeySources::new()), guard)
        .with_validation(pki.validation(transport));
    Engine::new(services).expect("engine services are consistent")
}

/// A transport that answers nothing: a host that supplies no network. Strict validation then
/// fails closed for a certificate whose status cannot be established.
pub struct NoNetwork;

impl HttpTransport for NoNetwork {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other(format!("no network: {}", request.url)))
    }
}
