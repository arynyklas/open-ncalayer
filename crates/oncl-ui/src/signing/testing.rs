//! A synthetic world for the signing and tool tests: a root, an OCSP responder, a time stamp
//! service and a signing key made on the spot, an engine trusting them, and documents.
use std::path::PathBuf;
use std::sync::Arc;

use der::{
    Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use oncl_core::Engine;
use oncl_pki::http::HttpTransport;
use oncl_pki::http::RouteTransport;
use oncl_pki::keygen::{self, KeySpec};
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::{self, KeyEntry};
use oncl_pki::resource::ResourceLimits;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::MockTsa;
use time::OffsetDateTime;
use x509_cert::ext::Extension;
use zeroize::Zeroizing;

use super::controller::{ActionKind, Controller, Effect, Event, Item};
use super::runner::{
    ConsentGuard, ExtraTrust, Outcome, desktop_engine, freeze, open_key_store, sign,
};
use crate::workspace::{Destination, JobControl, SignSpec};

pub(crate) const NOW: i64 = 1_793_620_800;
pub(crate) const ORIGIN: &str = "http://127.0.0.1:9";
pub(crate) const PASSWORD: &str = "synthetic loopback password";

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW).unwrap()
}

pub(crate) fn fixture(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}

pub(crate) fn short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
    out.extend_from_slice(body);
    out
}

pub(crate) fn aia(url: &str) -> Extension {
    let mut access = vec![6, 8, 43, 6, 1, 5, 5, 7, 48, 1];
    access.extend(short_tlv(0x86, url.as_bytes()));
    Extension {
        extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
        critical: false,
        extn_value: OctetString::new(short_tlv(0x30, &short_tlv(0x30, &access))).unwrap(),
    }
}

pub(crate) fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}

/// A synthetic root, an OCSP responder, a time stamp service and a signing key under it, all
/// made here.
pub(crate) struct World {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) root_entry: KeyEntry,
    pub(crate) leaf: KeyEntry,
    pub(crate) root: oncl_pki::cert::Certificate,
    /// What the engine reaches: the responder at `/ocsp` and the time service at `/tsa`.
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) store: PathBuf,
}

pub(crate) fn world() -> World {
    let mut root = fixture("user-rsa-sign");
    root.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec = TestCertSpec::from_cert(
        &oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
    );
    strip(&mut spec);
    spec.public_key = root.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 1];
    root.cert = issue_cert(&root, spec.clone());
    root.cert = issue_cert(&root, spec);
    let mut responder = fixture("user-rsa-sign");
    responder.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec = TestCertSpec::from_cert(&fixture("ocsp-gost2015").cert);
    strip(&mut spec);
    spec.public_key = responder.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 3];
    responder.cert = issue_cert(&root, spec);
    let mut leaf = fixture("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&leaf.cert);
    strip(&mut spec);
    spec.serial = vec![0x71, 4, 10];
    spec.extensions.push(aia(&format!("{ORIGIN}/ocsp")));
    leaf.cert = issue_cert(&root, spec);
    let mut tsa = fixture("tsa-gost2015");
    tsa.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec = TestCertSpec::from_cert(&tsa.cert);
    strip(&mut spec);
    spec.public_key = tsa.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 20];
    spec.extensions.push(aia(&format!("{ORIGIN}/ocsp")));
    tsa.cert = issue_cert(&root, spec);
    let dir = tempfile::tempdir().unwrap();
    let bytes = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: leaf.alias.clone(),
            pkcs8_der: leaf.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(leaf.cert.to_der().unwrap()),
        }],
        &[],
        PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x5a),
    )
    .unwrap();
    let store = dir.path().join("key.p12");
    std::fs::write(&store, bytes).unwrap();
    let ocsp = Arc::new(MockOcsp::new(responder).with_now(now()));
    let tsa = Arc::new(MockTsa::new(tsa).with_gen_time(now()));
    let http: Arc<dyn HttpTransport> = Arc::new(RouteTransport::new(vec![
        (format!("{ORIGIN}/ocsp"), ocsp.clone()),
        (format!("{ORIGIN}/tsa"), tsa.clone()),
    ]));
    World {
        dir,
        root_entry: root.clone(),
        leaf,
        root: root.cert,
        http,
        store,
    }
}

pub(crate) fn engine(w: &World) -> (Engine, Arc<ConsentGuard>) {
    desktop_engine(
        ResourceLimits::default(),
        w.http.clone(),
        ExtraTrust {
            anchors: vec![w.root.clone()],
            origins: vec![ORIGIN.to_owned()],
            tsa: Some(format!("{ORIGIN}/tsa")),
        },
        &w.dir.path().join("spool"),
        Arc::new(now),
    )
    .unwrap()
}

/// Signs `paths` as `spec` says, the user confirming exactly what the engine froze (the page's
/// whole dance, driven by the real controller). The key store is the world's, the password
/// its own.
pub(crate) fn sign_confirmed(
    engine: &Engine,
    guard: &ConsentGuard,
    w: &World,
    paths: &[PathBuf],
    spec: &SignSpec,
    destination: &Destination,
) -> Outcome {
    let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
    let shown: Vec<Item> = paths
        .iter()
        .map(|p| freeze(engine, p, &Arc::new(JobControl::default())).unwrap())
        .collect();
    sign(
        engine,
        guard,
        &w.store,
        &candidates[0].alias,
        &Zeroizing::new(PASSWORD.to_owned()),
        paths,
        spec,
        destination,
        &Arc::new(JobControl::default()),
        |frozen| {
            let mut c = Controller::new("tools", ActionKind::Sign);
            c.dispatch(Event::Documents(shown.clone()));
            c.dispatch(Event::Profile(spec.label()));
            c.dispatch(Event::KeyStore(w.store.display().to_string()));
            c.dispatch(Event::PasswordSubmitted(Zeroizing::new(
                PASSWORD.to_owned(),
            )));
            c.dispatch(Event::Unlocked(candidates.clone()));
            c.dispatch(Event::CertificateChosen(0));
            c.dispatch(Event::Frozen(&frozen.items));
            c.dispatch(Event::Arm);
            match c.dispatch(Event::Confirm {
                frozen: &frozen.items,
            }) {
                Effect::None => super::runner::Decision::Proceed(Box::new(
                    c.take_approved().expect("the confirmation was accepted"),
                )),
                _ => super::runner::Decision::Abort,
            }
        },
    )
}

pub(crate) fn documents(w: &World, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|n| {
            let p = w.dir.path().join(n);
            std::fs::write(&p, format!("the document {n}")).unwrap();
            p
        })
        .collect()
}
