//! Shared by the XAdES large-CRL and unsigned-layout cases: a synthetic root CA that
//! issues the signer and the TSA, a mock TSA and OCSP responder, and the real source
//! signer producing a baseline XAdES document at the requested level.
#![allow(dead_code)]
use oncl_pki::{
    crl::MockCrl,
    evidence::AdesLevel,
    http::{HttpError, HttpReply, HttpRequest, HttpTransport, RouteTransport},
    io::{Source, TemporaryStore},
    ocsp::MockOcsp,
    pkcs12::{KeyEntry, load},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
    testing::{TestCertSpec, issue_cert},
    tsp::{MockTsa, TsaProfile, TsaSpec},
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy},
};
use oncl_testkit::{read, synthetic};
use oncl_xml::{
    XmlSignProfile,
    xades::{XadesServices, XadesSourceSpec},
};
use std::io::Cursor;
use std::sync::Arc;
use time::{OffsetDateTime, macros::datetime};

pub const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
/// About 5 MB of DER: far over the 256 KiB markup cap and over the 4 MiB where a 16x
/// container charge exceeds the default 64 MiB metadata budget.
pub const REVOKED: u32 = 200_000;

pub struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
pub struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline verification must not fetch"))
    }
}
pub fn key(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(&f.path), &f.password).unwrap().remove(0)
}

pub struct Pki {
    pub signer: KeyEntry,
    pub anchors: oncl_pki::pkix::CaSet,
    pub http: RouteTransport,
    pub tsa: TsaSpec,
}
impl Pki {
    pub fn new() -> Self {
        let root = key("root-gost2015.key");
        let aia = TestCertSpec::from_cert(&key("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|e| {
                matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            })
            .collect::<Vec<_>>();
        let reissue = |mut entry: KeyEntry| {
            let mut spec = TestCertSpec::from_cert(&entry.cert);
            spec.extensions.retain(|e| {
                !matches!(
                    e.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            });
            spec.extensions.extend(aia.clone());
            entry.cert = issue_cert(&root, spec);
            entry
        };
        let signer = reissue(key("user-rsa-sign"));
        let tsa_key = reissue(key("tsa-gost2015"));
        let mut responder = key("ocsp-gost2015");
        responder.cert = issue_cert(&root, TestCertSpec::from_cert(&responder.cert));
        let mut tsa = TsaSpec::from(TsaProfile::basics_default());
        tsa.url = "http://tsa.synthetic.test".into();
        let http = RouteTransport::new(vec![
            (
                tsa.url.clone(),
                Arc::new(MockTsa::new(tsa_key).with_gen_time(NOW))
                    as Arc<dyn oncl_pki::http::HttpTransport>,
            ),
            (
                "http://ocsp.synthetic.test".into(),
                Arc::new(MockOcsp::new(responder).with_now(NOW)),
            ),
        ]);
        Self {
            signer,
            anchors: oncl_pki::pkix::CaSet::new(vec![root.cert]),
            http,
            tsa,
        }
    }
    pub fn serial(&self) -> Vec<u8> {
        self.signer
            .cert
            .tbs_certificate()
            .serial_number()
            .as_bytes()
            .to_vec()
    }
    /// The root's complete CRL: `revoked` unrelated serials and, when asked, the signer in
    /// the middle of the list; `wrong_key` makes the list not issued by the root.
    pub fn crl(&self, revoked: u32, revoke_signer: bool, wrong_key: bool) -> Vec<u8> {
        let mut crl = MockCrl::new(key("root-gost2015.key"))
            .with_this_update(NOW - time::Duration::MINUTE)
            .next_update(Some(NOW + time::Duration::HOUR));
        if wrong_key {
            crl = crl.wrong_key();
        }
        let serial = self.serial();
        for index in 0..revoked {
            if revoke_signer && index == revoked / 2 {
                crl = crl.revoke_with_reason(&serial, NOW - time::Duration::DAY, 1);
            }
            crl = crl.revoke(
                &(0x0100_0000_u32 + index).to_be_bytes(),
                NOW - time::Duration::DAY,
            );
        }
        crl.der()
    }
    /// An XAdES document of the fixed content at `level`, by the real source signer.
    pub fn xades(&mut self, level: AdesLevel) -> String {
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: NOW,
            anchors: &self.anchors,
            intermediates: &[],
            http: &self.http,
        };
        let network = NetworkPolicy::only_endpoints([
            "http://tsa.synthetic.test",
            "http://ocsp.synthetic.test",
        ])
        .unwrap();
        let services = XadesServices {
            validation: &context,
            network: &network,
            temporary: &store,
            tsa: Some(&self.tsa),
            material: oncl_pki::cms::ades::ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            evidence_limits: None,
            host_clock: None,
        };
        let spec = XadesSourceSpec {
            xml: XmlSignProfile {
                target: Some("p"),
                parent: Some("s"),
                signature_id: Some("sig"),
                ..Default::default()
            },
            level,
            signing_time: NOW,
        };
        let mut bytes = Vec::new();
        oncl_xml::xades::sign_source(
            Source::sequential(
                &mut Cursor::new(b"<r><data Id='p'>protected</data><s Id='s'/></r>"),
                None,
            ),
            &spec,
            &mut self.signer,
            &services,
            &mut bytes,
            &mut scope,
        )
        .unwrap();
        String::from_utf8(bytes).unwrap()
    }
    /// An XAdES-LT of the fixed content.
    pub fn lt(&mut self) -> String {
        self.xades(AdesLevel::Lt)
    }
}
