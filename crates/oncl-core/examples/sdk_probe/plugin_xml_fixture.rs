//! Bounded synthetic XAdES host configuration shared by WASM tests and L01 smoke.
use crate::plugin_crypto as crypto;
use oncl_core::{
    CadesConfiguration, ValidationServices, keys::KeySelector, plugins::PluginPermission,
};
use oncl_pdk::abi::{self, Import};
use oncl_pki::{
    evidence::EvidenceLimits,
    http::{HttpError, HttpErrorKind, HttpMethod, HttpReply, HttpRequest, HttpTransport},
    tsp::{MockTsa, TsaProfile, TsaSpec},
    validation::NetworkPolicy,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
pub(crate) const TSA: &str = "http://tsa.synthetic.test";
pub(crate) fn tsa() -> TsaSpec {
    let mut spec = TsaSpec::from(TsaProfile::kalkan_default());
    spec.url = TSA.into();
    spec
}
pub(crate) fn limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 24,
        max_bytes: 6_291_456,
        max_item_bytes: 262_144,
        max_crl_bytes: 6_291_456,
        max_crl_item_bytes: 262_144,
        max_total_bytes: 6_291_456,
        max_chain_len: 16,
        max_proofs: 8,
        max_coverage_parts: 256,
        max_coverage_bytes: 1 << 40,
    }
}
pub(crate) fn permission(imports: &[Import], keys: &[KeySelector]) -> PluginPermission {
    PluginPermission::new(
        "test.l01",
        "sign",
        oncl_core::plugins::CallerContext::ServiceClient("l01-authorized-service".into()),
        imports.iter().copied(),
    )
    .with_keys(keys.iter().map(KeySelector::key_id))
    .with_pki_endpoints([
        (HttpMethod::Get, "http://ocsp.synthetic.test"),
        (HttpMethod::Post, "http://ocsp.synthetic.test"),
        (
            HttpMethod::Get,
            "http://crl.synthetic.test/root-gost2015.crl",
        ),
        (
            HttpMethod::Get,
            "http://crl.synthetic.test/inter-gost2015.crl",
        ),
        (HttpMethod::Get, TSA),
    ])
    .unwrap()
}
pub(crate) struct Transport {
    inner: Arc<dyn HttpTransport>,
    pub(crate) tsa_requests: AtomicUsize,
    pub(crate) fail_tsa: AtomicBool,
}
impl HttpTransport for Transport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        if request.url.starts_with(TSA) {
            self.tsa_requests.fetch_add(1, Ordering::SeqCst);
            if self.fail_tsa.load(Ordering::SeqCst) {
                return Err(HttpError::new(
                    HttpErrorKind::Connect,
                    "synthetic TSA refusal",
                ));
            }
            MockTsa::new(crypto::issued("tsa-gost2015"))
                .with_gen_time(crypto::NOW)
                .send(request)
        } else {
            self.inner.send(request)
        }
    }
}
pub(crate) fn services() -> (ValidationServices, CadesConfiguration, Arc<Transport>) {
    let mut actual = None;
    let validation = crypto::validation_network(
        |inner| {
            let transport = Arc::new(Transport {
                inner,
                tsa_requests: AtomicUsize::new(0),
                fail_tsa: AtomicBool::new(false),
            });
            actual = Some(transport.clone());
            transport
        },
        NetworkPolicy::only_endpoints([
            "http://ocsp.synthetic.test",
            "http://crl.synthetic.test",
            TSA,
        ])
        .unwrap(),
    );
    (
        validation,
        CadesConfiguration::new(limits(), tsa()),
        actual.unwrap(),
    )
}
pub(crate) fn args(level: abi::XadesLevel, xml: &[u8]) -> abi::XadesArgs {
    use der::Encode;
    abi::XadesArgs {
        handle: 1,
        xml: xml.to_vec().into(),
        level,
        tsa: abi::TsaChoice::Basics,
        chain: vec![
            crypto::raw("inter-gost2015.key")
                .cert
                .to_der()
                .unwrap()
                .into(),
        ],
        signature_method: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".into()),
        digest_method: None,
    }
}
pub(crate) fn matching_issuer(
    name: &str,
) -> (oncl_core::keys::KeySelector, oncl_core::ValidationServices) {
    let (key, validation, _) = matching_issuer_with_certificate(name);
    (key, validation)
}
/// [`matching_issuer`] and the certificate the key's container holds.
pub(crate) fn matching_issuer_with_certificate(
    name: &str,
) -> (
    oncl_core::keys::KeySelector,
    oncl_core::ValidationServices,
    oncl_pki::cert::Certificate,
) {
    use der::Encode;
    use oncl_pki::{
        crl::MockCrl,
        http::RouteTransport,
        pkcs12,
        pkix::CaSet,
        testing::{TestCertSpec, issue_cert},
        validation::NetworkPolicy,
    };
    use std::sync::Arc;
    let mut root = crypto::raw("root-gost2015.key");
    let leaf = crypto::raw(name);
    root.key = leaf.key.clone();
    let mut root_spec = TestCertSpec::from_cert(&root.cert);
    root_spec
        .extensions
        .retain(|e| !matches!(e.extn_id.to_string().as_str(), "2.5.29.14" | "2.5.29.35"));
    root_spec.public_key = root.key.public_key().to_spki();
    root.cert = issue_cert(&root, root_spec);
    let mut leaf_spec = TestCertSpec::from_cert(&leaf.cert);
    leaf_spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    leaf_spec.extensions.extend(
        TestCertSpec::from_cert(&crypto::raw("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|e| e.extn_id.to_string() == "2.5.29.31"),
    );
    let certificate = issue_cert(&root, leaf_spec);
    let container = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: leaf.alias.clone(),
            pkcs8_der: leaf.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(certificate.to_der().unwrap()),
        }],
        &[],
        crypto::PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x71),
    )
    .unwrap();
    let crl = Arc::new(
        MockCrl::new(root.clone())
            .with_this_update(crypto::NOW - time::Duration::MINUTE)
            .next_update(Some(crypto::NOW + time::Duration::HOUR)),
    );
    let validation = oncl_core::ValidationServices::new(
        CaSet::new(vec![root.cert]),
        vec![],
        Arc::new(RouteTransport::new(vec![(
            "http://crl.synthetic.test".into(),
            crl,
        )])),
        NetworkPolicy::only_endpoints(["http://crl.synthetic.test"]).unwrap(),
        Arc::new(|| crypto::NOW),
    );
    (
        oncl_core::keys::KeySelector::inline(container, None),
        validation,
        certificate,
    )
}
