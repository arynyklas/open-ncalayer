//! What every plugin may ask of the core's cryptography: digests ([`hash`]), certificate
//! details as Kalkan renders them ([`cert_details`]), the CAs the core trusts
//! ([`ca_list`], [`ca_issuer`]) and certification paths through them ([`pkix_path`]); with
//! `keys`, time-stamps ([`tsp_stamp`], [`tsp_request`]), OCSP ([`ocsp_fetch`]) and CRLs
//! ([`crl_fetch`]), which the core requests itself, only from the PKI hosts
//! ([`check_pki_url`]). A built-in module's requests are the core's own: through the
//! core's transport, to the services it names, as the core's modules always asked them.

use super::{RequestBudget, denied, invalid, is_builtin};
use crate::cause;
use crate::host::{HostState, unix_ms};
use der::asn1::ObjectIdentifier;
use oncl_pdk::abi::{
    Bytes, CertArgs, CertDetails, CertStatusAbi, Check, CrlArgs, CrlOutcome, HashAlg, HashArgs,
    HostResult, IssuerSel, KeyUsageBit, MAX_PKI_TIMEOUT_MS, MAX_TSP_RETRIES, NetFailure, NetKind,
    NetStage, Nonce, OcspArgs, OcspOutcome, PathArgs, PathOutcome, PathTime, PkiMethod, PkiUrl,
    Problem, Revocation, SignerReport, SignerSel, StampArgs, StampMode, StampOutcome, TokenForm,
    TsaChoice, TspOutcome, TspReport, TspRequestArgs, VerifyArgs, VerifyAt, VerifyReport,
    XmlSigReport, XmlVerifyArgs,
};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::crl::CrlError;
use oncl_pki::http::{self, HttpError, HttpReply, HttpRequest, HttpTransport, NonceSpec};
use oncl_pki::info::{self, KeyUsageBits, cert_info, kcert_types};
use oncl_pki::key::{self, SigAlg};
use oncl_pki::ocsp::{self, CertStatus, OcspError};
use oncl_pki::pkix::{self, CaSet, PathError};
use oncl_pki::tsp::{self, TsaProfile, TsaSpec};
use oncl_pki::{cms, crl, oid, xmldsig};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// The core's algorithm of `alg`.
pub(crate) fn hash_alg(alg: HashAlg) -> key::HashAlg {
    match alg {
        HashAlg::Sha1 => key::HashAlg::Sha1,
        HashAlg::Sha256 => key::HashAlg::Sha256,
        HashAlg::Sha512 => key::HashAlg::Sha512,
        HashAlg::Gost34311 => key::HashAlg::Gost34311,
        HashAlg::Streebog256 => key::HashAlg::Streebog256,
        HashAlg::Streebog512 => key::HashAlg::Streebog512,
    }
}

/// `hash`: the digest of the data (at most what one host call carries).
pub(crate) fn hash(args: HashArgs) -> HostResult<Bytes> {
    Ok(Bytes::from(hash_alg(args.alg).digest(&args.data)))
}

/// The certificate of `der`.
pub(crate) fn parse(der: &[u8]) -> HostResult<Certificate> {
    cert::parse(der).map_err(|e| invalid(format!("not a certificate: {e}")))
}

pub(crate) fn der_of(cert: &Certificate) -> Bytes {
    Bytes::from(der::Encode::to_der(cert).expect("a decoded certificate re-encodes"))
}

/// `cert_details`: the names, types, key identifiers, serial and URLs of a certificate.
pub(crate) fn cert_details(args: CertArgs) -> HostResult<CertDetails> {
    let cert = parse(&args.der)?;
    let tbs = cert.tbs_certificate();
    let details = cert_info(&cert);
    Ok(CertDetails {
        subject_dn: info::kalkan_dn(tbs.subject()),
        issuer_dn: info::kalkan_dn(tbs.issuer()),
        knca_types: kcert_types(&details)
            .into_iter()
            .map(|t| t.name().to_owned())
            .collect(),
        ski_hex: info::ski_hex(&cert),
        aki_hex: info::aki_hex(&cert),
        serial_dec: info::serial_dec(&cert),
        ocsp_urls: info::aia_urls(&cert, oid::AD_OCSP),
        ca_issuers_urls: info::aia_urls(&cert, oid::AD_CA_ISSUERS),
        crl_urls: crl::crl_urls(&cert),
        signing_alg: details.signing_alg().ok().map(|alg| {
            match alg {
                SigAlg::Gost2004 => "gost2004",
                SigAlg::Gost2015_512 => "gost2015_512",
                SigAlg::RsaSha256 => "rsa_sha256",
                SigAlg::RsaSha1 => "rsa_sha1",
            }
            .to_owned()
        }),
        issuer_cn: info::common_name(tbs.issuer()),
    })
}

/// `ca_list`: the CAs the core trusts, in their order.
pub(crate) fn ca_list(state: &HostState) -> Vec<Bytes> {
    state.services.cas.certs().iter().map(der_of).collect()
}

/// `ca_issuer`: the CA among them that issued the certificate (by name, the one whose key
/// identifier matches first), if any.
pub(crate) fn ca_issuer(state: &HostState, args: CertArgs) -> HostResult<Option<Bytes>> {
    let cert = parse(&args.der)?;
    Ok(state.services.cas.issuers_of(&cert).next().map(der_of))
}

/// The PKI hosts of the NCA: the only hosts the core asks for time-stamps, OCSP and CRLs
/// on a plugin's behalf ([`crate::HostServices::pki_hosts`]), and their subdomains. The
/// NCA's CAs publish their CRLs on `crl.root.gov.kz` and `crl1.root.gov.kz`.
pub const NCA_PKI_HOSTS: [&str; 7] = [
    "tsp.pki.gov.kz",
    "ocsp.pki.gov.kz",
    "crl.pki.gov.kz",
    "pki.gov.kz",
    "test.pki.gov.kz",
    "crl.root.gov.kz",
    "crl1.root.gov.kz",
];

/// [`NCA_PKI_HOSTS`], for [`crate::HostServices::pki_hosts`].
pub fn nca_pki_hosts() -> Arc<[String]> {
    NCA_PKI_HOSTS.iter().map(|h| (*h).to_owned()).collect()
}

/// The TSA of `PkiUrl::Default`.
const DEFAULT_TSA: &str = "http://tsp.pki.gov.kz";
/// The OCSP responder of `PkiUrl::Default`.
const DEFAULT_OCSP: &str = "http://ocsp.pki.gov.kz";

/// A URL of a PKI service, if the core may ask it: `http(s)://` to one of the PKI hosts
/// or a subdomain of one; any for a built-in module.
fn check_pki_url(state: &HostState, url: &str) -> HostResult<()> {
    if is_builtin(state) {
        return Ok(());
    }
    check_pki_url_in(&state.services.pki_hosts, url)
}

/// [`check_pki_url`] against `pki_hosts`.
fn check_pki_url_in(pki_hosts: &[String], url: &str) -> HostResult<()> {
    let parsed = url::Url::parse(url).map_err(|e| invalid(format!("{url}: {e}")))?;
    let host = match (parsed.scheme(), parsed.host_str()) {
        ("http" | "https", Some(host)) => host.to_ascii_lowercase(),
        _ => return Err(denied(format!("{url} is not an http(s) URL of a PKI host"))),
    };
    let allowed = pki_hosts.iter().any(|pki| {
        host == *pki
            || host
                .strip_suffix(pki.as_str())
                .is_some_and(|sub| sub.ends_with('.'))
    });
    if allowed {
        Ok(())
    } else {
        Err(denied(format!("{host} is not a PKI host")))
    }
}

/// The core's transport for an instance's PKI requests. A plugin's go only to the PKI
/// hosts, never to where a redirect points (a 3xx reply is the reply), each request
/// counted in the call's [`super::MAX_HTTP_REQUESTS`]; a built-in module's are the core's
/// own.
pub(super) struct PkiHttp {
    /// `None` for a built-in module.
    hosts: Option<Arc<[String]>>,
    http: Arc<dyn HttpTransport>,
    budget: RequestBudget,
}

impl PkiHttp {
    pub(super) fn of(state: &HostState) -> Self {
        PkiHttp {
            hosts: (!is_builtin(state)).then(|| Arc::clone(&state.services.pki_hosts)),
            http: Arc::clone(&state.services.http),
            budget: state.call.http_requests.clone(),
        }
    }
}

impl HttpTransport for PkiHttp {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let Some(hosts) = &self.hosts else {
            return self.http.send(request);
        };
        check_pki_url_in(hosts, request.url).map_err(|e| HttpError::other(e.message))?;
        self.budget
            .take()
            .map_err(|e| HttpError::other(e.message))?;
        let mut request = *request;
        request.opts.redirects = false;
        self.http.send(&request)
    }
}

/// The URL of `url`: the default one, the one `cert_url` reads from the certificate, or the
/// given one; `None` if the certificate names none. It must be a PKI host's.
fn pki_url(
    state: &HostState,
    url: &PkiUrl,
    default: &str,
    cert_url: impl Fn(&Certificate) -> Option<String>,
) -> HostResult<Option<String>> {
    let url = match url {
        PkiUrl::Default => Some(default.to_owned()),
        PkiUrl::FromCert(der) => cert_url(&parse(der)?),
        PkiUrl::Fixed(url) => Some(url.clone()),
    };
    if let Some(url) = &url {
        check_pki_url(state, url)?;
    }
    Ok(url)
}

/// The TSA URL a certificate names: the time-stamping access of its SubjectInfoAccess,
/// else of its AuthorityInfoAccess.
fn tsa_url_of(cert: &Certificate) -> Option<String> {
    info::sia_urls(cert, oid::AD_TIME_STAMPING)
        .into_iter()
        .chain(info::aia_urls(cert, oid::AD_TIME_STAMPING))
        .next()
}

fn pki_method(method: &PkiMethod) -> http::PkiMethod {
    match method {
        PkiMethod::Get => http::PkiMethod::Get,
        PkiMethod::GetUrlEncoded => http::PkiMethod::GetUrlEncoded,
        PkiMethod::Post { content_type } => http::PkiMethod::Post {
            content_type: content_type.clone(),
        },
        PkiMethod::PostWithPath => http::PkiMethod::PostWithPath,
        PkiMethod::GetUnder(limit) => http::PkiMethod::GetUnder(*limit),
    }
}

fn nonce(nonce: &Nonce) -> HostResult<NonceSpec> {
    Ok(match nonce {
        Nonce::None => NonceSpec::None,
        Nonce::Random(len) => NonceSpec::Random(*len),
        Nonce::Value(value) if value.len() <= usize::from(u8::MAX) => {
            NonceSpec::Value(value.to_vec())
        }
        Nonce::Value(_) => return Err(invalid("a nonce is at most 255 bytes")),
    })
}

fn timeout(ms: u32) -> HostResult<Duration> {
    if ms == 0 || ms > MAX_PKI_TIMEOUT_MS {
        return Err(invalid(format!(
            "a timeout is 1 to {MAX_PKI_TIMEOUT_MS} ms"
        )));
    }
    Ok(Duration::from_millis(u64::from(ms)))
}

fn object_id(text: &str) -> HostResult<ObjectIdentifier> {
    ObjectIdentifier::new(text).map_err(|e| invalid(format!("OID {text:?}: {e}")))
}

/// A PKI request that failed, as the plugin sees it.
pub(super) fn net_failure(
    stage: NetStage,
    url: &str,
    kind: http::NetKind,
    detail: String,
) -> NetFailure {
    let address = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned());
    NetFailure {
        stage,
        kind: match kind {
            http::NetKind::UnknownHost => NetKind::UnknownHost,
            http::NetKind::Connect => NetKind::Connect,
            http::NetKind::Timeout => NetKind::Timeout,
            http::NetKind::Tls => NetKind::Tls,
            http::NetKind::Http(status) => NetKind::Http(status),
            http::NetKind::InvalidResponse => NetKind::InvalidResponse,
            http::NetKind::Rejected(status) => NetKind::Rejected(status),
            http::NetKind::ClockSkew => NetKind::ClockSkew,
            http::NetKind::Other => NetKind::Other,
        },
        address,
        detail,
    }
}

/// The certificate names no URL of the service.
fn no_url(stage: NetStage) -> NetFailure {
    NetFailure {
        stage,
        kind: NetKind::Other,
        address: String::new(),
        detail: "the certificate names no URL".to_owned(),
    }
}

/// A resolved TSA: its spec, or the failure of a certificate without a TSA URL.
pub(crate) type Tsa = Result<TsaSpec, NetFailure>;

/// The core's TSA spec of `choice`, its URL checked. A built-in module's basics TSA is the
/// core's ([`crate::HostServices::tsa`]).
pub(crate) fn tsa_spec(state: &HostState, choice: &TsaChoice) -> HostResult<Tsa> {
    let spec = match choice {
        TsaChoice::Basics if is_builtin(state) => TsaSpec::from(state.services.tsa.clone()),
        TsaChoice::Basics => TsaSpec::from(TsaProfile::basics_default()),
        TsaChoice::Kalkan => TsaSpec::from(TsaProfile::kalkan_default()),
        TsaChoice::Custom(custom) => {
            if custom.retries > MAX_TSP_RETRIES {
                return Err(invalid(format!("at most {MAX_TSP_RETRIES} retries")));
            }
            let Some(url) = pki_url(state, &custom.url, DEFAULT_TSA, tsa_url_of)? else {
                return Ok(Err(no_url(NetStage::Tsp)));
            };
            TsaSpec {
                url,
                method: pki_method(&custom.method),
                hash: hash_alg(custom.hash),
                policy: custom.policy.as_deref().map(object_id).transpose()?,
                nonce: nonce(&custom.nonce)?,
                cert_req: custom.cert_req,
                retries: custom.retries,
                timeout: timeout(custom.timeout_ms)?,
                check_skew: custom
                    .check_skew_ms
                    .map(|ms| Duration::from_millis(u64::from(ms))),
                require_tsa_eku: custom.require_tsa_eku,
            }
        }
    };
    check_pki_url(state, &spec.url)?;
    Ok(Ok(spec))
}

/// The failure of a time-stamp from `spec`.
pub(crate) fn tsp_failure(spec: &TsaSpec, e: &tsp::TspError) -> NetFailure {
    net_failure(NetStage::Tsp, &spec.url, e.kind(), e.to_string())
}

/// `tsp_stamp`: time-stamps of signers of a CMS. A signer of a certificate is the first
/// one Kalkan's way finds; without one nothing is asked.
pub(crate) fn tsp_stamp(state: &HostState, args: StampArgs) -> HostResult<StampOutcome> {
    let cms_invalid = |e: cms::CmsError| invalid(e.to_string()).with_cause(cause::cms(&e));
    let count = || cms::signer_count(&args.cms).map_err(cms_invalid);
    let signers = match &args.signers {
        SignerSel::OfCert(der) => {
            let cert = parse(der)?;
            match cms::signer_index_of(&args.cms, &cert).map_err(cms_invalid)? {
                Some(index) => tsp::SignerSel::Index(index),
                None => return Ok(StampOutcome::NoSigner),
            }
        }
        SignerSel::Last if count()? == 0 => return Err(invalid("the CMS has no signers")),
        SignerSel::Last => tsp::SignerSel::Last,
        SignerSel::Index(index) => {
            let count = count()?;
            match usize::try_from(*index) {
                Ok(i) if i < count => tsp::SignerSel::Index(i),
                _ => return Err(invalid(format!("no signer {index} among {count}"))),
            }
        }
        SignerSel::AllUnstamped => {
            count()?;
            tsp::SignerSel::AllUnstamped
        }
    };
    let spec = match tsa_spec(state, &args.tsa)? {
        Ok(spec) => spec,
        Err(failure) => return Ok(StampOutcome::Failed(failure)),
    };
    let mode = match args.mode {
        StampMode::Replace => tsp::StampMode::Replace,
        StampMode::Append => tsp::StampMode::Append,
    };
    let form = match args.token {
        TokenForm::Token => tsp::TokenForm::Token,
        TokenForm::WholeResponse => tsp::TokenForm::WholeResponse,
    };
    Ok(
        match tsp::stamp(&args.cms, signers, &spec, mode, form, &PkiHttp::of(state)) {
            Ok(cms) => StampOutcome::Stamped(Bytes::from(cms)),
            Err(e) => StampOutcome::Failed(tsp_failure(&spec, &e)),
        },
    )
}

/// `tsp_request`: a time-stamp of a hash.
pub(crate) fn tsp_request(state: &HostState, args: TspRequestArgs) -> HostResult<TspOutcome> {
    let spec = match tsa_spec(state, &TsaChoice::Custom(args.tsa))? {
        Ok(spec) => spec,
        Err(failure) => return Ok(TspOutcome::Failed(failure)),
    };
    Ok(
        match tsp::request(&spec, &args.imprint, &PkiHttp::of(state)) {
            Ok(reply) => TspOutcome::Ok {
                response: Bytes::from(reply.response),
                token: Bytes::from(reply.token),
                gen_time_ms: unix_ms(reply.tst.gen_time),
                tsa_cert: Some(der_of(&reply.tsa_cert)),
            },
            Err(e) => TspOutcome::Failed(tsp_failure(&spec, &e)),
        },
    )
}

/// `pkix_path`: whether a certification path from the certificate through the CAs the
/// core trusts is valid at the time asked.
pub(crate) fn pkix_path(state: &HostState, args: PathArgs) -> HostResult<PathOutcome> {
    let cert = parse(&args.cert)?;
    let now = (state.services.clock)();
    let at = match args.at {
        PathTime::Now => now,
        PathTime::NotAfterIfExpired => pkix::validation_time(&cert, now),
        PathTime::UnixMs(ms) => {
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
                .map_err(|e| invalid(format!("the time: {e}")))?
        }
    };
    Ok(match pkix::build_path(&cert, &state.services.cas, at) {
        Ok(_) => PathOutcome::Valid,
        Err(PathError::IssuerNotFound) => PathOutcome::IssuerNotFound,
        Err(e) => PathOutcome::Invalid(e.to_string()),
    })
}

/// The issuer `issuer` names for `cert`.
fn issuer_of(state: &HostState, cert: &Certificate, issuer: &IssuerSel) -> HostResult<Certificate> {
    match issuer {
        IssuerSel::HostCas => state
            .services
            .cas
            .issuers_of(cert)
            .next()
            .cloned()
            .ok_or_else(|| invalid("no CA the core trusts issued the certificate")),
        IssuerSel::Given(der) => parse(der),
        IssuerSel::VerifiesCert(candidates) => {
            for der in candidates {
                let candidate = parse(der)?;
                if cert::verify_signature(cert, &candidate).is_ok() {
                    return Ok(candidate);
                }
            }
            Err(invalid("no certificate given verifies the certificate"))
        }
    }
}

fn status(status: CertStatus) -> CertStatusAbi {
    match status {
        CertStatus::Good => CertStatusAbi::Good,
        CertStatus::Revoked { time, reason } => CertStatusAbi::Revoked {
            at_ms: unix_ms(time),
            reason,
        },
        CertStatus::Unknown => CertStatusAbi::Unknown,
    }
}

/// What a response failing the core's check has wrong.
fn ocsp_problem(e: &OcspError) -> Problem {
    match e {
        OcspError::NoCerts
        | OcspError::ResponderNotFound
        | OcspError::ResponderNotTrusted(_)
        | OcspError::OcspSigningMissing
        | OcspError::NoCheckMissing
        | OcspError::BadSignature(_) => Problem::ResponderUnverified,
        OcspError::ThisUpdate | OcspError::NextUpdate => Problem::OcspStale,
        OcspError::NonceMismatch => Problem::NonceMismatch,
        _ => Problem::Malformed,
    }
}

/// `ocsp_fetch`: an OCSP request about a certificate, the response read and, if asked,
/// checked.
pub(crate) fn ocsp_fetch(state: &HostState, args: OcspArgs) -> HostResult<OcspOutcome> {
    let cert = parse(&args.cert)?;
    let issuer = issuer_of(state, &cert, &args.issuer)?;
    let Some(url) = pki_url(state, &args.url, DEFAULT_OCSP, ocsp::ocsp_url)? else {
        return Ok(OcspOutcome::Failed(no_url(NetStage::Ocsp)));
    };
    let spec = ocsp::RequestSpec {
        cert_id_hash: hash_alg(args.cert_id_hash),
        nonce: nonce(&args.nonce)?,
        method: pki_method(&args.method),
        url: Some(url.clone()),
        timeout: timeout(args.timeout_ms)?,
    };
    let cas = &state.services.cas;
    let now = (state.services.clock)();
    let check = args.check.then_some((cas.as_ref(), now));
    Ok(
        match ocsp::fetch(&cert, &issuer, &spec, &PkiHttp::of(state), check) {
            Ok(fetched) => OcspOutcome::Ok {
                http_status: fetched.http_status,
                response: Bytes::from(fetched.response),
                basic: fetched.basic.map(Bytes::from),
                response_status: fetched.response_status,
                cert_status: fetched.answer.map(|answer| status(answer.status)),
                produced_at_ms: fetched.produced_at.map(unix_ms),
                problem: fetched.problem.as_ref().map(ocsp_problem),
            },
            Err(e) => {
                OcspOutcome::Failed(net_failure(NetStage::Ocsp, &url, e.kind(), e.to_string()))
            }
        },
    )
}

/// `crl_fetch`: the CRLs of a certificate's distribution points and its status in them.
/// Every distribution point must be on a PKI host.
pub(crate) fn crl_fetch(state: &HostState, args: CrlArgs) -> HostResult<CrlOutcome> {
    let cert = parse(&args.cert)?;
    let issuer = issuer_of(state, &cert, &args.issuer)?;
    let timeout = timeout(args.timeout_ms)?;
    let urls = crl::crl_urls(&cert);
    for url in urls.iter().chain(&crl::freshest_urls(&cert)) {
        check_pki_url(state, url)?;
    }
    let address = urls.first().cloned().unwrap_or_default();
    let now = (state.services.clock)();
    Ok(
        match crl::fetch_for(&cert, &issuer, &PkiHttp::of(state), timeout, now) {
            Ok((crls, crl_status)) => CrlOutcome::Ok {
                crls: crls.into_iter().map(Bytes::from).collect(),
                status: match crl_status {
                    crl::CrlStatus::Good => CertStatusAbi::Good,
                    crl::CrlStatus::Revoked { time, reason } => CertStatusAbi::Revoked {
                        at_ms: unix_ms(time),
                        reason,
                    },
                },
            },
            Err(e @ (CrlError::NoUrl | CrlError::Http(_) | CrlError::HttpStatus(_))) => {
                CrlOutcome::Failed(net_failure(
                    NetStage::Crl,
                    &address,
                    e.kind(),
                    e.to_string(),
                ))
            }
            Err(_) => CrlOutcome::Invalid(Problem::CrlInvalid),
        },
    )
}

/// The ABI's check of `check`.
fn check_abi(check: cms::Check) -> Check {
    match check {
        cms::Check::Ok => Check::Ok,
        cms::Check::Skipped => Check::Skipped,
        cms::Check::Fail(problem) => Check::Fail(problem_abi(problem)),
    }
}

fn problem_abi(problem: cms::Problem) -> Problem {
    match problem {
        cms::Problem::Malformed => Problem::Malformed,
        cms::Problem::NoContent => Problem::NoContent,
        cms::Problem::NoSignerCert => Problem::NoSignerCert,
        cms::Problem::BadSignature => Problem::BadSignature,
        cms::Problem::DigestMismatch => Problem::DigestMismatch,
        cms::Problem::EssCertIdMismatch => Problem::EssCertIdMismatch,
        cms::Problem::Expired => Problem::Expired,
        cms::Problem::NotYetValid => Problem::NotYetValid,
        cms::Problem::UnknownCa => Problem::UnknownCa,
        cms::Problem::PathInvalid => Problem::PathInvalid,
        cms::Problem::Revoked { at, reason } => Problem::Revoked {
            at_ms: unix_ms(at),
            reason,
        },
        cms::Problem::StatusUnknown => Problem::StatusUnknown,
        cms::Problem::ResponderUnverified => Problem::ResponderUnverified,
        cms::Problem::OcspStale => Problem::OcspStale,
        cms::Problem::CrlInvalid => Problem::CrlInvalid,
        cms::Problem::TspInvalid => Problem::TspInvalid,
        cms::Problem::TspImprintMismatch => Problem::TspImprintMismatch,
        cms::Problem::Net(failure) => Problem::Net(net_failure(
            match failure.stage {
                cms::NetStage::Ocsp => NetStage::Ocsp,
                cms::NetStage::Crl => NetStage::Crl,
            },
            &failure.url,
            failure.kind,
            failure.detail,
        )),
    }
}

/// `cms_verify`: a report on the signers of a CMS; the revocation sources its certificates
/// name are asked only on the PKI hosts.
pub(crate) fn cms_verify(state: &HostState, args: VerifyArgs) -> HostResult<VerifyReport> {
    let custom = match &args.chain {
        Some(list) if !list.is_empty() => Some(CaSet::new(
            list.iter()
                .map(|der| parse(der))
                .collect::<HostResult<Vec<_>>>()?,
        )),
        _ => None,
    };
    let trust = custom.as_ref().unwrap_or(&state.services.cas);
    let chain = match &args.chain {
        Some(list) if list.is_empty() => cms::ChainPolicy::Skip,
        _ => cms::ChainPolicy::Through(trust),
    };
    let mut require_key_usage = KeyUsageBits::default();
    for bit in &args.require_key_usage {
        match bit {
            KeyUsageBit::DigitalSignature => require_key_usage.digital_signature = true,
            KeyUsageBit::NonRepudiation => require_key_usage.non_repudiation = true,
            KeyUsageBit::KeyEncipherment => require_key_usage.key_encipherment = true,
            KeyUsageBit::KeyAgreement => require_key_usage.key_agreement = true,
        }
    }
    let spec = cms::ReportSpec {
        at: match args.at {
            VerifyAt::Now => cms::VerifyAt::Now,
            VerifyAt::SigningTime => cms::VerifyAt::SigningTime,
            VerifyAt::TspTime => cms::VerifyAt::TspTime,
        },
        chain,
        trust,
        revocation: match args.revocation {
            Revocation::None => cms::Revocation::None,
            Revocation::EmbeddedOcsp => cms::Revocation::EmbeddedOcsp,
            Revocation::LiveOcsp => cms::Revocation::LiveOcsp,
            Revocation::LiveOcspThenCrl => cms::Revocation::LiveOcspThenCrl,
        },
        first_signer_only: args.first_signer_only,
        require_key_usage,
    };
    let now = (state.services.clock)();
    let report = cms::report(
        &args.cms,
        args.data.as_deref().map(Vec::as_slice),
        &spec,
        &PkiHttp::of(state),
        now,
    )
    .map_err(|e| invalid(e.to_string()))?;
    Ok(VerifyReport {
        content: report.content.map(Bytes::from),
        signers: report
            .signers
            .into_iter()
            .map(|signer| SignerReport {
                certificate: signer.certificate.as_ref().map(der_of),
                signing_time_ms: signer.signing_time.map(unix_ms),
                signature: check_abi(signer.signature),
                ess_cert_id: check_abi(signer.ess_cert_id),
                validity: check_abi(signer.validity),
                path: check_abi(signer.path),
                revocation: check_abi(signer.revocation),
                tsp: signer.tsp.map(|tsp| TspReport {
                    gen_time_ms: tsp.gen_time.map(unix_ms),
                    check: check_abi(tsp.check),
                    tsa_cert: tsp.tsa_cert.as_ref().map(der_of),
                }),
            })
            .collect(),
    })
}

/// `xml_verify`: every signature of the document, in document order, each verified with
/// the certificate of its own `KeyInfo`.
pub(crate) fn xml_verify(args: XmlVerifyArgs) -> HostResult<Vec<XmlSigReport>> {
    let checks = xmldsig::verify_each(&args.xml).map_err(|e| invalid(e.to_string()))?;
    Ok(checks
        .into_iter()
        .map(|check| XmlSigReport {
            certificate: check.cert.as_ref().map(der_of).unwrap_or_default(),
            valid: check.result.is_ok(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every CRL the NCA's certificates point to is on a host the core may ask: XAdES-LT
    /// fetches the CRLs of the chain's CAs that name no OCSP responder.
    #[test]
    fn nca_certificates_crl_hosts_are_pki_hosts() {
        let dir = oncl_testkit::fixture("nca/prod");
        let mut urls = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let der = std::fs::read(entry.unwrap().path()).unwrap();
            urls.extend(oncl_pki::crl::crl_urls(&parse(&der).unwrap()));
        }
        assert!(urls.len() >= 6, "{urls:?}");
        for url in &urls {
            check_pki_url_in(&nca_pki_hosts(), url)
                .unwrap_or_else(|e| panic!("{url}: {}", e.message));
        }
    }

    #[test]
    fn the_nca_root_hosts_admit_no_look_alikes() {
        for url in [
            "http://crl.root.gov.kz.evil/x.crl",
            "http://evilroot.gov.kz/x.crl",
            "http://gov.kz/x.crl",
            "file://crl.root.gov.kz/x.crl",
        ] {
            assert!(check_pki_url_in(&nca_pki_hosts(), url).is_err(), "{url}");
        }
    }
}
