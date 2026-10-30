//! What every plugin may ask of the core's cryptography: digests ([`hash`]), certificate
//! details as Kalkan renders them ([`cert_details`]) and the CAs the core trusts
//! ([`ca_list`], [`ca_issuer`]).

use super::invalid;
use crate::host::HostState;
use oncl_pdk::abi::{Bytes, CertArgs, CertDetails, HashAlg, HashArgs, HostResult};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::info::{self, cert_info, kcert_types};
use oncl_pki::key::{self, SigAlg};
use oncl_pki::{crl, oid};

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

fn der_of(cert: &Certificate) -> Bytes {
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
