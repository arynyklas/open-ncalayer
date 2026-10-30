//! The NCA CA certificates the original bundled for its OCSP requests, and the serial
//! numbers among them it would use as issuers: the 2018 RSA and GOST CAs and the 2022 GOST
//! CA, plus the 2022 RSA CA, which the original lacked (its RSA certificates got the 2018
//! CA as issuer and so no answer).

use der::{Decode, Encode};
use x509_cert::Certificate;

/// The certificates, in the original's order: GOST 2015, RSA 2015, GOST 2018, RSA 2018,
/// GOST 2022, RSA 2022.
const CAS: [&[u8]; 6] = [
    include_bytes!("../../../fixtures/nca/prod/ncagost.der"),
    include_bytes!("../../../fixtures/nca/prod/ncarsa.der"),
    include_bytes!("../../../fixtures/nca/prod/ncagost18.der"),
    include_bytes!("../../../fixtures/nca/prod/ncarsa18.der"),
    include_bytes!("../../../fixtures/nca/prod/ncagost22.der"),
    include_bytes!("../../../fixtures/nca/prod/ncarsa22.der"),
];

/// The serial numbers (lower-case hex) of the CAs that may be issuers.
const SERIALS: [&str; 4] = [
    "3576f5b31b5a6821a16fefab1212c94d938dc7ee",
    "46170a97a64bbaf7643c87d90c0fe24071595a8d",
    "7e30be9fc890633f1fff5a3c0cb0c85f4c6d1708",
    // The fix: the NCA RSA 2022 CA.
    "5cae24d749b26480d2de37233c3ea4515db55ac7",
];

/// The issuer of the OCSP `CertID` for the certificate `der`: among the allowed CAs signed
/// with the certificate's signature algorithm, the one named as its issuer, else the
/// first (as the original took it); `None` if there is none.
pub fn issuer_for(der: &[u8]) -> Option<&'static [u8]> {
    let cert = Certificate::from_der(der).ok()?;
    let alg = &cert.signature_algorithm().oid;
    let issuer = cert.tbs_certificate().issuer().to_der().ok()?;
    let candidates: Vec<(&'static [u8], Certificate)> = CAS
        .iter()
        .filter_map(|der| Some((*der, Certificate::from_der(der).ok()?)))
        .filter(|(_, ca)| {
            &ca.signature_algorithm().oid == alg && SERIALS.contains(&serial(ca).as_str())
        })
        .collect();
    candidates
        .iter()
        .find(|(_, ca)| {
            ca.tbs_certificate().subject().to_der().ok().as_deref() == Some(&issuer[..])
        })
        .or_else(|| candidates.first())
        .map(|(der, _)| *der)
}

/// The serial number of `cert`, lower-case hex without leading zero bytes.
fn serial(cert: &Certificate) -> String {
    let bytes = cert.tbs_certificate().serial_number().as_bytes();
    let start = bytes.iter().take_while(|b| **b == 0).count();
    bytes[start..].iter().map(|b| format!("{b:02x}")).collect()
}
