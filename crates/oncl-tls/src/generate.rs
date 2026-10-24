//! The local CA and its server leaf.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, SanType, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime, UtcOffset};
use zeroize::Zeroizing;

use crate::{TlsError, TlsInfo, TlsMaterial, TlsSource};

/// Leaf validity, below the 825-day limit of Apple clients.
const LEAF_VALIDITY_DAYS: i64 = 800;
/// Backdating against clock skew between issuing and the first use.
const BACKDATE: Duration = Duration::hours(1);

/// Issues a fresh local CA and a server leaf for `127.0.0.1`, `::1` and `localhost`.
///
/// `label` (for example `user@host`) and the date of `now` go into the CA common name, so
/// the user can tell this CA apart in a trust store. The CA private key lives only in memory
/// for the duration of this call: its serialized PKCS#8 is zeroized on drop and it is never
/// returned or written; `chain_pem` holds only the leaf.
pub fn generate(now: OffsetDateTime, label: &str) -> Result<TlsMaterial, TlsError> {
    let now = now
        .to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|e| TlsError::Gen(e.to_string()))?;
    let not_before = now - BACKDATE;
    let leaf_not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
    let ca_not_after = leaf_not_after + Duration::days(1);

    let ca_params = ca_params(now, label, not_before, ca_not_after)?;
    let ca_key = Zeroizing::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(gen_err)?);
    let ca_cert = ca_params.self_signed(&*ca_key).map_err(gen_err)?;
    let leaf_key = Zeroizing::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(gen_err)?);
    let leaf_cert = {
        let issuer = Issuer::new(ca_params, &*ca_key);
        leaf_params(not_before, leaf_not_after)?
            .signed_by(&*leaf_key, &issuer)
            .map_err(gen_err)?
    };
    // The CA key is not needed any more: zeroize it now rather than at the end of scope.
    drop(ca_key);

    let ca_der = ca_cert.der().to_vec();
    let info = TlsInfo {
        source: TlsSource::Generated,
        ca_sha1: Some(crate::sha1_hex(&ca_der)),
        ca_sha256: Some(crate::sha256_hex(&ca_der)),
        leaf_sha256: crate::sha256_hex(leaf_cert.der()),
        leaf_not_after: crate::rfc3339(leaf_not_after).map_err(TlsError::Gen)?,
        created_at: crate::rfc3339(now).map_err(TlsError::Gen)?,
        generator: crate::generator(),
    };
    Ok(TlsMaterial {
        chain_pem: leaf_cert.pem(),
        key_pem: Zeroizing::new(leaf_key.serialize_pem()),
        ca_pem: Some(ca_cert.pem()),
        ca_der: Some(ca_der),
        info,
        warnings: Vec::new(),
    })
}

fn ca_params(
    now: OffsetDateTime,
    label: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<CertificateParams, TlsError> {
    let date = now.date();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        format!(
            "OpenNCALayer Local CA ({label} {:04}-{:02}-{:02})",
            date.year(),
            u8::from(date.month()),
            date.day()
        ),
    );
    dn.push(
        DnType::OrganizationName,
        "OpenNCALayer (this computer only)",
    );

    let mut params = CertificateParams::default();
    params.serial_number = Some(random_serial()?);
    params.distinguished_name = dn;
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // rcgen marks nameConstraints critical and omits `excludedSubtrees` when it is empty.
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4(Ipv4Addr::LOCALHOST.octets(), [0xff; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6(Ipv6Addr::LOCALHOST.octets(), [0xff; 16])),
            GeneralSubtree::DnsName("localhost".to_owned()),
        ],
        excluded_subtrees: Vec::new(),
    });
    // The subject key identifier is written for every CA (`IsCa::Ca`).
    Ok(params)
}

fn leaf_params(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<CertificateParams, TlsError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");

    let mut params = CertificateParams::default();
    params.serial_number = Some(random_serial()?);
    params.distinguished_name = dn;
    params.not_before = not_before;
    params.not_after = not_after;
    params.subject_alt_names = vec![
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        SanType::DnsName("localhost".try_into().map_err(gen_err)?),
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // `ExplicitNoCa` writes basicConstraints CA:FALSE and the subject key identifier.
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

/// 16 random bytes; the top bit is cleared and the next one set, so the serial is a positive
/// INTEGER encoded in exactly 16 octets.
fn random_serial() -> Result<SerialNumber, TlsError> {
    let mut serial = [0u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| TlsError::Gen("system random number generator failed".to_owned()))?;
    serial[0] = (serial[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&serial))
}

fn gen_err(e: rcgen::Error) -> TlsError {
    TlsError::Gen(e.to_string())
}
