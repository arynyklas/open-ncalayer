//! CA certificates of the NCA production PKI, embedded as the original's `cacerts.jks`
//! carries them. They are the default trust set; the NCA test PKI is not embedded.

use crate::cert::{self, Certificate};
use std::sync::LazyLock;

/// DER of the embedded certificates with their `cacerts.jks` aliases, in alias order.
const EMBEDDED: [(&str, &[u8]); 10] = [
    (
        "rcagost",
        include_bytes!("../../../fixtures/nca/prod/rcagost.der"),
    ),
    (
        "ncagost",
        include_bytes!("../../../fixtures/nca/prod/ncagost.der"),
    ),
    (
        "ncagost18",
        include_bytes!("../../../fixtures/nca/prod/ncagost18.der"),
    ),
    (
        "rcagost22",
        include_bytes!("../../../fixtures/nca/prod/rcagost22.der"),
    ),
    (
        "ncagost22",
        include_bytes!("../../../fixtures/nca/prod/ncagost22.der"),
    ),
    (
        "rcarsa",
        include_bytes!("../../../fixtures/nca/prod/rcarsa.der"),
    ),
    (
        "rcarsa20",
        include_bytes!("../../../fixtures/nca/prod/rcarsa20.der"),
    ),
    (
        "ncarsa",
        include_bytes!("../../../fixtures/nca/prod/ncarsa.der"),
    ),
    (
        "ncarsa18",
        include_bytes!("../../../fixtures/nca/prod/ncarsa18.der"),
    ),
    (
        "ncarsa22",
        include_bytes!("../../../fixtures/nca/prod/ncarsa22.der"),
    ),
];

static NCA_PRODUCTION: LazyLock<Vec<Certificate>> = LazyLock::new(|| {
    EMBEDDED
        .iter()
        .map(|(alias, der)| {
            cert::parse(der).unwrap_or_else(|e| panic!("embedded certificate {alias}: {e}"))
        })
        .collect()
});

/// The 10 CA certificates of the NCA production PKI (root and issuing CAs, GOST and RSA,
/// generations 2015–2022) in the alias order of the original's `cacerts.jks`: `rcagost`,
/// `ncagost`, `ncagost18`, `rcagost22`, `ncagost22`, `rcarsa`, `rcarsa20`, `ncarsa`,
/// `ncarsa18`, `ncarsa22`.
pub fn nca_production() -> &'static [Certificate] {
    &NCA_PRODUCTION
}

/// The RSA CAs of the NCA (`rcarsa20`, `ncarsa22`) with the SHA-256 of their DER, which
/// [`nca_tls_roots`] checks: the CAs of the TLS certificates of government sites. (Browsers
/// do not use the GOST CAs.)
const TLS_ROOTS: [(&str, &str); 2] = [
    (
        "rcarsa20",
        "9ba06354b626641715182e4d07c9dbaa1777720fa795d03174ffc68876535dcd",
    ),
    (
        "ncarsa22",
        "84fb799a66140950818c056a5d9730acc2a7622cdd4ef0d47113b132fb892905",
    ),
];

/// `(alias, DER)` of the NCA's RSA CAs `rcarsa20` and `ncarsa22`, for a browser's trust
/// store, each checked against its SHA-256 pinned here.
///
/// # Errors
///
/// An embedded certificate is missing or does not match its pinned SHA-256 (a broken
/// build): the message names it.
pub fn nca_tls_roots() -> Result<Vec<(&'static str, &'static [u8])>, String> {
    pinned(&TLS_ROOTS)
}

/// The embedded certificates of `pins`, each checked against its SHA-256.
fn pinned(pins: &[(&'static str, &str)]) -> Result<Vec<(&'static str, &'static [u8])>, String> {
    use sha2::{Digest, Sha256};
    pins.iter()
        .map(|&(alias, sha256)| {
            let (_, der) = EMBEDDED
                .iter()
                .find(|(a, _)| *a == alias)
                .ok_or_else(|| format!("the certificate {alias} is not embedded"))?;
            let digest = Sha256::digest(der);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            if hex != sha256 {
                return Err(format!(
                    "the embedded certificate {alias} has SHA-256 {hex}, not {sha256}"
                ));
            }
            Ok((alias, *der))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn embedded_roots_match_sha256sums() {
        let sums = include_str!("../../../fixtures/nca/SHA256SUMS");
        let prod: Vec<(&str, &str)> = sums
            .lines()
            .filter_map(|line| line.split_once("  "))
            .filter_map(|(sum, path)| {
                Some((path.strip_prefix("prod/")?.strip_suffix(".der")?, sum))
            })
            .collect();
        assert_eq!(prod.len(), 10);

        let aliases: Vec<&str> = EMBEDDED.iter().map(|(alias, _)| *alias).collect();
        assert_eq!(
            aliases,
            [
                "rcagost",
                "ncagost",
                "ncagost18",
                "rcagost22",
                "ncagost22",
                "rcarsa",
                "rcarsa20",
                "ncarsa",
                "ncarsa18",
                "ncarsa22",
            ]
        );
        for (alias, der) in EMBEDDED {
            let sum = prod
                .iter()
                .find(|(name, _)| *name == alias)
                .map(|(_, s)| *s);
            assert_eq!(Some(hex(&Sha256::digest(der)).as_str()), sum, "{alias}");
        }

        let certs = nca_production();
        assert_eq!(certs.len(), 10);
        for (cert, (alias, der)) in certs.iter().zip(EMBEDDED) {
            assert_eq!(cert.to_der().unwrap(), der, "{alias} is DER");
        }
    }

    #[test]
    fn tls_roots_are_the_pinned_rsa_cas() {
        let roots = nca_tls_roots().unwrap();
        assert_eq!(
            roots.iter().map(|(alias, _)| *alias).collect::<Vec<_>>(),
            ["rcarsa20", "ncarsa22"]
        );
        for (alias, der) in roots {
            assert!(EMBEDDED.contains(&(alias, der)), "{alias}");
        }
        // A wrong pin or an unknown alias is an error, never a panic.
        let wrong = pinned(&[("rcarsa20", "00")]).unwrap_err();
        assert!(
            wrong.contains("rcarsa20") && wrong.contains("not 00"),
            "{wrong}"
        );
        assert!(
            pinned(&[("nope", "00")])
                .unwrap_err()
                .contains("not embedded")
        );
    }
}
