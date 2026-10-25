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
}
