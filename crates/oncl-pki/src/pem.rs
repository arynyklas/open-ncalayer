//! PEM output as NCALayer writes it (Kalkan's `PEMWriter`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Java's `line.separator`, which NCALayer's PEM writer uses.
const NL: &str = if cfg!(windows) { "\r\n" } else { "\n" };

/// `-----BEGIN <label>-----`, base64 of `der` in lines of 64 characters,
/// `-----END <label>-----`, each line ended by the platform line separator (`\r\n` on
/// Windows, `\n` elsewhere).
pub fn encode(label: &str, der: &[u8]) -> String {
    const DASHES: &str = "-----";
    let body = STANDARD.encode(der);
    let lines = body.len().div_ceil(64);
    let boundary = DASHES.len() * 2 + label.len();
    let mut pem = String::with_capacity(
        "BEGIN ".len() + "END ".len() + 2 * boundary + body.len() + (lines + 2) * NL.len(),
    );
    for part in [DASHES, "BEGIN ", label, DASHES, NL] {
        pem.push_str(part);
    }
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push_str(NL);
    }
    for part in [DASHES, "END ", label, DASHES, NL] {
        pem.push_str(part);
    }
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let nl = NL;
        assert_eq!(
            encode("CERTIFICATE", &[0xfb, 0xff]),
            format!("-----BEGIN CERTIFICATE-----{nl}+/8={nl}-----END CERTIFICATE-----{nl}")
        );
        let line = "A".repeat(64);
        assert_eq!(
            encode("X", &[0; 96]),
            format!("-----BEGIN X-----{nl}{line}{nl}{line}{nl}-----END X-----{nl}")
        );
        assert_eq!(
            encode("X", &[]),
            format!("-----BEGIN X-----{nl}-----END X-----{nl}")
        );
    }
}
