//! PEM output as NCALayer writes it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Java's `line.separator`, which NCALayer's PEM writer uses.
const NL: &str = if cfg!(windows) { "\r\n" } else { "\n" };

/// `-----BEGIN CMS-----`, base64 in lines of 64 characters, `-----END CMS-----`, each line
/// ended by the platform line separator (`\r\n` on Windows, `\n` elsewhere).
pub fn to_pem(der: &[u8]) -> String {
    const BEGIN: &str = "-----BEGIN CMS-----";
    const END: &str = "-----END CMS-----";
    let body = STANDARD.encode(der);
    let lines = body.len().div_ceil(64);
    let mut pem =
        String::with_capacity(BEGIN.len() + END.len() + body.len() + (lines + 2) * NL.len());
    pem.push_str(BEGIN);
    pem.push_str(NL);
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push_str(NL);
    }
    pem.push_str(END);
    pem.push_str(NL);
    pem
}
