//! What the OpenNCALayer plugin ports share, built as the original's plugins built it:
//!
//! - [`http`]: `multipart/form-data` bodies byte for byte;
//! - [`url`]: `new URL(context, spec)` of Java and origins;
//! - [`zip`]: deflated archives;
//! - [`props`]: Java's `Properties.storeToXML`;
//! - [`date`]: `SimpleDateFormat` patterns;
//! - [`reply`]: the replies of the ecc.kz family;
//! - [`md5_hex`].
//!
//! The JSON dialects (org.json, Java's `HashMap` order, the dispatchers) are
//! `oncl_pdk`'s, re-exported from `oncl-protocol`.

pub mod date;
pub mod http;
pub mod props;
pub mod reply;
pub mod url;
pub mod zip;

use md5::{Digest, Md5};

/// The MD5 of `data` as lower-case hex.
pub fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn md5_hex_known() {
        assert_eq!(super::md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(super::md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }
}
