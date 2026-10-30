//! DER for the OpenNCALayer plugin ports, built in the guest with RustCrypto's `der`,
//! `x509-cert` and `cms` (no randomness, no keys: the host signs):
//!
//! - [`attr`]: values of signed attributes and names made from DN strings;
//! - [`cms_read`]: content, signers and certificates of a CMS;
//! - [`esedo`]: the ESEDO signed attributes and OCSP request, by a port's profile;
//! - [`jks`]: the trusted certificates of a Java KeyStore;
//! - [`x509text`]: the certificate texts of Java and Kalkan the original's plugins sent.

pub mod attr;
pub mod cms_read;
pub mod esedo;
pub mod jks;
pub mod x509text;

/// A DER TLV of `tag` around `content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// Lower-case hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
