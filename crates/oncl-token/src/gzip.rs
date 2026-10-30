//! Certificates as tokens store them: gzip-compressed, or raw DER.

use crate::error::TokenError;
use crate::{MAX_CERT, MAX_GZ_CERT};
use flate2::read::GzDecoder;
use std::io::Read;

/// The certificate bytes of a token object: the first gzip member when `raw` starts with
/// the gzip magic (bytes after the member, such as a status word, are ignored), else `raw`.
///
/// # Errors
///
/// [`TokenError::Malformed`] for more than [`MAX_GZ_CERT`] input bytes, a broken gzip
/// member, or more than [`MAX_CERT`] decompressed bytes.
pub(crate) fn cert_bytes(raw: &[u8]) -> Result<Vec<u8>, TokenError> {
    if raw.len() > MAX_GZ_CERT {
        return Err(TokenError::Malformed(format!(
            "a stored certificate of {} bytes",
            raw.len()
        )));
    }
    if !raw.starts_with(&[0x1f, 0x8b]) {
        return Ok(raw.to_vec());
    }
    let mut out = Vec::new();
    GzDecoder::new(raw)
        .take(MAX_CERT as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| TokenError::Malformed(format!("compressed certificate: {e}")))?;
    if out.len() > MAX_CERT {
        return Err(TokenError::Malformed(format!(
            "a compressed certificate of more than {MAX_CERT} bytes"
        )));
    }
    Ok(out)
}

/// Gzip of `data`, as tokens store certificates.
#[cfg(any(test, feature = "emulator"))]
pub(crate) fn compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("writes to a Vec");
    enc.finish().expect("writes to a Vec")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_cert_tolerates_trailing_bytes_and_raw() {
        let cert: Vec<u8> = (0..1500u32).map(|i| (i * 7) as u8).collect();
        let mut gz = compress(&cert);
        assert_eq!(cert_bytes(&gz).unwrap(), cert);
        gz.extend([0x90, 0x00]);
        assert_eq!(
            cert_bytes(&gz).unwrap(),
            cert,
            "a status word after the member"
        );
        assert_eq!(cert_bytes(&cert).unwrap(), cert, "raw DER as is");
        assert!(matches!(
            cert_bytes(&[0x1f, 0x8b, 0x08, 0x00]),
            Err(TokenError::Malformed(_))
        ));
        assert!(matches!(
            cert_bytes(&[0u8; MAX_GZ_CERT + 1]),
            Err(TokenError::Malformed(_))
        ));
    }

    #[test]
    fn gzip_bomb_is_cut() {
        let bomb = compress(&vec![0u8; 1 << 20]);
        assert!(bomb.len() <= MAX_GZ_CERT, "{}", bomb.len());
        assert!(matches!(cert_bytes(&bomb), Err(TokenError::Malformed(_))));
        let just = compress(&vec![0u8; MAX_CERT]);
        assert_eq!(cert_bytes(&just).unwrap().len(), MAX_CERT);
    }
}
