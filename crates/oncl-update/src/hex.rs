//! Lowercase hex of fixed-size byte arrays: sha256 sums and the install id.

use std::fmt::Write;

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `s` as `N` bytes; `None` unless it is exactly `2 * N` lowercase hex digits.
pub(crate) fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let digits = s.as_bytes();
    if digits.len() != 2 * N {
        return None;
    }
    let nibble = |d: u8| match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'a'..=b'f' => Some(d - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (byte, [hi, lo]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Some(out)
}

/// `#[serde(with = "crate::hex::array")]`: a byte array as a lowercase hex string.
pub(crate) mod array {
    use serde::de::{Error, Unexpected};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        super::decode(&s).ok_or_else(|| {
            D::Error::invalid_value(
                Unexpected::Str(&s),
                &format!("{} lowercase hex digits", 2 * N).as_str(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        assert_eq!(encode(&[0x00, 0xab, 0x7f]), "00ab7f");
        assert_eq!(decode::<3>("00ab7f"), Some([0x00, 0xab, 0x7f]));
        assert_eq!(decode::<3>("00AB7F"), None, "uppercase");
        assert_eq!(decode::<3>("00ab7"), None, "short");
        assert_eq!(decode::<3>("00ab7f00"), None, "long");
        assert_eq!(decode::<1>("0g"), None, "not hex");
        assert_eq!(decode::<1>("+1"), None, "sign");
    }
}
