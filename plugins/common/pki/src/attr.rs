//! Values of signed attributes, and names from the DN strings the original's plugins parsed
//! with Kalkan's (Bouncy Castle's) `X509Name`.

use crate::tlv;
use const_oid::ObjectIdentifier;
use der::Encode;

/// A DER UTF8String of `s`.
pub fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

/// A DER PrintableString of `bytes` as they are: the original's values are not checked
/// against the PrintableString alphabet (`ESEDO\0` keeps its NUL).
pub fn printable(bytes: &[u8]) -> Vec<u8> {
    tlv(0x13, bytes)
}

/// A DER OCTET STRING of `bytes`.
pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// The OID Bouncy Castle's `X509Name` (Kalkan's symbols included) gives `symbol`, any case.
fn symbol_oid(symbol: &str) -> Option<&'static str> {
    const SYMBOLS: [(&str, &str); 37] = [
        ("C", "2.5.4.6"),
        ("O", "2.5.4.10"),
        ("T", "2.5.4.12"),
        ("OU", "2.5.4.11"),
        ("CN", "2.5.4.3"),
        ("L", "2.5.4.7"),
        ("ST", "2.5.4.8"),
        ("S", "2.5.4.8"),
        ("SERIALNUMBER", "2.5.4.5"),
        ("SN", "2.5.4.5"),
        ("E", "1.2.840.113549.1.9.1"),
        ("EMAILADDRESS", "1.2.840.113549.1.9.1"),
        ("DC", "0.9.2342.19200300.100.1.25"),
        ("UID", "0.9.2342.19200300.100.1.1"),
        ("STREET", "2.5.4.9"),
        ("SURNAME", "2.5.4.4"),
        ("GIVENNAME", "2.5.4.42"),
        ("G", "2.5.4.42"),
        ("INITIALS", "2.5.4.43"),
        ("GENERATION", "2.5.4.44"),
        ("UNSTRUCTUREDADDRESS", "1.2.840.113549.1.9.8"),
        ("UNSTRUCTUREDNAME", "1.2.840.113549.1.9.2"),
        ("UNIQUEIDENTIFIER", "2.5.4.45"),
        ("DN", "2.5.4.46"),
        ("PSEUDONYM", "2.5.4.65"),
        ("POSTALADDRESS", "2.5.4.16"),
        ("NAMEATBIRTH", "1.3.36.8.3.14"),
        ("COUNTRYOFCITIZENSHIP", "1.3.6.1.5.5.7.9.4"),
        ("COUNTRYOFRESIDENCE", "1.3.6.1.5.5.7.9.5"),
        ("GENDER", "1.3.6.1.5.5.7.9.3"),
        ("PLACEOFBIRTH", "1.3.6.1.5.5.7.9.2"),
        ("DATEOFBIRTH", "1.3.6.1.5.5.7.9.1"),
        ("POSTALCODE", "2.5.4.17"),
        ("BUSINESSCATEGORY", "2.5.4.15"),
        ("TELEPHONENUMBER", "2.5.4.20"),
        ("NAME", "2.5.4.41"),
        ("DNQUALIFIER", "2.5.4.46"),
    ];
    let upper = symbol.to_ascii_uppercase();
    SYMBOLS
        .iter()
        .find(|(s, _)| *s == upper)
        .map(|(_, oid)| *oid)
}

/// The DER of a string value as Bouncy Castle's `X509DefaultEntryConverter` encodes it:
/// IA5String for e-mail and DC, GeneralizedTime text for the date of birth, PrintableString
/// for C, SERIALNUMBER, DN qualifier and telephone number, UTF8String otherwise.
fn entry_value(oid: &str, value: &str) -> Vec<u8> {
    match oid {
        "1.2.840.113549.1.9.1" | "0.9.2342.19200300.100.1.25" => tlv(0x16, value.as_bytes()),
        "1.3.6.1.5.5.7.9.1" => tlv(0x18, value.as_bytes()),
        "2.5.4.6" | "2.5.4.5" | "2.5.4.46" | "2.5.4.20" => tlv(0x13, value.as_bytes()),
        _ => utf8(value),
    }
}

/// The DER of `X509Name(dn).getEncoded()` of Kalkan (Bouncy Castle): the RDNs in the order
/// of the string, multi-valued ones (`+`) as DER SETs, attribute types by symbol (any case,
/// Kalkan's `S` and `G` included) or dotted OID (an `OID.` prefix allowed), a `#hex` value
/// as the DER it names, any other through `X509DefaultEntryConverter`. `\` escapes and
/// quoted values as `X509NameTokenizer` reads them.
///
/// # Errors
///
/// An unknown symbol, a malformed OID or hex value, a part without `=`.
pub fn x509_name_from_kalkan_dn(dn: &str) -> Result<Vec<u8>, String> {
    let mut rdns = Vec::new();
    for rdn in split_unescaped(dn, ',') {
        let mut avas = Vec::new();
        for ava in split_unescaped(&rdn, '+') {
            let (kind, value) = ava
                .split_once('=')
                .ok_or_else(|| format!("badly formatted directory string: {ava}"))?;
            let kind = kind.trim();
            let dotted = kind
                .strip_prefix("OID.")
                .or_else(|| kind.strip_prefix("oid."));
            let oid = match dotted.or_else(|| {
                kind.chars()
                    .next()
                    .filter(char::is_ascii_digit)
                    .map(|_| kind)
            }) {
                Some(dotted) => dotted.to_owned(),
                None => symbol_oid(kind)
                    .ok_or_else(|| {
                        format!("Unknown object id - {kind} - passed to distinguished name")
                    })?
                    .to_owned(),
            };
            let parsed = ObjectIdentifier::new(&oid).map_err(|e| format!("{oid}: {e}"))?;
            let value = unescape(value);
            let encoded = match value.strip_prefix('#') {
                Some(hex) if !value.starts_with("\\#") => from_hex(hex)?,
                _ => entry_value(&oid, &value),
            };
            let mut ava = parsed.to_der().map_err(|e| e.to_string())?;
            ava.extend_from_slice(&encoded);
            avas.push(tlv(0x30, &ava));
        }
        // A DER SET: its elements sorted by their encodings.
        avas.sort();
        rdns.push(tlv(0x31, &avas.concat()));
    }
    Ok(tlv(0x30, &rdns.concat()))
}

/// The DER of the name of an RFC 2253 string (`X500Principal.getName()`) as Kalkan's
/// `X509Name(String)` parses it: in the order of the string, which is the reverse of the
/// certificate's, so the name comes out reversed; `OID=#hex` values keep their DER.
///
/// # Errors
///
/// As [`x509_name_from_kalkan_dn`].
pub fn x509_name_from_rfc2253(dn: &str) -> Result<Vec<u8>, String> {
    x509_name_from_kalkan_dn(dn)
}

/// `s` split at each `sep` not escaped by `\` nor inside double quotes, each part trimmed.
fn split_unescaped(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let (mut escaped, mut quoted) = (false, false);
    for c in s.chars() {
        if escaped {
            part.push(c);
            escaped = false;
        } else if c == '\\' {
            part.push(c);
            escaped = true;
        } else if c == '"' {
            part.push(c);
            quoted = !quoted;
        } else if c == sep && !quoted {
            parts.push(part.trim().to_owned());
            part.clear();
        } else {
            part.push(c);
        }
    }
    if !part.trim().is_empty() || !parts.is_empty() {
        parts.push(part.trim().to_owned());
    }
    parts
}

/// A value without its escapes and quotes; a leading `\#` stays (a literal `#`).
fn unescape(value: &str) -> String {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("\\#") {
        return format!("\\#{}", unescape(rest));
    }
    let mut out = String::new();
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c != '"' {
            out.push(c);
        }
    }
    out
}

fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("bad hex value: {hex}"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("bad hex value: {hex}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_encodings() {
        assert_eq!(utf8("Ә"), [0x0c, 0x02, 0xd3, 0x98]);
        assert_eq!(
            printable(b"ESEDO\0"),
            [0x13, 6, b'E', b'S', b'E', b'D', b'O', 0]
        );
        assert_eq!(octets(&[1, 2]), [0x04, 2, 1, 2]);
        assert_eq!(octets(&[0; 200])[..3], [0x04, 0x81, 200]);
    }

    #[test]
    fn names_from_strings() {
        // SERIALNUMBER and C as PrintableString, the rest UTF8String, in string order.
        let der = x509_name_from_kalkan_dn("CN=Ә,SERIALNUMBER=IIN1,C=KZ").unwrap();
        let mut expected = Vec::new();
        for (oid, value) in [
            ([0x55, 4, 3], utf8("Ә")),
            ([0x55, 4, 5], printable(b"IIN1")),
            ([0x55, 4, 6], printable(b"KZ")),
        ] {
            let mut ava = tlv(0x06, &oid);
            ava.extend_from_slice(&value);
            expected.extend_from_slice(&tlv(0x31, &tlv(0x30, &ava)));
        }
        assert_eq!(der, tlv(0x30, &expected));
        // Escapes, `#hex` and dotted OIDs.
        let hex = x509_name_from_rfc2253("2.5.4.5=#130449494e31,CN=a\\,b").unwrap();
        assert!(
            hex.windows(6)
                .any(|w| w == [0x13, 4, b'I', b'I', b'N', b'1'])
        );
        assert!(hex.windows(5).any(|w| w == [0x0c, 3, b'a', b',', b'b']));
        assert!(x509_name_from_kalkan_dn("XX=1").is_err());
    }
}
