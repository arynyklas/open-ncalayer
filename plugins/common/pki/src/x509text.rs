//! Names and algorithms as the Java classes of the original's plugins printed them.
//!
//! Each name function takes the DER of a Name (a certificate's subject or issuer).

use crate::hex;
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::Name;

/// The text values of the attributes of type `oid` (dotted) of `name`, in DER order (as
/// BouncyCastle's `X500Name.getRDNs(oid)` gives them); values of no string type are left
/// out.
///
/// # Errors
///
/// `name` is not the DER of a Name.
pub fn attribute_values(name: &[u8], oid: &str) -> Result<Vec<String>, String> {
    Ok(rdns(name)?
        .iter()
        .flatten()
        .filter(|ava| ava.oid.to_string() == oid)
        .filter_map(string_value)
        .collect())
}

/// The text of a value of a string type (UTF8, Printable, IA5, Teletex as Latin-1, BMP,
/// Universal, Numeric, Visible), else `None`.
fn string_value(ava: &AttributeTypeAndValue) -> Option<String> {
    let bytes = ava.value.value();
    match ava.value.tag() {
        Tag::Utf8String
        | Tag::PrintableString
        | Tag::Ia5String
        | Tag::VisibleString
        | Tag::NumericString => String::from_utf8(bytes.to_vec()).ok(),
        Tag::TeletexString => Some(bytes.iter().map(|&b| char::from(b)).collect()),
        Tag::BmpString => char::decode_utf16(
            bytes
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])),
        )
        .collect::<Result<String, _>>()
        .ok(),
        // UniversalString (tag 28), which `der` does not name.
        tag if tag.number().value() == 28 && tag.class() == der::Class::Universal => bytes
            .chunks(4)
            .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            .collect(),
        _ => None,
    }
}

/// `#` and the hex of the value's DER.
fn hex_value(ava: &AttributeTypeAndValue) -> String {
    format!("#{}", hex(&ava.value.to_der().unwrap_or_default()))
}

/// The RDNs of `name`, each its AVAs, in DER order.
fn rdns(name: &[u8]) -> Result<Vec<Vec<AttributeTypeAndValue>>, String> {
    let name = Name::from_der(name).map_err(|e| e.to_string())?;
    Ok(name
        .iter_rdn()
        .map(|rdn| rdn.iter().cloned().collect())
        .collect())
}

/// `X500Principal.getName()` (RFC 2253): the RDNs from the last, joined by `,`; the
/// keywords RFC 2253 names (CN, C, L, ST, O, OU, STREET, DC, UID), any other type as its
/// dotted OID with `#` and the hex of the value's DER; `,+"\<>;` escaped, as are a leading
/// `#` or space and a trailing space.
///
/// # Errors
///
/// `name` is not the DER of a Name.
pub fn rfc2253(name: &[u8]) -> Result<String, String> {
    const KEYWORDS: [(&str, &str); 9] = [
        ("2.5.4.3", "CN"),
        ("2.5.4.6", "C"),
        ("2.5.4.7", "L"),
        ("2.5.4.8", "ST"),
        ("2.5.4.10", "O"),
        ("2.5.4.11", "OU"),
        ("2.5.4.9", "STREET"),
        ("0.9.2342.19200300.100.1.25", "DC"),
        ("0.9.2342.19200300.100.1.1", "UID"),
    ];
    let mut out = Vec::new();
    for rdn in rdns(name)?.iter().rev() {
        let avas: Vec<String> = rdn
            .iter()
            .map(|ava| {
                let oid = ava.oid.to_string();
                match (KEYWORDS.iter().find(|(o, _)| *o == oid), string_value(ava)) {
                    (Some((_, keyword)), Some(text)) => format!("{keyword}={}", escape_2253(&text)),
                    (Some((_, keyword)), None) => format!("{keyword}={}", hex_value(ava)),
                    (None, _) => format!("{oid}={}", hex_value(ava)),
                }
            })
            .collect();
        out.push(avas.join("+"));
    }
    Ok(out.join(","))
}

fn escape_2253(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let edge = (i == 0 && (c == '#' || c == ' ')) || (i + 1 == chars.len() && c == ' ');
        if edge || ",+\"\\<>;".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `X500Principal.toString()`, the same as `X509Certificate.getSubjectDN().toString()` of
/// the default provider (Sun's `X500Name.toString()`): the RDNs from the last, joined by
/// `, `, AVAs by ` + `; Sun's keywords, any other type as `OID.<dotted>`; a value of a string
/// type in double quotes when it holds one of `,+=\n<>#;\"` or starts, ends or doubles
/// white space (`"` and `\` escaped inside), other values `#` and the hex of their DER.
///
/// # Errors
///
/// `name` is not the DER of a Name.
pub fn x500_principal(name: &[u8]) -> Result<String, String> {
    const KEYWORDS: [(&str, &str); 18] = [
        ("2.5.4.3", "CN"),
        ("2.5.4.6", "C"),
        ("2.5.4.7", "L"),
        ("2.5.4.8", "ST"),
        ("2.5.4.10", "O"),
        ("2.5.4.11", "OU"),
        ("2.5.4.12", "T"),
        ("1.3.6.1.4.1.42.2.11.2.1", "IP"),
        ("2.5.4.9", "STREET"),
        ("0.9.2342.19200300.100.1.25", "DC"),
        ("2.5.4.46", "DNQUALIFIER"),
        ("2.5.4.4", "SURNAME"),
        ("2.5.4.42", "GIVENNAME"),
        ("2.5.4.43", "INITIALS"),
        ("2.5.4.44", "GENERATION"),
        ("1.2.840.113549.1.9.1", "EMAILADDRESS"),
        ("0.9.2342.19200300.100.1.1", "UID"),
        ("2.5.4.5", "SERIALNUMBER"),
    ];
    let mut out = Vec::new();
    for rdn in rdns(name)?.iter().rev() {
        let avas: Vec<String> = rdn
            .iter()
            .map(|ava| {
                let oid = ava.oid.to_string();
                let keyword = KEYWORDS
                    .iter()
                    .find(|(o, _)| *o == oid)
                    .map_or_else(|| format!("OID.{oid}"), |(_, k)| (*k).to_owned());
                let value = string_value(ava).map_or_else(|| hex_value(ava), |t| quote_sun(&t));
                format!("{keyword}={value}")
            })
            .collect();
        out.push(avas.join(" + "));
    }
    Ok(out.join(", "))
}

/// Sun's `X500Name.toString()`: see [`x500_principal`].
///
/// # Errors
///
/// `name` is not the DER of a Name.
pub fn sun_x500name(name: &[u8]) -> Result<String, String> {
    x500_principal(name)
}

fn quote_sun(text: &str) -> String {
    const SPECIAL: &str = ",+=\n<>#;\\\"";
    let chars: Vec<char> = text.chars().collect();
    let mut quote = false;
    let mut previous_white = false;
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let white = c == ' ' || c == '\n';
        if (i == 0 && white) || SPECIAL.contains(c) || (white && previous_white) {
            quote = true;
        }
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        previous_white = white;
        out.push(c);
    }
    if previous_white {
        quote = true;
    }
    if quote { format!("\"{out}\"") } else { out }
}

/// The value of the first RDN of type `kind` (as written, case and all) of the DN string
/// `dn` parsed as `javax.naming.ldap.LdapName`, walking `getRdns()`: from the last RDN of
/// the string to the first. The value without its escapes.
pub fn ldap_first(dn: &str, kind: &str) -> Option<String> {
    let mut parts = Vec::new();
    let (mut part, mut escaped) = (String::new(), false);
    for c in dn.chars() {
        if escaped {
            part.push('\\');
            part.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ',' || c == ';' {
            parts.push(std::mem::take(&mut part));
        } else {
            part.push(c);
        }
    }
    parts.push(part);
    parts.iter().rev().find_map(|rdn| {
        rdn.split('+').find_map(|ava| {
            let (t, v) = ava.split_once('=')?;
            (t.trim() == kind).then(|| unescape_ldap(v.trim()))
        })
    })
}

fn unescape_ldap(value: &str) -> String {
    let mut out = String::new();
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// `X509Certificate.getSigAlgName()` of Kalkan for the signature OID `oid`.
pub fn kalkan_sig_alg_name(oid: &str) -> Option<&'static str> {
    match oid {
        "1.2.398.3.10.1.1.1.2" | "1.3.6.1.4.1.6801.1.5.8" => Some("ECGOST34310"),
        "1.2.398.3.10.1.1.2.3.1" => Some("ECGOST3410-2015-256"),
        "1.2.398.3.10.1.1.2.3.2" => Some("ECGOST3410-2015-512"),
        "1.2.840.113549.1.1.11" => Some("SHA256WithRSAEncryption"),
        "1.2.840.113549.1.1.5" => Some("SHA1WithRSAEncryption"),
        _ => None,
    }
}

/// `PublicKey.getAlgorithm()` of Kalkan for the key OID `oid` of a SubjectPublicKeyInfo.
pub fn kalkan_key_alg_name(oid: &str) -> Option<&'static str> {
    match oid {
        "1.2.840.113549.1.1.1" => Some("RSA"),
        "1.2.398.3.10.1.1.1.1" | "1.3.6.1.4.1.6801.1.5.8" => Some("ECGOST34310"),
        "1.2.398.3.10.1.1.2.1" | "1.2.398.3.10.1.1.2.2" => Some("ECGOST3410-2015"),
        _ => None,
    }
}
