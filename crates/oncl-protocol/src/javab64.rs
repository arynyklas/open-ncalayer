//! The Base64 codecs the original's modules use, with their errors: Java 8's strict
//! `Base64.getDecoder()` (the basics module's and most plugins'), Kalkan's lenient decoder,
//! and `Base64.getMimeEncoder()`.

/// The standard alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The value of a character of the standard alphabet.
fn value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Java 8's `Base64.getDecoder().decode(String)`, with the messages of its
/// `IllegalArgumentException`: the standard alphabet, no whitespace, padding optional but
/// complete when present, trailing bits ignored. Characters beyond Latin-1 are one `?` each,
/// a supplementary character included (`getBytes(ISO_8859_1)`).
///
/// Canonical text (padded, no trailing bits: what `btoa` writes), which Java decodes to the
/// same bytes, is decoded by the `base64` crate's strict engine; any other text as Java does.
///
/// # Errors
///
/// `Illegal base64 character <hex>`, `Input byte[] should at least have 2 bytes for base64
/// bytes`, `Last unit does not have enough valid bits`, `Input byte array has wrong 4-byte
/// ending unit`, `Input byte array has incorrect ending byte at <n>`.
pub fn decode_java(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(text) {
        Ok(bytes) => Ok(bytes),
        Err(_) => decode_java_units(text),
    }
}

/// [`decode_java`] as Java's decoder walks the text.
fn decode_java_units(text: &str) -> Result<Vec<u8>, String> {
    let src: Vec<u8> = text
        .chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect();
    if src.is_empty() {
        return Ok(Vec::new());
    }
    if src.len() < 2 {
        return Err("Input byte[] should at least have 2 bytes for base64 bytes".to_owned());
    }
    let mut out = Vec::with_capacity(src.len() / 4 * 3 + 2);
    let mut bits: u32 = 0;
    let mut shift: i32 = 18;
    let mut sp = 0;
    while sp < src.len() {
        let b = src[sp];
        sp += 1;
        let Some(v) = value(b) else {
            if b == b'=' {
                // `=` where no padding may be, or a single `=` where two must be.
                let incomplete = shift == 6 && (sp == src.len() || src[sp] != b'=');
                if incomplete || shift == 18 {
                    return Err("Input byte array has wrong 4-byte ending unit".to_owned());
                }
                if shift == 6 {
                    sp += 1;
                }
                break;
            }
            return Err(format!("Illegal base64 character {}", java_byte_hex(b)));
        };
        bits |= u32::from(v) << shift;
        shift -= 6;
        if shift < 0 {
            out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
            shift = 18;
            bits = 0;
        }
    }
    match shift {
        6 => out.push((bits >> 16) as u8),
        0 => out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8]),
        12 => return Err("Last unit does not have enough valid bits".to_owned()),
        _ => {}
    }
    if sp < src.len() {
        return Err(format!(
            "Input byte array has incorrect ending byte at {sp}"
        ));
    }
    Ok(out)
}

/// `Integer.toString(b, 16)` of a Java (signed) byte.
fn java_byte_hex(b: u8) -> String {
    if b < 0x80 {
        format!("{b:x}")
    } else {
        format!("-{:x}", 0x100 - u16::from(b))
    }
}

/// Kalkan's `Base64.decode(String)` (Bouncy Castle's old encoder): whitespace (space, tab,
/// CR, LF) is skipped, except within the last four characters left after trailing
/// whitespace; any other ASCII character outside the alphabet (`=` too) counts as 0; `=`
/// matters only as the third or fourth of those last four.
///
/// # Errors
///
/// What the original throws, as `<simple class name>: <message>` (prefix `java.lang.` for
/// `toString()`): `ArrayIndexOutOfBoundsException: <code>` for a character from U+0080 on
/// (its UTF-16 code unit), `StringIndexOutOfBoundsException: String index out of range: <n>`
/// for fewer than four characters.
pub fn decode_kalkan(text: &str) -> Result<Vec<u8>, String> {
    let data: Vec<u16> = text.encode_utf16().collect();
    let ignore = |c: u16| matches!(c, 0x0a | 0x0d | 0x09 | 0x20);
    let table = |c: u16| -> Result<u8, String> {
        if c >= 0x80 {
            return Err(format!("ArrayIndexOutOfBoundsException: {c}"));
        }
        Ok(value(c as u8).unwrap_or(0))
    };
    let at = |i: isize| -> Result<u16, String> {
        usize::try_from(i)
            .ok()
            .and_then(|i| data.get(i).copied())
            .ok_or_else(|| {
                format!("StringIndexOutOfBoundsException: String index out of range: {i}")
            })
    };
    let mut end = data.len() as isize;
    while end > 0 && ignore(data[end as usize - 1]) {
        end -= 1;
    }
    let finish = end - 4;
    let next_i = |mut i: isize| {
        while i < finish && ignore(data[i as usize]) {
            i += 1;
        }
        i
    };
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let mut i = next_i(0);
    while i < finish {
        let b1 = table(at(i)?)?;
        i = next_i(i + 1);
        let b2 = table(at(i)?)?;
        i = next_i(i + 1);
        let b3 = table(at(i)?)?;
        i = next_i(i + 1);
        let b4 = table(at(i)?)?;
        out.push((b1 << 2) | (b2 >> 4));
        out.push((b2 << 4) | (b3 >> 2));
        out.push((b3 << 6) | b4);
        i = next_i(i + 1);
    }
    let (c1, c2, c3, c4) = (at(end - 4)?, at(end - 3)?, at(end - 2)?, at(end - 1)?);
    let padding = u16::from(b'=');
    if c3 == padding {
        let (b1, b2) = (table(c1)?, table(c2)?);
        out.push((b1 << 2) | (b2 >> 4));
    } else if c4 == padding {
        let (b1, b2, b3) = (table(c1)?, table(c2)?, table(c3)?);
        out.push((b1 << 2) | (b2 >> 4));
        out.push((b2 << 4) | (b3 >> 2));
    } else {
        let (b1, b2, b3, b4) = (table(c1)?, table(c2)?, table(c3)?, table(c4)?);
        out.push((b1 << 2) | (b2 >> 4));
        out.push((b2 << 4) | (b3 >> 2));
        out.push((b3 << 6) | b4);
    }
    Ok(out)
}

/// Java's `Base64.getMimeEncoder().encodeToString(bytes)`: the standard alphabet with
/// padding, lines of 76 characters joined by `\r\n`, none after the last.
pub fn encode_mime(bytes: &[u8]) -> String {
    let mut plain = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for k in 0..4 {
            if k <= n {
                plain.push(char::from(ALPHABET[(v >> (18 - 6 * k)) as usize & 63]));
            } else {
                plain.push('=');
            }
        }
    }
    let mut out = String::with_capacity(plain.len() + plain.len() / 76 * 2);
    for (i, line) in plain.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        // ASCII only.
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    /// Characters at every kind of edge: values with and without the low bits a last unit
    /// drops, both non-letters of the alphabet, padding, whitespace, an illegal ASCII
    /// character, Latin-1 and beyond.
    const EDGES: &[char] = &['A', 'Q', 'g', 'w', '+', '/', '=', ' ', '\n', '!', 'é', '€'];

    fn xorshift(mut state: u64) -> impl FnMut() -> usize {
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state >> 32).unwrap()
        }
    }

    fn same(text: &str) {
        assert_eq!(decode_java(text), decode_java_units(text), "{text:?}");
    }

    #[test]
    fn every_short_text_decodes_as_java_does() {
        let mut texts = vec![String::new()];
        for _ in 0..5 {
            texts = texts
                .iter()
                .flat_map(|t| EDGES.iter().map(move |c| format!("{t}{c}")))
                .collect();
            texts.iter().for_each(|t| same(t));
        }
    }

    #[test]
    fn random_texts_decode_as_java_does() {
        let alphabet: Vec<char> = ALPHABET
            .iter()
            .map(|b| char::from(*b))
            .chain(EDGES.iter().copied())
            .collect();
        let mut next = xorshift(0x2545_f491_4f6c_dd1d);
        for _ in 0..200_000 {
            let len = 6 + next() % 4;
            let text: String = (0..len)
                .map(|_| alphabet[next() % alphabet.len()])
                .collect();
            same(&text);
        }
    }

    #[test]
    fn encodings_and_their_variants_decode_as_java_does() {
        let mut next = xorshift(0x9e37_79b9_7f4a_7c15);
        for _ in 0..20_000 {
            let bytes: Vec<u8> = (0..next() % 64).map(|_| next() as u8).collect();
            let canonical = STANDARD.encode(&bytes);
            assert_eq!(decode_java(&canonical).unwrap(), bytes);
            same(&canonical);
            // Without padding.
            same(canonical.trim_end_matches('='));
            if canonical.is_empty() {
                continue;
            }
            let mut chars: Vec<char> = canonical.chars().collect();
            // Another character anywhere: of the alphabet (trailing bits), padding,
            // whitespace, illegal, beyond ASCII.
            let at = next() % chars.len();
            chars[at] = EDGES[next() % EDGES.len()];
            same(&chars.iter().collect::<String>());
            // One more anywhere.
            let at = next() % (chars.len() + 1);
            chars.insert(at, EDGES[next() % EDGES.len()]);
            same(&chars.iter().collect::<String>());
        }
    }
}
