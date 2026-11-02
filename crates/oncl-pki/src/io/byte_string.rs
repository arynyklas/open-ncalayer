//! PDF byte-string primitives, independent of the document/object parser.
use crate::resource::ProcessingError;

/// Append one hex or escaped-literal PDF string and return its encoded extent.
/// Callers admit output capacity (at most input.len()) before calling. This
/// primitive creates no provenance capability and uses no auxiliary heap buffer.
pub fn decode_pdf_byte_string(
    input: &[u8],
    output: &mut Vec<u8>,
) -> Result<usize, ProcessingError> {
    let invalid = || ProcessingError::InvalidInput("PDF byte string");
    let mut at = 1usize;
    match input.first() {
        Some(b'<') if input.get(1) != Some(&b'<') => {
            let mut high = None;
            loop {
                let byte = *input.get(at).ok_or_else(invalid)?;
                at += 1;
                if byte == b'>' {
                    break;
                }
                if matches!(byte, 0 | 9 | 10 | 12 | 13 | 32) {
                    continue;
                }
                let digit = match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => return Err(invalid()),
                };
                if let Some(first) = high.take() {
                    output.push(first * 16 + digit);
                } else {
                    high = Some(digit);
                }
            }
            if let Some(first) = high {
                output.push(first * 16);
            }
        }
        Some(b'(') => {
            let mut depth = 1usize;
            while depth != 0 {
                let byte = *input.get(at).ok_or_else(invalid)?;
                at += 1;
                match byte {
                    b'\\' => {
                        let byte = *input.get(at).ok_or_else(invalid)?;
                        at += 1;
                        match byte {
                            b'n' => output.push(b'\n'),
                            b'r' => output.push(b'\r'),
                            b't' => output.push(b'\t'),
                            b'b' => output.push(8),
                            b'f' => output.push(12),
                            b'\n' => {}
                            b'\r' => {
                                if input.get(at) == Some(&b'\n') {
                                    at += 1;
                                }
                            }
                            b'0'..=b'7' => {
                                let mut value = u16::from(byte - b'0');
                                for _ in 0..2 {
                                    if let Some(digit @ b'0'..=b'7') = input.get(at) {
                                        value = value * 8 + u16::from(*digit - b'0');
                                        at += 1;
                                    } else {
                                        break;
                                    }
                                }
                                output.push(value as u8);
                            }
                            _ => output.push(byte),
                        }
                    }
                    b'(' => {
                        depth = depth.checked_add(1).ok_or_else(invalid)?;
                        output.push(byte);
                    }
                    b')' => {
                        depth -= 1;
                        if depth != 0 {
                            output.push(byte);
                        }
                    }
                    b'\r' => {
                        if input.get(at) == Some(&b'\n') {
                            at += 1;
                        }
                        output.push(b'\n');
                    }
                    _ => output.push(byte),
                }
            }
        }
        _ => return Err(invalid()),
    }
    Ok(at)
}

/// Borrow a canonical DER SEQUENCE followed only by zero container padding.
/// This checks framing, not ASN.1 semantics or cryptographic validity.
pub fn padded_der_sequence(bytes: &[u8]) -> Result<&[u8], ProcessingError> {
    let invalid = || ProcessingError::InvalidInput("noncanonical padded DER sequence");
    if bytes.first() != Some(&0x30) {
        return Err(invalid());
    }
    let first = *bytes.get(1).ok_or_else(invalid)?;
    let (header, length) = if first < 128 {
        (2usize, usize::from(first))
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > 8 || bytes.get(2) == Some(&0) {
            return Err(invalid());
        }
        let mut length = 0usize;
        for byte in bytes.get(2..2 + count).ok_or_else(invalid)? {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or_else(invalid)?;
        }
        if length < 128 {
            return Err(invalid());
        }
        (2 + count, length)
    };
    let end = header.checked_add(length).ok_or_else(invalid)?;
    let sequence = bytes.get(..end).ok_or_else(invalid)?;
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    Ok(sequence)
}
