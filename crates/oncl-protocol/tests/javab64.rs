//! Java's strict Base64 decoder, Kalkan's lenient one and Java's MIME encoder.

use oncl_protocol::javab64::{decode_java, decode_kalkan, encode_mime};

#[test]
fn java_decodes() {
    assert_eq!(decode_java(""), Ok(vec![]));
    assert_eq!(decode_java("aGVsbG8="), Ok(b"hello".to_vec()));
    assert_eq!(decode_java("aGVsbG8"), Ok(b"hello".to_vec()));
    assert_eq!(decode_java("aGVsbA=="), Ok(b"hell".to_vec()));
    assert_eq!(decode_java("aGVsbA"), Ok(b"hell".to_vec()));
    // Trailing bits are ignored.
    assert_eq!(decode_java("YR=="), Ok(b"a".to_vec()));
}

#[test]
fn java_errors() {
    let err = |s: &str| decode_java(s).unwrap_err();
    assert_eq!(
        err("a"),
        "Input byte[] should at least have 2 bytes for base64 bytes"
    );
    assert_eq!(err("aGVs bG8="), "Illegal base64 character 20");
    assert_eq!(err("aGVsbG8\n"), "Illegal base64 character a");
    assert_eq!(err("aGVsbG-8"), "Illegal base64 character 2d");
    // Latin-1 bytes print as negative Java bytes; other characters become `?`.
    assert_eq!(err("aé"), "Illegal base64 character -17");
    assert_eq!(err("aӘ"), "Illegal base64 character 3f");
    // A supplementary character is one `?` too.
    assert_eq!(
        err("\u{1F600}"),
        "Input byte[] should at least have 2 bytes for base64 bytes"
    );
    assert_eq!(err("a\u{1F600}"), "Illegal base64 character 3f");
    assert_eq!(
        err("aGVsbA="),
        "Input byte array has wrong 4-byte ending unit"
    );
    assert_eq!(
        err("aGVs="),
        "Input byte array has wrong 4-byte ending unit"
    );
    assert_eq!(
        err("=aGVs"),
        "Input byte array has wrong 4-byte ending unit"
    );
    assert_eq!(err("aGVsb"), "Last unit does not have enough valid bits");
    assert_eq!(err("aGVsb="), "Last unit does not have enough valid bits");
    assert_eq!(
        err("aGVsbA==aGVs"),
        "Input byte array has incorrect ending byte at 8"
    );
    assert_eq!(
        err("aGVsbG8=x"),
        "Input byte array has incorrect ending byte at 8"
    );
}

#[test]
fn kalkan_lenient() {
    assert_eq!(decode_kalkan("aGVsbG8="), Ok(b"hello".to_vec()));
    assert_eq!(decode_kalkan("aGVsbA=="), Ok(b"hell".to_vec()));
    assert_eq!(decode_kalkan("aGVs"), Ok(b"hel".to_vec()));
    // Whitespace is skipped, trailing whitespace too.
    assert_eq!(decode_kalkan("aGVs\r\nbG8=\n \t"), Ok(b"hello".to_vec()));
    assert_eq!(decode_kalkan(" aG Vs bG8="), Ok(b"hello".to_vec()));
    // Characters outside the alphabet count as 0; `=` is padding only at the end.
    assert_eq!(decode_kalkan("-GVs"), decode_kalkan("AGVs"));
    assert_eq!(decode_kalkan("a=Vs"), decode_kalkan("aAVs"));
    // No padding: the last four characters are a whole unit.
    assert_eq!(decode_kalkan("aGVsbG8A"), Ok(b"hello\0".to_vec()));
    assert_eq!(
        decode_kalkan("aGV\u{400}"),
        Err("ArrayIndexOutOfBoundsException: 1024".to_owned())
    );
    assert_eq!(
        decode_kalkan("ab"),
        Err("StringIndexOutOfBoundsException: String index out of range: -2".to_owned())
    );
    assert_eq!(
        decode_kalkan(""),
        Err("StringIndexOutOfBoundsException: String index out of range: -4".to_owned())
    );
    assert_eq!(
        decode_kalkan("ab \n"),
        Err("StringIndexOutOfBoundsException: String index out of range: -2".to_owned())
    );
    // Within padding, the character after `=` is not looked up.
    assert_eq!(decode_kalkan("YQ=\u{400}"), Ok(b"a".to_vec()));
}

#[test]
fn mime_encodes_in_lines_of_76() {
    assert_eq!(encode_mime(b""), "");
    assert_eq!(encode_mime(b"hello"), "aGVsbG8=");
    assert_eq!(encode_mime(b"hell"), "aGVsbA==");
    let long = encode_mime(&[0u8; 60]);
    assert_eq!(long, format!("{}\r\n{}", "A".repeat(76), "A".repeat(4)));
    // Exactly one line: no separator after it.
    assert_eq!(encode_mime(&[0u8; 57]), "A".repeat(76));
}
