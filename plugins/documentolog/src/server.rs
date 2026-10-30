//! The challenge of Documentolog's server: a random key `sRand` sent RSA-encrypted with the
//! vendor's public key, the fields of the answer AES-encrypted with it.

use aes::Aes128;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use num_bigint::BigUint;
use oncl_pdk::{host, javab64};

/// The public key (modulus, big-endian hex) of Documentolog's server, which the agent
/// encrypts its challenge with; the exponent is 65537. Behaviour data of the vendor's
/// protocol: only its server can read the challenge.
#[cfg_attr(feature = "test-key", allow(dead_code))]
pub const VENDOR_MODULUS: &str = "A357A4474858CA81F11CD484E53995759A8C287E4E405049586787ADCB4C9524A46D3E7B807356211151E77AB40F9E4CD74DB7C49B43BEA3821D2FB6687712CA3D18A53B6B5C4F6AB7DE5ECF963EFF084C7F2D0F49587F7527D82B434CA2493DACCB40A911E6CAA765BF9B70E145D637909985E0606F27271F577FD8F6C2D61DD5DC54ACE90C13124C2B1B0D932E3DC31BE2021D7A0B090FE52A6C34CBA04ADA45D1DE13BFF7B537872D3E3F714733F7311254595DC6491C75C57FC09C0C7E3D03C332EC5BFE389A33C2A77307391A6CFE78DB000901E82F17E6AE719ABDCD673C2357843B301379763E9E39162CE051A6C33E10B6F533B74097837CFD604FBD";

/// The key of the tests' server (feature `test-key`), in the vendor key's place.
#[cfg(feature = "test-key")]
const TEST_MODULUS: &str = "B0C26A67518D55F7CA8215687EB9EAB86E7F29474FAE2057BC6C9C023D8B3B83B18F72E6459CEA713E85EDF4EFB9A72DADE136D6D7861075884099B15B2073840CCF3C2C4A2E4B24F61516CB5C36FEA8256EE664847DAF6EB25BD4944885F06187E3444E4DF37E505F83F76D0E5617D504BD3B1BDCBC41B64247A9DB286966F41BB393AC995D6F697BE99F91A8FD93B89B0EA53A3D4FC2B262DBD2C155DA98CBF28FA45A25EA13606F6953EA51F8F7FFAC4EFA9BC5BEE5A24457522AD472BF2E73E7AB5D82E4C1305F55EC3A16996ECDEDB3761417FE24EF26B3A3280FCB8CDBADCDC48E65F32F811C65D0341D4D74E92964AC9F54E4ABDACB5A1135823BE863";

fn modulus() -> BigUint {
    #[cfg(feature = "test-key")]
    let hex = TEST_MODULUS;
    #[cfg(not(feature = "test-key"))]
    let hex = VENDOR_MODULUS;
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("a hex modulus")
}

/// RSA/ECB/PKCS1Padding of `message` with the server's key: `00 02 <random non-zero> 00
/// <message>` raised to 65537 modulo the key.
fn encrypt(message: &[u8]) -> Option<Vec<u8>> {
    let n = modulus();
    let k = n.bits().div_ceil(8) as usize;
    let padding = k.checked_sub(message.len() + 3).filter(|len| *len >= 8)?;
    let mut ps = Vec::with_capacity(padding);
    while ps.len() < padding {
        let bytes = host::random((padding - ps.len()) as u32 + 16).ok()?;
        ps.extend(
            bytes
                .into_iter()
                .filter(|b| *b != 0)
                .take(padding - ps.len()),
        );
    }
    let mut em = vec![0, 2];
    em.extend(ps);
    em.push(0);
    em.extend_from_slice(message);
    let c = BigUint::from_bytes_be(&em).modpow(&BigUint::from(65_537_u32), &n);
    let c = c.to_bytes_be();
    let mut out = vec![0; k - c.len()];
    out.extend(c);
    Some(out)
}

/// `URLEncoder.encode(text, "UTF-8")` of base64 text.
fn url_encode(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '+' => "%2B".to_owned(),
            '/' => "%2F".to_owned(),
            '=' => "%3D".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

/// A challenge: `sRand` (the first 16 characters of a random UUID) and `code` (the
/// URL-encoded base64 of its encryption).
pub fn challenge() -> Option<(String, String)> {
    let mut bytes = host::random(16).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let uuid = format!("{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16]);
    let s_rand: String = uuid.chars().take(16).collect();
    let code = url_encode(&STANDARD.encode(encrypt(s_rand.as_bytes())?));
    Some((s_rand, code))
}

/// A field of the answer: AES/CBC/PKCS5 with the key `s_rand`, the IV its first 16
/// characters, the ciphertext the base64 of the rest.
pub fn decrypt(s_rand: &str, field: &str) -> Option<String> {
    let at = field.char_indices().nth(16).map(|(i, _)| i)?;
    let (iv, rest) = field.split_at(at);
    let ciphertext = javab64::decode_java(rest).ok()?;
    let plain = cbc::Decryptor::<Aes128>::new_from_slices(s_rand.as_bytes(), iv.as_bytes())
        .ok()?
        .decrypt_padded_vec::<Pkcs7>(&ciphertext)
        .ok()?;
    String::from_utf8(plain).ok()
}

/// `new String(text.getBytes("windows-1251"), "UTF-8")`: what the original does to the
/// storage path of the SP variant, which undoes UTF-8 read as windows-1251.
pub fn redecode_1251(text: &str) -> String {
    const HIGH: [u16; 64] = [
        0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, 0x20AC, 0x2030, 0x0409,
        0x2039, 0x040A, 0x040C, 0x040B, 0x040F, 0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
        0x2013, 0x2014, 0xFFFF, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F, 0x00A0,
        0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7, 0x0401, 0x00A9, 0x0404, 0x00AB,
        0x00AC, 0x00AD, 0x00AE, 0x0407, 0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6,
        0x00B7, 0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457,
    ];
    let bytes: Vec<u8> = text
        .chars()
        .map(|c| {
            let code = u32::from(c);
            if code < 0x80 {
                code as u8
            } else if (0x0410..=0x044F).contains(&code) {
                (code - 0x0410 + 0xC0) as u8
            } else {
                HIGH.iter()
                    .position(|h| u32::from(*h) == code)
                    .map_or(b'?', |i| 0x80 + i as u8)
            }
        })
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
