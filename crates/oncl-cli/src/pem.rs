//! Explicit PEM intake of a CMS (`verify --profile cms --pem`).
//!
//! The text is read through the bounded intake first (at most [`MAX_PEM_BYTES`]); it must be
//! exactly one `CMS` or `PKCS7` block, nothing before or after it, with a strict base64 body.
//! The decoded DER then goes to the same verifier as any other CMS input.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oncl_pki::resource::ProcessingError;

/// The largest PEM text accepted: its decoded CMS is below 12 MiB.
pub const MAX_PEM_BYTES: usize = 16 << 20;

const LABELS: [&str; 2] = ["CMS", "PKCS7"];

/// The DER inside the single PEM block of `text`.
pub fn decode_cms(text: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    let bad = |why| ProcessingError::InvalidInput(why);
    let text = std::str::from_utf8(text).map_err(|_| bad("PEM is not text"))?;
    let text = text.trim();
    let label = LABELS
        .into_iter()
        .find(|label| text.starts_with(&format!("-----BEGIN {label}-----")))
        .ok_or_else(|| bad("PEM must be one CMS or PKCS7 block"))?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text[begin.len()..]
        .strip_suffix(end.as_str())
        .ok_or_else(|| bad("PEM has text after the block or no end line"))?;
    if body.contains("-----") {
        return Err(bad("PEM must be exactly one block"));
    }
    let compact: String = body.split_ascii_whitespace().collect();
    if compact.is_empty() {
        return Err(bad("PEM block is empty"));
    }
    STANDARD
        .decode(compact)
        .map_err(|_| bad("PEM body is not base64"))
}
