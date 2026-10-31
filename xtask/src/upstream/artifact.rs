//! What a downloaded file is, by its bytes (never by its name), and whether it is what the
//! source should give: an HTML page (an error or captcha page served with status 200) is
//! never a file of the original.

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::http::Downloaded;
use super::sources::Source;

/// A file format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// A ZIP with `META-INF/MANIFEST.MF`.
    Jar,
    /// A ZIP.
    Zip,
    /// An Inno Setup installer.
    InnoExe,
    /// A Go program carrying a gzip stream (the Windows lite installer).
    GoDropper,
    /// Another PE executable.
    Pe,
    /// An OLE compound file (Windows Installer).
    Msi,
    /// A macOS disk image.
    Dmg,
    /// A shell script (possibly with a payload).
    Sh,
    /// A DER `ContentInfo{SignedData}`.
    Der,
    /// An HTML page.
    Html,
    /// Anything else.
    Other,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = serde_json::to_value(self).expect("format serializes");
        f.write_str(name.as_str().unwrap_or("other"))
    }
}

/// How many bytes of the head [`detect_format`] looks at.
pub const HEAD_BYTES: usize = 1 << 20;
/// How many bytes of the tail [`detect_format`] looks at.
pub const TAIL_BYTES: usize = 512;

const PKCS7_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];

/// The format of a file whose first [`HEAD_BYTES`] are `head` and last [`TAIL_BYTES`] are
/// `tail`.
pub fn detect_format(head: &[u8], tail: &[u8]) -> Format {
    if head.starts_with(b"PK\x03\x04") {
        return if contains(head, b"META-INF/MANIFEST.MF") {
            Format::Jar
        } else {
            Format::Zip
        };
    }
    if head.starts_with(b"MZ") {
        return if contains(head, b"Inno Setup Setup Data (") {
            Format::InnoExe
        } else if contains(head, b"go1.") && contains(head, &[0x1f, 0x8b, 0x08]) {
            Format::GoDropper
        } else {
            Format::Pe
        };
    }
    if head.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Format::Msi;
    }
    if tail.len() >= 512 && tail[tail.len() - 512..].starts_with(b"koly") {
        return Format::Dmg;
    }
    if head.starts_with(b"#!") {
        return Format::Sh;
    }
    if head.first() == Some(&0x30)
        && matches!(head.get(1), Some(0x80 | 0x82 | 0x83))
        && contains(&head[..head.len().min(32)], PKCS7_SIGNED_DATA)
    {
        return Format::Der;
    }
    if is_html(head) {
        return Format::Html;
    }
    Format::Other
}

/// Whether `head` starts (after a BOM and white space) like an HTML document.
pub fn is_html(head: &[u8]) -> bool {
    let start = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let start: Vec<u8> = start
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(16)
        .map(u8::to_ascii_lowercase)
        .collect();
    [&b"<!doctype html"[..], b"<html", b"<head", b"<body"]
        .iter()
        .any(|p| start.starts_with(p))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The head and tail of a file, for [`detect_format`].
///
/// # Errors
///
/// I/O errors.
pub fn head_tail(path: &Path) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut head = Vec::new();
    (&mut file).take(HEAD_BYTES as u64).read_to_end(&mut head)?;
    let mut tail = Vec::new();
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL_BYTES as u64)))?;
    file.read_to_end(&mut tail)?;
    Ok((head, tail))
}

/// Whether the file at `path` contains `needle`, read in chunks.
///
/// # Errors
///
/// I/O errors.
pub fn file_contains(path: &Path, needle: &[u8]) -> std::io::Result<bool> {
    let mut file = File::open(path)?;
    let mut buf = vec![0; 1 << 20];
    let mut carry: Vec<u8> = Vec::new();
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(false);
        }
        carry.extend_from_slice(&buf[..n]);
        if contains(&carry, needle) {
            return Ok(true);
        }
        let keep = needle.len().saturating_sub(1).min(carry.len());
        carry.drain(..carry.len() - keep);
    }
}

/// Why a downloaded file is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    /// An HTML page instead of the file.
    UnexpectedHtml,
    /// Another format than the source gives.
    UnexpectedFormat {
        /// What the source gives.
        expected: Format,
        /// What came.
        found: Format,
    },
    /// The SHA-256 differs from the manifest's `hash`.
    HashMismatch {
        /// The manifest's.
        expected: String,
        /// The file's.
        actual: String,
    },
    /// The SHA-1 differs from the one published on the download page.
    Sha1Mismatch {
        /// The page's.
        expected: String,
        /// The file's.
        actual: String,
    },
    /// The file cannot be read.
    Io(String),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactError::UnexpectedHtml => f.write_str("an HTML page instead of the file"),
            ArtifactError::UnexpectedFormat { expected, found } => {
                write!(f, "format {found}, expected {expected}")
            }
            ArtifactError::HashMismatch { expected, actual } => {
                write!(f, "sha256 {actual}, the manifest says {expected}")
            }
            ArtifactError::Sha1Mismatch { expected, actual } => {
                write!(f, "sha1 {actual}, the page says {expected}")
            }
            ArtifactError::Io(e) => write!(f, "read: {e}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

/// Checks a downloaded file against its source: not HTML (by bytes or `Content-Type`), the
/// expected format (a JAR also passes as a ZIP and the reverse), the manifest's SHA-256 and
/// the page's SHA-1. The format found is returned.
///
/// # Errors
///
/// [`ArtifactError`].
pub fn check_artifact(d: &Downloaded, source: &Source) -> Result<Format, ArtifactError> {
    let (head, tail) = head_tail(&d.path).map_err(|e| ArtifactError::Io(e.kind().to_string()))?;
    let mut found = detect_format(&head, &tail);
    // The markers of a large installer may lie past the head.
    if found == Format::Pe {
        let io = |e: std::io::Error| ArtifactError::Io(e.kind().to_string());
        if source.expected_format == Some(Format::InnoExe)
            && file_contains(&d.path, b"Inno Setup Setup Data (").map_err(io)?
        {
            found = Format::InnoExe;
        } else if source.expected_format == Some(Format::GoDropper)
            && file_contains(&d.path, b"go1.").map_err(io)?
            && file_contains(&d.path, &[0x1f, 0x8b, 0x08]).map_err(io)?
        {
            found = Format::GoDropper;
        }
    }
    let html_type = d
        .content_type
        .as_deref()
        .is_some_and(|t| t.trim().to_ascii_lowercase().starts_with("text/html"));
    if found == Format::Html || html_type && source.expected_format != Some(Format::Html) {
        return Err(ArtifactError::UnexpectedHtml);
    }
    if let Some(expected) = source.expected_format {
        let zipish = |f| matches!(f, Format::Jar | Format::Zip);
        if expected != found && !(zipish(expected) && zipish(found)) {
            return Err(ArtifactError::UnexpectedFormat { expected, found });
        }
    }
    if let Some(expected) = &source.expected_sha256
        && !expected.eq_ignore_ascii_case(&d.sha256)
    {
        return Err(ArtifactError::HashMismatch {
            expected: expected.to_ascii_lowercase(),
            actual: d.sha256.clone(),
        });
    }
    if let super::sources::SourceKind::Page {
        published_sha1: Some(expected),
        ..
    } = &source.kind
        && !expected.eq_ignore_ascii_case(&d.sha1)
    {
        return Err(ArtifactError::Sha1Mismatch {
            expected: expected.to_ascii_lowercase(),
            actual: d.sha1.clone(),
        });
    }
    Ok(found)
}
