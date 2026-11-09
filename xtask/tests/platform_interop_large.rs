//! The large rows of the interop matrix stay just below the 1 GiB guarantee of the product
//! and say so truthfully. Deterministic: no tool, no fixture, only the generators at small
//! sizes and the size arithmetic at the real default. The guarantee is read from
//! `oncl-pki` (`ResourceLimits::default().input_bytes`, which is what `oncl sign` refuses
//! documents above), so the harness and the product cannot drift apart again; the exact
//! boundary is the product's own test `the_default_guarantees_one_gibibyte_and_refuses_one_byte_more`.

use oncl_pki::resource::ResourceLimits;
use xtask::platform_interop::Coverage;
use xtask::platform_interop::cases::large::{
    DEFAULT_LARGE_BYTES, guaranteed_bytes, pdf_len, size_label, write_binary, write_pdf, write_xml,
};

const GIB: u64 = 1 << 30;
/// The two PDF shapes of the large rows: 16 300-byte streams and 1 MiB streams.
const PDF_SHAPES: [usize; 2] = [16_300, 1 << 20];
const LARGE_ROWS: [&str; 4] = [
    "large-cms-detached-rsa",
    "large-xml-enveloped-rsa",
    "large-pdf-signature-rsa",
    "large-pdf-signature-rsa-1mib-pages",
];

#[test]
fn the_guarantee_is_the_product_limit() {
    assert_eq!(guaranteed_bytes(), ResourceLimits::default().input_bytes);
    assert_eq!(guaranteed_bytes(), GIB);
}

#[test]
fn the_label_follows_the_size_of_the_artifact() {
    // Just below the guarantee, from 95 % of it to one byte short of it.
    assert_eq!(size_label(1_060_000_000), "just below 1 GiB");
    assert_eq!(size_label(GIB - 1), "just below 1 GiB");
    let edge = (GIB * 95).div_ceil(100);
    // At and above the guarantee the product refuses the document: never a clean claim.
    assert_eq!(size_label(GIB), "1.0GiB, above the guarantee");
    assert_eq!(size_label(1_181_116_006), "1.1GiB, above the guarantee");
    assert_eq!(size_label(edge), "just below 1 GiB");
    assert_eq!(size_label(edge - 1), "0.9GiB");
    // Smaller artifacts keep their size in GiB to one decimal.
    assert_eq!(size_label(134_217_728), "0.1GiB");
    assert_eq!(size_label(GIB / 2), "0.5GiB");
    assert_eq!(size_label(1_048_576), "0.0GiB");
    // 0.9 GiB is not "just below": a smaller artifact cannot keep the claim.
    assert_eq!(size_label(GIB / 10 * 9), "0.9GiB");
}

#[test]
fn the_default_and_every_generator_stay_below_the_product_limit() {
    let limit = ResourceLimits::default().input_bytes;
    assert!(
        DEFAULT_LARGE_BYTES < limit,
        "--large-bytes {DEFAULT_LARGE_BYTES} must be below the guarantee {limit}"
    );
    // The binary and XML generators never exceed the request; the PDF generator overshoots
    // it with small streams (a page costs more than the 200 bytes budgeted) and rounds the
    // page count down with large ones.
    let mut largest = DEFAULT_LARGE_BYTES;
    for stream in PDF_SHAPES {
        let len = pdf_len(DEFAULT_LARGE_BYTES, stream);
        eprintln!(
            "pdf stream {stream}: {len} bytes, {:+} against the request",
            i128::from(len) - i128::from(DEFAULT_LARGE_BYTES)
        );
        // Every one of them is claimed as just below the guarantee, not rounded to a size.
        assert_eq!(size_label(len), "just below 1 GiB", "stream {stream}");
        largest = largest.max(len);
    }
    assert!(
        largest < limit,
        "the largest generated artifact, {largest} bytes, must be below the guarantee {limit}"
    );
    assert_eq!(size_label(DEFAULT_LARGE_BYTES), "just below 1 GiB");
    assert_eq!(size_label(largest), "just below 1 GiB");
}

#[test]
fn the_pdf_length_is_what_the_generator_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("doc.pdf");
    // Small streams reach 5-digit object numbers, large ones several xref offsets digits.
    for (bytes, stream) in [
        (1, 16_300),
        (50_000, 16),
        (400_000, 100),
        (3_000_000, 100),
        (3_000_000, 16_300),
        (5_000_000, 1 << 20),
        (9_999_999, 1 << 20),
    ] {
        let written = write_pdf(&path, bytes, stream).unwrap();
        assert_eq!(written, std::fs::metadata(&path).unwrap().len());
        assert_eq!(
            pdf_len(bytes, stream),
            written,
            "bytes {bytes}, stream {stream}"
        );
    }
}

#[test]
fn the_xml_and_binary_generators_never_exceed_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("doc.xml");
    for bytes in [1_000, 100_000, 5_000_000] {
        let written = write_xml(&path, bytes).unwrap();
        assert_eq!(written, std::fs::metadata(&path).unwrap().len());
        assert!(
            written < bytes && written > bytes - 200,
            "{bytes}: {written}"
        );
    }
    let path = dir.path().join("data.bin");
    write_binary(&path, 300_001).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_001);
}

#[test]
fn the_rows_expect_the_label_their_artifacts_get() {
    let coverage = Coverage::load().unwrap();
    for id in LARGE_ROWS {
        let row = coverage.row(id).unwrap();
        let size = match id {
            "large-pdf-signature-rsa" => pdf_len(DEFAULT_LARGE_BYTES, PDF_SHAPES[0]),
            "large-pdf-signature-rsa-1mib-pages" => pdf_len(DEFAULT_LARGE_BYTES, PDF_SHAPES[1]),
            _ => DEFAULT_LARGE_BYTES,
        };
        let claim = format!("size={} ", size_label(size));
        assert!(
            row.expected.starts_with(&claim),
            "{id}: expected `{}` does not start with `{claim}`",
            row.expected
        );
        assert!(
            row.what.contains("just below the 1 GiB guarantee"),
            "{id}: {}",
            row.what
        );
        assert!(!row.what.contains("1.1 GiB"), "{id}: {}", row.what);
    }
}
