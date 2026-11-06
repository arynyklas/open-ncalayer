//! Dense documents: the cross-reference model scales with a declared, charged budget
//! (`PdfLimits::max_xref_entries`, 16 bytes a row against the operation's memory), not
//! with the object-graph ceiling `max_objects`. Real documents of many pages/objects
//! sign; a hostile or lying table is refused before any key use, quickly.
use oncl_pdf::{PdfDocument, PdfError, PdfLimits, PdfSignProfile, budget, sign_source};
use oncl_pki::{
    cms,
    cms::stream::CmsSignServices,
    io::{Source, TemporaryStore},
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{io::Cursor, sync::Arc, time::Instant};
#[path = "support/dense_gen.rs"]
mod dense_gen;
use dense_gen::{Dense, classic, classic_with_table, streamed, xref_stream_with, zlib};

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope_with(limits: ResourceLimits) -> ResourceScope {
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
fn scope() -> ResourceScope {
    scope_with(ResourceLimits::default())
}
fn open(bytes: &[u8], limits: &PdfLimits) -> Result<usize, PdfError> {
    let mut scope = scope();
    let mut cursor = Cursor::new(bytes);
    PdfDocument::open(Source::seekable(&mut cursor, None), limits, &mut scope)
        .map(|d| d.revision_count())
}
fn sign(input: &[u8], limits: &PdfLimits) -> Result<Vec<u8>, PdfError> {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope();
    let file = oncl_testkit::synthetic("user-rsa-sign");
    let mut key = oncl_pki::pkcs12::load(&oncl_testkit::read(file.path), &file.password)
        .unwrap()
        .remove(0);
    let mut output = store.stage(&mut scope).unwrap();
    let mut profile = PdfSignProfile::new(16384).unwrap();
    profile.limits = limits.clone();
    sign_source(
        Source::seekable(&mut Cursor::new(input), None),
        &profile,
        &mut key,
        &CmsSignServices::new(None, Some(&store)),
        &mut output,
        &scope,
    )?;
    let mut result = Vec::new();
    output.copy_to(&mut result).unwrap();
    Ok(result)
}
/// The CMS of the last signature verifies over exactly the ByteRange bytes.
fn assert_signature_verifies(output: &[u8], original: &[u8]) {
    assert!(output.starts_with(original), "incremental update");
    let text = String::from_utf8_lossy(&output[original.len()..]);
    let p = text.rfind("/ByteRange [").unwrap() + 12;
    let end = text[p..].find(']').unwrap() + p;
    let r: Vec<usize> = text[p..end]
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(r[0], 0);
    assert_eq!(r[2] + r[3], output.len());
    let padded: Vec<u8> = output[r[1] + 1..r[2] - 1]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let der = oncl_pki::io::padded_der_sequence(&padded).unwrap();
    let mut data = output[..r[1]].to_vec();
    data.extend_from_slice(&output[r[2]..]);
    assert_eq!(cms::verify(der, Some(&data)).unwrap().len(), 1);
    data[10] ^= 1;
    assert!(cms::verify(der, Some(&data)).is_err());
}
fn dense_documents() -> Vec<(&'static str, Dense)> {
    vec![
        ("classic x3", classic(20_000, 3)),
        ("stream+predictor x3", streamed(20_000, 3, true)),
        ("stream, no predictor", streamed(20_000, 1, false)),
    ]
}

/// The D4/D6 defect: a document of many objects/pages is not "too many objects".
#[test]
fn dense_documents_far_past_max_objects_sign_and_verify() {
    let limits = PdfLimits::default();
    for (name, doc) in dense_documents() {
        assert!(
            doc.pages * 2 > limits.max_objects * 4,
            "{name}: the document must dwarf max_objects"
        );
        let revisions = doc.bytes.windows(9).filter(|w| *w == b"startxref").count();
        let output = sign(&doc.bytes, &limits).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_signature_verifies(&output, &doc.bytes);
        assert_eq!(open(&output, &limits).unwrap(), revisions + 1, "{name}");
    }
}

/// `max_xref_entries` is exact: the document's own entry count passes, one fewer is
/// refused. The count is over all revisions.
#[test]
fn xref_entry_budget_is_exact_over_all_revisions() {
    for (name, doc) in dense_documents() {
        let limits = |n: u64| PdfLimits {
            max_xref_entries: n as usize,
            ..PdfLimits::default()
        };
        open(&doc.bytes, &limits(doc.entries)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(
            matches!(
                open(&doc.bytes, &limits(doc.entries - 1)),
                Err(PdfError::Limit("xref entries"))
            ),
            "{name}: limit+1 must be refused"
        );
        // Signing adds revisions of its own; the SDK refuses before any key use.
        assert!(
            sign(&doc.bytes, &limits(doc.entries - 1)).is_err(),
            "{name}"
        );
    }
}

/// Each row is charged to the operation's memory as it is read: an operation that
/// cannot hold the rows is refused (MemoryLimit), one that can holds them, and the
/// host-side estimate (`budget::xref_memory`) is never below the real charge.
#[test]
fn xref_rows_are_charged_honestly_to_the_operation_memory() {
    let doc = classic(200_000, 1);
    let limits = PdfLimits::default();
    let (metadata, memory) = budget::reader(&limits).unwrap();
    let fixed = metadata + memory;
    let with_memory = |memory_bytes: u64| ResourceLimits {
        memory_bytes,
        ..ResourceLimits::default()
    };
    let attempt = |memory_bytes: u64| {
        let mut scope = scope_with(with_memory(memory_bytes));
        let mut cursor = Cursor::new(&doc.bytes);
        PdfDocument::open(Source::seekable(&mut cursor, None), &limits, &mut scope).map(|_| ())
    };
    // The rows are 16 bytes each: half of them cannot fit.
    let half = fixed + doc.entries / 2 * 16;
    assert!(
        matches!(
            attempt(half),
            Err(PdfError::Processing(ProcessingError::MemoryLimit))
        ),
        "rows beyond the memory budget must be refused"
    );
    attempt(fixed + budget::xref_memory(&limits, doc.entries).unwrap()).unwrap();
}

/// Hostile tables: huge declared counts and lies are refused quickly and cheaply.
#[test]
fn hostile_xref_tables_are_refused_quickly() {
    let limits = PdfLimits::default();
    let started = Instant::now();
    // Declared count far past the budget.
    let huge = classic_with_table("0 4000000000\n0000000000 65535 f \n");
    assert!(matches!(
        open(&huge, &limits),
        Err(PdfError::Limit("xref entries"))
    ));
    // Count within the budget but nothing like it in the file: a lie.
    let lying = classic_with_table("0 4000000\n0000000000 65535 f \n");
    assert!(matches!(
        open(&lying, &limits),
        Err(PdfError::Malformed("xref section beyond the source"))
    ));
    // Many one-entry subsections, each honest, past the budget by one.
    let small = PdfLimits {
        max_xref_entries: 1000,
        ..PdfLimits::default()
    };
    let mut table = String::new();
    for n in 0..1001 {
        table.push_str(&format!("{} 1\n{:010} 00000 n \n", n * 2, 9));
    }
    let many = classic_with_table(&table);
    assert!(matches!(
        open(&many, &small),
        Err(PdfError::Limit("xref entries"))
    ));
    // Two subsections claiming the same object numbers.
    let overlap = classic_with_table(
        "0 2\n0000000000 65535 f \n0000000009 00000 n \n1 1\n0000000009 00000 n \n",
    );
    assert!(open(&overlap, &limits).is_err());
    // A cross-reference stream whose /Index declares millions of rows over a few bytes.
    let stream = xref_stream_with(
        "/Size 5000000 /W [1 4 2] /Index [0 4000000] /Filter /FlateDecode",
        &zlib(&[0u8; 14]),
    );
    assert!(matches!(
        open(&stream, &limits),
        Err(PdfError::Malformed("truncated xref stream"))
    ));
    let beyond = xref_stream_with(
        "/Size 5000000 /W [1 4 2] /Index [0 4194305] /Filter /FlateDecode",
        &zlib(&[0u8; 14]),
    );
    assert!(matches!(
        open(&beyond, &limits),
        Err(PdfError::Limit("xref entries"))
    ));
    // A deflate bomb behind two rows: only what the declared rows need is inflated.
    let bomb = xref_stream_with(
        "/Size 2 /W [1 4 2] /Index [0 2] /Filter /FlateDecode",
        &zlib(&vec![0u8; 16 * 1024 * 1024]),
    );
    assert!(open(&bomb, &limits).is_err());
    assert!(
        started.elapsed().as_secs() < 30,
        "hostile tables must be refused quickly, took {:?}",
        started.elapsed()
    );
}

/// The ceiling is real: past `max_objects` the object-graph bounds still hold (an object
/// stream's member count, the field count) while a big table alone does not trip them.
#[test]
fn object_graph_bounds_still_refuse_limit_plus_one() {
    let doc = classic(5_000, 1);
    // A table of 5000 objects is far under the xref budget and opens under max_objects 512.
    let limits = PdfLimits {
        max_objects: 512,
        ..PdfLimits::default()
    };
    assert_eq!(open(&doc.bytes, &limits).unwrap(), 1);
    // An object stream with more members than max_objects is refused at resolution.
    let streamed = streamed(2_000, 1, true);
    let tiny = PdfLimits {
        max_objects: 50,
        ..PdfLimits::default()
    };
    assert!(sign(&streamed.bytes, &tiny).is_err());
}
/// Smallest operation memory budget under which `bytes` opens (bisected).
fn least_memory(bytes: &[u8], limits: &PdfLimits) -> u64 {
    let (mut refused, mut admitted) = (0u64, 1_000_000_000u64);
    while refused + 1 < admitted {
        let mid = (refused + admitted) / 2;
        let mut scope = scope_with(ResourceLimits {
            memory_bytes: mid,
            ..ResourceLimits::default()
        });
        let mut cursor = Cursor::new(bytes);
        match PdfDocument::open(Source::seekable(&mut cursor, None), limits, &mut scope) {
            Ok(_) => admitted = mid,
            Err(PdfError::Processing(ProcessingError::MemoryLimit)) => refused = mid,
            Err(other) => panic!("{other:?}"),
        }
    }
    admitted
}
/// Every run of consecutive object numbers costs its 32-byte header on top of the rows:
/// a table of one-entry runs is charged for them (the host bound assumes one per entry).
#[test]
fn runs_are_charged_on_top_of_the_rows() {
    let limits = PdfLimits::default();
    let (metadata, memory) = budget::reader(&limits).unwrap();
    let runs = 60_000u64;
    let mut table = String::new();
    for n in 0..runs {
        table.push_str(&format!("{} 1\n{:010} 00000 n \n", n * 2, 9));
    }
    let bytes = dense_gen::classic_with_table_size(&table, (runs * 2) as u32);
    let charged = least_memory(&bytes, &limits) - (metadata + memory);
    assert!(charged >= runs * (16 + 32), "charged {charged}");
    assert!(charged <= budget::xref_memory(&limits, runs).unwrap());
}
/// Acceptance of a table never depends on where the 64 KiB read chunks fall: entries
/// padded with long blanks (past the usual refill margin) open at every alignment.
#[test]
fn classic_table_acceptance_is_independent_of_chunk_alignment() {
    let limits = PdfLimits::default();
    for pad in [70usize, 100, 300, 4000, 40_000] {
        for shift in 0..9usize {
            let count = 400_000 / (pad + 20);
            let mut table = format!("{}0 {count}\n", " ".repeat(shift));
            for _ in 0..count {
                table.push_str(&format!("{:010}{}00000 n \n", 9, " ".repeat(pad)));
            }
            let bytes = dense_gen::classic_with_table_size(&table, count as u32 + 1);
            assert!(bytes.len() > 300_000);
            open(&bytes, &limits).unwrap_or_else(|e| panic!("pad {pad} shift {shift}: {e:?}"));
        }
    }
    // A unit blank for longer than a chunk, with the table running on past the
    // chunk, is malformed whatever the alignment.
    for shift in [0usize, 5, 17] {
        let mut table = format!("{}0 9000\n", " ".repeat(shift));
        for n in 0..9000 {
            let pad = if n == 3000 { 70_000 } else { 1 };
            table.push_str(&format!("{:010}{}00000 n \n", 9, " ".repeat(pad)));
        }
        let bytes = dense_gen::classic_with_table_size(&table, 9001);
        assert!(open(&bytes, &limits).is_err(), "shift {shift}");
    }
}
/// A subsection header `first<blanks>count` (and an entry) whose digits are cut by the
/// chunk end must not be read as the truncated number: sweep the padding that moves the
/// second header's tokens across the 64 KiB boundary, for several header paddings.
#[test]
fn tokens_cut_by_the_chunk_end_are_reread_not_truncated() {
    let limits = PdfLimits::default();
    let count = 1234usize;
    for entry_pad in (65_536 - 220)..=(65_536 - 20) {
        for header_pad in [70usize, 100, 130] {
            let mut table = format!("0 1\n{:010}{}00000 n \n", 9, " ".repeat(entry_pad - 31));
            table.push_str(&format!("1{}{count}\n", " ".repeat(header_pad)));
            for _ in 0..count {
                table.push_str(&format!("{:010} 00000 n \n", 9));
            }
            let bytes = dense_gen::classic_with_table_size(&table, count as u32 + 2);
            open(&bytes, &limits)
                .unwrap_or_else(|e| panic!("pad {entry_pad} header {header_pad}: {e:?}"));
        }
    }
}
/// The charge is the rows themselves, not a flat allowance: the smallest memory budget
/// that opens a document sits between 16 bytes per entry and the host-side bound.
#[test]
fn the_charge_is_the_rows_actually_held() {
    let doc = classic(200_000, 1);
    let limits = PdfLimits::default();
    let (metadata, memory) = budget::reader(&limits).unwrap();
    let charged = least_memory(&doc.bytes, &limits) - (metadata + memory);
    assert!(charged >= doc.entries * 16, "charged {charged}");
    assert!(
        charged <= budget::xref_memory(&limits, doc.entries).unwrap(),
        "charged {charged}"
    );
}
