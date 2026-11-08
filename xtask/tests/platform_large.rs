//! Small deterministic cases of `cargo xtask platform-proof`: the reference generator, the
//! operating-system measurement and the result parsing. They never run the full-size matrix:
//! that is the separate acceptance gate (docs/dev/platform-acceptance.md). The oracle test
//! needs lxml, pyHanko and friends (`ONCL_PYHANKO_PYTHON`) and fails, never skips, without them.

use std::{io::Read, path::Path};
use xtask::platform::{
    generate::{
        self, blob,
        pdf::{self, PdfProfile},
        xml::{self, XmlKind},
    },
    large::{http_raw, otlp},
    measure::{self, Feed, RunOptions},
};

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).unwrap();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    generate::hex(&h.finalize())
}

#[test]
fn blob_has_the_exact_size_a_visible_structure_and_is_deterministic() {
    let dir = scratch();
    for size in [1u64, 19, 20, 21, 100_000, 3 * 1024 * 1024 + 7] {
        let a = dir.path().join(format!("a{size}"));
        let b = dir.path().join(format!("b{size}"));
        let (facts, digests) = blob::generate(&a, size, 7).unwrap();
        let (_, again) = blob::generate(&b, size, 7).unwrap();
        assert_eq!(digests.len, size);
        assert_eq!(digests, again, "same seed, same bytes");
        assert_eq!(
            sha256(&a),
            digests.sha256,
            "the digest is of the bytes written"
        );
        let bytes = std::fs::read(&a).unwrap();
        assert_eq!(bytes.len() as u64, size);
        let mut at = 0usize;
        let mut frames = 0u64;
        while at + 20 <= bytes.len() && &bytes[at..at + 8] == b"ONCLBLOB" {
            assert_eq!(
                u64::from_be_bytes(bytes[at + 8..at + 16].try_into().unwrap()),
                frames
            );
            let len = u32::from_be_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
            at += 20 + len + 4;
            frames += 1;
        }
        assert_eq!(frames, facts.frames);
    }
    // not a constant fill
    let (_, _) = blob::generate(&dir.path().join("c"), 100_000, 1).unwrap();
    let bytes = std::fs::read(dir.path().join("c")).unwrap();
    let distinct: std::collections::HashSet<u8> = bytes.iter().copied().collect();
    assert!(
        distinct.len() > 200,
        "{} distinct byte values",
        distinct.len()
    );
}

#[test]
fn xml_has_the_exact_size_consistent_extents_and_is_deterministic() {
    let dir = scratch();
    for kind in [XmlKind::Archive, XmlKind::Soap] {
        for size in [64 * 1024u64, 1_000_003] {
            let a = dir.path().join("a.xml");
            let b = dir.path().join("b.xml");
            let (facts, digests) = xml::generate(&a, size, 11, kind).unwrap();
            let (facts2, digests2) = xml::generate(&b, size, 11, kind).unwrap();
            assert_eq!(digests.len, size);
            assert_eq!(digests, digests2);
            assert_eq!(facts.whole_canonical_sha256, facts2.whole_canonical_sha256);
            let bytes = std::fs::read(&a).unwrap();
            assert_eq!(bytes.len() as u64, size);
            for e in &facts.elements {
                assert_eq!(bytes[e.start as usize], b'<', "{}", e.id);
                assert_eq!(bytes[e.end as usize - 1], b'>', "{}", e.id);
                assert!(e.canonical_len > 0 && e.canonical_len <= e.end - e.start + 4096);
            }
            let close = facts.root_close_offset as usize;
            assert_eq!(
                &bytes[close..close + facts.suffix_after_root_close.len()],
                facts.suffix_after_root_close.as_bytes()
            );
            assert!(bytes[facts.far_tamper_offset as usize].is_ascii_digit());
            assert_eq!(
                bytes[facts.far_tamper_offset as usize],
                facts.far_tamper_byte
            );
            assert_eq!(
                bytes[facts.uncovered_tamper_offset as usize],
                facts.uncovered_tamper_byte
            );
            let far = facts
                .elements
                .iter()
                .find(|e| e.id == facts.far_target)
                .unwrap();
            assert!(
                facts.far_tamper_offset > far.start && facts.far_tamper_offset < far.end,
                "the far byte lies inside the far element"
            );
            assert!(
                facts.uncovered_tamper_offset < far.start
                    || facts.uncovered_tamper_offset >= far.end,
                "the other byte lies outside"
            );
            // non-canonical on purpose: the document is not its own canonical form
            let text = String::from_utf8(bytes).unwrap();
            assert!(
                text.contains("<rec:item  seq = "),
                "records are written in a lexical form that canonicalization changes"
            );
            assert!(
                text.contains("xmlns:unused="),
                "an unused namespace declaration is present"
            );
        }
    }
}

#[test]
fn soap_has_no_processing_instruction_and_archive_has() {
    let dir = scratch();
    let (_, _) = xml::generate(&dir.path().join("s.xml"), 400_000, 3, XmlKind::Soap).unwrap();
    let (_, _) = xml::generate(&dir.path().join("a.xml"), 400_000, 3, XmlKind::Archive).unwrap();
    let soap = std::fs::read_to_string(dir.path().join("s.xml")).unwrap();
    let archive = std::fs::read_to_string(dir.path().join("a.xml")).unwrap();
    assert!(
        !soap.replace("<?xml version", "").contains("<?"),
        "SOAP 1.1 forbids processing instructions"
    );
    assert!(
        archive.contains("<?audit seq="),
        "the archive exercises PI canonicalization"
    );
}

#[test]
fn pdf_has_three_revisions_valid_trailers_and_the_exact_size() {
    let dir = scratch();
    for profile in [PdfProfile::Dense, PdfProfile::Compact] {
        let path = dir.path().join("a.pdf");
        let (facts, digests) = pdf::generate(&path, 2 * 1024 * 1024 + 13, 5, profile).unwrap();
        assert_eq!(digests.len, 2 * 1024 * 1024 + 13);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(facts.revisions.len(), 3);
        assert_eq!(facts.revisions[0].kind, "xref-table");
        let mut previous_end = 0;
        for r in &facts.revisions {
            assert_eq!(r.start, previous_end);
            previous_end = r.end;
            let tail =
                String::from_utf8_lossy(&bytes[r.end as usize - 40..r.end as usize]).into_owned();
            assert!(tail.ends_with("%%EOF\n"), "{tail:?}");
            assert!(tail.contains(&format!("startxref\n{}\n", r.startxref)));
            let at = r.startxref as usize;
            if r.kind == "xref-table" {
                assert_eq!(&bytes[at..at + 4], b"xref");
            } else {
                assert!(String::from_utf8_lossy(&bytes[at..at + 30]).contains(" 0 obj"));
            }
        }
        assert_eq!(previous_end, digests.len);
        let payload = &bytes
            [facts.embedded_offset as usize..(facts.embedded_offset + facts.embedded_len) as usize];
        assert_eq!(
            generate::hex(&<sha2::Sha256 as sha2::Digest>::digest(payload)),
            facts.embedded_sha256
        );
        assert!(facts.pages > 4);
    }
}

#[test]
fn stored_zlib_streams_decode_with_a_real_inflater() {
    use std::io::Read;
    for len in [0usize, 1, 65534, 65535, 65536, 200_001] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let z = pdf::zlib_stored(&data);
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(&z[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data, "length {len}");
    }
}

/// The generator against third-party tools: lxml's canonicalization of every Id'd element and of
/// the whole document, and pyHanko/qpdf/pypdf/pdfminer on the PDF structure.
#[test]
fn reference_generator_agrees_with_lxml_and_pyhanko() {
    let python = std::env::var("ONCL_PYHANKO_PYTHON")
        .expect("ONCL_PYHANKO_PYTHON must name a Python with lxml, cryptography, asn1crypto and pyHanko (never skipped)");
    let dir = scratch();
    let evidence = xtask::platform::large::validate_reference(
        Path::new(&python),
        std::env::var_os("ONCL_PY_TOOLS")
            .map(std::path::PathBuf::from)
            .as_deref(),
        dir.path(),
        &mut |_| {},
    )
    .unwrap();
    for name in [
        "blob",
        "xml-archive",
        "xml-soap",
        "pdf-dense",
        "pdf-compact",
    ] {
        assert_eq!(evidence[name]["ok"], true, "{name}: {}", evidence[name]);
    }
}

#[test]
fn proc_status_and_result_lines_parse() {
    let text =
        "Name:\tx\nVmPeak:\t  900 kB\nVmHWM:\t 2048 kB\nVmRSS:\t 1024 kB\nRssAnon:\t  512 kB\n";
    let s = measure::parse_proc_status(text).unwrap();
    assert_eq!(
        (s.vm_hwm, s.vm_rss, s.rss_anon),
        (2048 * 1024, 1024 * 1024, 512 * 1024)
    );
    assert!(measure::parse_proc_status("Name:\tx\n").is_none());
    let out = "noise\nONCL-PROOF-RESULT {\"ok\":true,\"digest\":\"ab\"}\n";
    let v = measure::parse_result_line(out, "ONCL-PROOF-RESULT ").unwrap();
    assert_eq!(v["digest"], "ab");
    assert!(measure::parse_result_line("nothing", "ONCL-PROOF-RESULT ").is_none());
    assert!(
        measure::parse_result_line("ONCL-PROOF-RESULT {not json", "ONCL-PROOF-RESULT ").is_none()
    );
}

#[test]
fn peaks_criterion_is_the_stricter_of_working_set_and_private_bytes() {
    let p = measure::Peaks {
        peak_working_set: 5,
        peak_private: 9,
        sampled_max: 1,
    };
    assert_eq!(p.criterion(), 9);
    let p = measure::Peaks {
        peak_working_set: 12,
        peak_private: 9,
        sampled_max: 99,
    };
    assert_eq!(
        p.criterion(),
        12,
        "a polling sample never replaces the OS peak"
    );
}

#[test]
fn a_real_process_is_measured_by_the_operating_system() {
    let dir = scratch();
    let (program, args): (&str, &[&str]) = if cfg!(windows) {
        ("cmd", &["/C", "echo", "measured"])
    } else {
        ("sh", &["-c", "echo measured"])
    };
    let mut command = std::process::Command::new(program);
    command.args(args);
    let m = measure::run_measured(
        command,
        RunOptions {
            watch: Some(dir.path().to_path_buf()),
            ..RunOptions::default()
        },
    )
    .unwrap();
    assert!(m.success, "{:?}", m.exit);
    assert!(m.stdout_text().contains("measured"));
    assert!(
        m.peaks.peak_working_set > 0,
        "the OS reports a peak working set: {:?}",
        m.peaks
    );
    #[cfg(windows)]
    assert!(
        m.peaks.peak_private > 0,
        "the OS reports peak private bytes: {:?}",
        m.peaks
    );
    assert_eq!(m.temp.unwrap().final_files, 0);
}

#[test]
fn a_fed_stdin_with_no_declared_length_reaches_the_child() {
    let dir = scratch();
    let path = dir.path().join("in.bin");
    std::fs::write(&path, vec![b'x'; 300_000]).unwrap();
    let (program, args): (&str, &[&str]) = if cfg!(windows) {
        ("cmd", &["/C", "find", "/c", "/v", ""])
    } else {
        ("sh", &["-c", "wc -c"])
    };
    let mut command = std::process::Command::new(program);
    command.args(args);
    let m = measure::run_measured(
        command,
        RunOptions {
            feed: Feed::File(path),
            ..RunOptions::default()
        },
    )
    .unwrap();
    assert!(m.success, "{}", m.stderr_text());
    let counted: String = m
        .stdout_text()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    assert!(!counted.is_empty());
}

#[test]
fn storage_preflight_refuses_an_insufficient_scratch_as_blocked() {
    let dir = scratch();
    let ok = measure::preflight_storage(dir.path(), 1).unwrap();
    assert_eq!(ok.kind, "fixed", "tests run on a local fixed drive");
    let err = measure::preflight_storage(dir.path(), u64::MAX)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("BLOCKED:"), "{err}");
}

#[test]
fn scratch_usage_counts_files_below_a_directory() {
    let dir = scratch();
    std::fs::create_dir(dir.path().join("a")).unwrap();
    std::fs::write(dir.path().join("a/x"), [0u8; 10]).unwrap();
    std::fs::write(dir.path().join("y"), [0u8; 5]).unwrap();
    assert_eq!(measure::tree_usage(dir.path()), (15, 2));
    assert_eq!(measure::tree_usage(&dir.path().join("missing")), (0, 0));
}

#[test]
fn otlp_gauges_decode_from_the_wire_format() {
    let body = otlp::encode_gauge("oncl.executor.running", 2);
    let points = otlp::decode_metrics(&body).unwrap();
    assert_eq!(points, vec![("oncl.executor.running".to_owned(), 2.0)]);
    let body = otlp::encode_gauge("oncl.executor.queued", -1);
    assert_eq!(otlp::decode_metrics(&body).unwrap()[0].1, -1.0);
    assert!(
        otlp::decode_metrics(&[0x0a, 0xff, 0xff]).is_none(),
        "a truncated message is refused"
    );
}

#[test]
fn a_multipart_mixed_answer_yields_its_final_record_and_artifact() {
    let part = |content_type: &str, data: &str| {
        format!(
            "--B\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{data}\r\n",
            data.len()
        )
    };
    let body = format!(
        "{}{}{}--B--\r\n",
        part("application/json", "{\"type\":\"progress\"}"),
        part("application/octet-stream", "ABCDE"),
        part(
            "application/json",
            "{\"type\":\"final\",\"status\":\"completed\"}"
        )
    )
    .into_bytes();
    let reply = http_raw::Reply {
        status: 200,
        content_type: "multipart/mixed; boundary=B".into(),
        body,
        ..Default::default()
    };
    let (final_record, artifact) = http_raw::multipart_final(&reply).unwrap();
    assert_eq!(final_record["status"], "completed");
    assert_eq!(artifact, b"ABCDE");
}
