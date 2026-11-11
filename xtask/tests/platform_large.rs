//! Small deterministic cases of `cargo xtask platform-proof`: the reference generator, the
//! operating-system measurement and the result parsing. They never run the full-size matrix:
//! that is the separate acceptance gate (docs/dev/platform-acceptance.md). The oracle test
//! needs lxml, pyHanko and friends (`ONCL_PYHANKO_PYTHON`) and fails, never skips, without them.

use std::{io::Read, path::Path, time::Duration};
use xtask::platform::{
    generate::{
        self, blob,
        pdf::{self, PdfProfile},
        xml::{self, XmlKind},
    },
    large::{barrier, http_raw, otlp},
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
    // Windows asks the OS after the process exits. Elsewhere the peak is sampled while it
    // runs (`/proc/<pid>/status`, every 100 ms), so the process must outlive a sample: one
    // that exits at once (`echo`) is gone before the first one.
    let (program, args): (&str, &[&str]) = if cfg!(windows) {
        ("cmd", &["/C", "echo", "measured"])
    } else {
        ("sh", &["-c", "echo measured; sleep 1"])
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
    // macOS has no /proc: the proof's measurement exists for Windows and Linux only.
    #[cfg(any(windows, target_os = "linux"))]
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
    // 100 000 lines of `x\r\n`, 300 000 bytes: more than a pipe holds, so the child reads
    // while it is fed. (Windows' `find` splits lines at CRLF only.)
    std::fs::write(&path, b"x\r\n".repeat(100_000)).unwrap();
    // Windows' `find` counts lines, named by its full path: under Git Bash (the shell of the
    // CI steps) a bare `find` is GNU find, which takes `/c` for the system drive and walks it.
    let (program, args, expected): (std::path::PathBuf, &[&str], &str) = if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
        let find = std::path::Path::new(&root)
            .join("System32")
            .join("find.exe");
        (find, &["/c", "/v", ""], "100000")
    } else {
        ("sh".into(), &["-c", "wc -c"], "300000")
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
    assert_eq!(counted, expected, "{}", m.stdout_text());
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

#[test]
fn a_barrier_returns_when_its_state_holds_and_names_what_never_happened() {
    let mut polls = 0;
    let value = barrier::wait_until("three polls", Duration::from_secs(5), || {
        polls += 1;
        (polls == 3).then_some(polls * 10)
    })
    .unwrap();
    assert_eq!(value, 30);
    let error = barrier::wait_until::<()>(
        "a slot that is never freed",
        Duration::from_millis(100),
        || None,
    )
    .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("timed out") && text.contains("a slot that is never freed"),
        "{text}"
    );
}

#[test]
fn spool_and_flag_barriers_demand_the_whole_state() {
    let mib = 1u64 << 20;
    // five spools of 8 MiB: every file and (nearly) every byte, not either one
    assert!(barrier::spools_hold(5, 40 * mib, 5, 8 * mib));
    assert!(
        barrier::spools_hold(5, 40 * mib - 5 * 64 * 1024, 5, 8 * mib),
        "the parser's withheld tail is tolerated"
    );
    assert!(
        !barrier::spools_hold(4, 40 * mib, 5, 8 * mib),
        "a spool is missing"
    );
    assert!(
        !barrier::spools_hold(5, 20 * mib, 5, 8 * mib),
        "the spools are not written yet"
    );
    assert!(barrier::all_hold(&[true, true]));
    assert!(!barrier::all_hold(&[true, false]));
    assert!(
        !barrier::all_hold(&[]),
        "a barrier that waits for nobody must not pass"
    );
}

#[test]
fn the_gauge_read_for_a_barrier_is_the_second_export_after_the_change() {
    let sample = |name: &str, value: f64, at: f64| otlp::Sample {
        name: name.into(),
        value,
        at,
    };
    let samples = vec![
        sample("oncl.requests.in_flight", 5.0, 1.0),
        sample("oncl.executor.running", 9.0, 1.1),
        sample("oncl.requests.in_flight", 5.0, 1.2),
        // the change happened at 1.25: this export may have been read just before it
        sample("oncl.requests.in_flight", 4.0, 1.4),
        sample("oncl.requests.in_flight", 0.0, 1.6),
        sample("oncl.requests.in_flight", 0.0, 1.8),
    ];
    let name = "oncl.requests.in_flight";
    assert_eq!(otlp::second_sample_after(&samples, name, 1.25), Some(0.0));
    assert_eq!(
        otlp::second_sample_after(&samples, name, 1.7),
        None,
        "only one export has arrived since"
    );
    assert_eq!(otlp::second_sample_after(&samples, "missing", 0.0), None);
}

/// Reads a request head from `stream`.
fn read_request_head(stream: &mut std::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "closed in the head");
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

fn stalled_upload(document: usize, hold: Duration) -> http_raw::Upload {
    http_raw::Upload {
        path: "/v1/operations".into(),
        metadata: "{}".into(),
        document: http_raw::Source::Bytes(vec![7; document]),
        chunked: true,
        expect_continue: true,
        bytes_per_second: None,
        stall_after: Some((document as u64, hold)),
        abort_after: None,
    }
}

#[test]
fn a_stalled_upload_is_parked_on_100_continue_and_let_go_by_the_harness() {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let head = read_request_head(&mut stream);
        assert!(head.to_ascii_lowercase().contains("expect: 100-continue"));
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        // everything the client writes until it closes
        let mut received = 0usize;
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return received,
                Ok(n) => received += n,
            }
        }
    });
    let probe = http_raw::Probe::default();
    assert!(!probe.continued() && !probe.stalled() && probe.answered().is_none());
    let upload = stalled_upload(100_000, Duration::from_secs(60));
    let reply = std::thread::scope(|s| {
        let client = s.spawn(|| http_raw::send_probed(&address, "t", &upload, &probe));
        barrier::wait_until("the client to be parked", Duration::from_secs(20), || {
            (probe.continued() && probe.stalled()).then_some(())
        })
        .unwrap();
        assert_eq!(probe.document_sent(), 100_000);
        assert_eq!(probe.answered(), None, "nobody answered: it is a stall");
        assert!(
            !client.is_finished(),
            "a stalled client waits until it is let go"
        );
        probe.release();
        client.join().unwrap()
    });
    assert!(
        reply
            .transport_error
            .as_deref()
            .is_some_and(|e| e.contains("on purpose")),
        "{:?}",
        reply.transport_error
    );
    assert_eq!(reply.status, 0);
    let received = server.join().unwrap();
    assert!(received >= 100_000, "the server saw the bytes: {received}");
}

#[test]
fn a_refusal_before_the_body_is_seen_without_a_100_continue() {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request_head(&mut stream);
        let body = r#"{"code":"CapacityExceeded","applied":"NotApplied"}"#;
        write!(
            stream,
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let probe = http_raw::Probe::default();
    let reply = http_raw::send_probed(
        &address,
        "t",
        &stalled_upload(100_000, Duration::from_secs(60)),
        &probe,
    );
    server.join().unwrap();
    assert_eq!(reply.status, 503);
    assert!(reply.refused_before_body);
    assert_eq!(reply.sent_document_bytes, 0);
    assert!(!probe.continued(), "no 100 Continue: no upload slot");
    assert!(!probe.stalled());
    assert_eq!(probe.answered(), Some(503));
    assert_eq!(reply.json().unwrap()["code"], "CapacityExceeded");
}

#[test]
fn a_stall_the_server_ends_is_answered_without_the_harness_letting_go() {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request_head(&mut stream);
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        // read until the client has gone silent (it is parked), then end the stall the way the
        // idle rule does
        stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut received = 0usize;
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => panic!("the client closed"),
                Ok(n) => received += n,
                Err(_) => break,
            }
        }
        assert!(received >= 10_000, "{received}");
        let body = r#"{"code":"DeadlineExceeded","applied":"NotApplied"}"#;
        write!(
            stream,
            "HTTP/1.1 504 Gateway Timeout\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let probe = http_raw::Probe::default();
    let reply = http_raw::send_probed(
        &address,
        "t",
        &stalled_upload(10_000, Duration::from_secs(60)),
        &probe,
    );
    server.join().unwrap();
    assert!(probe.continued() && probe.stalled());
    assert_eq!(probe.answered(), Some(504));
    assert_eq!(reply.status, 504);
    assert_eq!(reply.json().unwrap()["code"], "DeadlineExceeded");
    assert!(!reply.refused_before_body);
}
