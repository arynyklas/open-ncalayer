//! Artifacts of at least 1 GiB (the size is `--large-bytes`): content-bearing generated
//! inputs (a pseudo-random binary file, a canonical XML document of many elements, a PDF of
//! many pages: never one padded or sparse object), signed by `oncl` and judged by an
//! independent decomposition: a streamed digest of exactly the signed bytes plus an
//! external check of signedAttrs / SignedInfo / the CMS signature. `oncl`'s own parser is
//! never the oracle. No claim above the artifact size is made; the guaranteed document size is 1 GiB.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, ensure};

use super::super::oncl::{INVALID, VALID, path_str};
use super::super::world::{NOW, Profile};
use super::super::{Case, Ctx, Observed};
use super::common::grade;

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("large-cms-detached-rsa", large_cms),
        Case::new("large-xml-enveloped-rsa", large_xml),
        Case::new("large-pdf-signature-rsa", |ctx| {
            large_pdf(ctx, 16_300, ctx.large_bytes)
        }),
        // The cheap reproduction of D6: 128 MiB, about 8000 pages with 16 KiB streams.
        Case::new("pdf-many-pages-128mib-rsa", |ctx| {
            large_pdf(ctx, 16_300, 134_217_728)
        }),
        Case::new("large-pdf-signature-rsa-1mib-pages", |ctx| {
            large_pdf(ctx, 1 << 20, ctx.large_bytes)
        }),
    ]
}

fn scratch(ctx: &Ctx, name: &str) -> anyhow::Result<PathBuf> {
    let dir = ctx.scratch.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
    Ok(dir)
}

fn gib(bytes: u64) -> String {
    format!("{:.1}GiB", bytes as f64 / (1u64 << 30) as f64)
}

/// xorshift64*: deterministic, content-bearing bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

fn write_binary(path: &Path, bytes: u64) -> anyhow::Result<()> {
    let mut out = BufWriter::with_capacity(1 << 20, std::fs::File::create(path)?);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut left = bytes;
    let mut block = vec![0_u8; 1 << 16];
    while left > 0 {
        for chunk in block.chunks_mut(8) {
            let v = rng.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        let n = left.min(block.len() as u64) as usize;
        out.write_all(&block[..n])?;
        left -= n as u64;
    }
    out.flush()?;
    Ok(())
}

/// Flips one bit of the byte at `offset`.
fn flip(path: &Path, offset: u64) -> anyhow::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut b = [0_u8; 1];
    f.read_exact(&mut b)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&[b[0] ^ 1])?;
    Ok(())
}

fn tmp_args(dir: &Path) -> anyhow::Result<Vec<String>> {
    Ok(vec![
        "--temporary-directory".to_owned(),
        path_str(dir)?.to_owned(),
    ])
}

fn oncl_run(ctx: &Ctx, dir: &Path, words: &[String]) -> anyhow::Result<super::super::tools::Out> {
    let mut args = ctx.world.trust_args();
    args.extend(tmp_args(dir)?);
    // The large operations take minutes: the default deadline of 300 s is not the subject.
    args.extend(["--timeout-seconds".to_owned(), "3500".to_owned()]);
    args.extend(words.iter().cloned());
    ctx.oncl.run(&args)
}

fn sign_words(
    ctx: &Ctx,
    profile: &str,
    input: &Path,
    output: &Path,
    extra: &[&str],
) -> anyhow::Result<Vec<String>> {
    let signer = ctx.world.signer(Profile::Rsa);
    let mut words: Vec<String> = vec![
        "sign".into(),
        "--profile".into(),
        profile.into(),
        "--input".into(),
        path_str(input)?.into(),
        "--output".into(),
        path_str(output)?.into(),
        "--key".into(),
        path_str(&signer.p12)?.into(),
        "--secret-file".into(),
        path_str(&ctx.world.secret)?.into(),
        "--authorize".into(),
    ];
    words.extend(extra.iter().map(|s| (*s).to_owned()));
    Ok(words)
}

fn verify_words(profile: &str, input: &Path, extra: &[&str]) -> anyhow::Result<Vec<String>> {
    let mut words: Vec<String> = vec![
        "verify".into(),
        "--profile".into(),
        profile.into(),
        "--input".into(),
        path_str(input)?.into(),
    ];
    words.extend(extra.iter().map(|s| (*s).to_owned()));
    Ok(words)
}

fn large_cms(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let dir = scratch(ctx, "large-cms")?;
    let (data, sig) = (dir.join("data.bin"), dir.join("sig.p7s"));
    write_binary(&data, ctx.large_bytes)?;
    let started = Instant::now();
    let signed = oncl_run(
        ctx,
        &dir,
        &sign_words(ctx, "cms", &data, &sig, &["--detached"])?,
    )?;
    ensure!(
        signed.ok(),
        "oncl sign of {} bytes: {}",
        ctx.large_bytes,
        signed.brief()
    );
    let sign_seconds = started.elapsed().as_secs();
    let data_arg = path_str(&data)?.to_owned();
    let verified = oncl_run(
        ctx,
        &dir,
        &verify_words("cms", &sig, &["--detached", &data_arg])?,
    )?;
    ensure!(
        verified.code == Some(VALID),
        "oncl verify: {}",
        verified.brief()
    );
    let openssl = ctx.openssl(&[
        "cms".to_owned(),
        "-verify".into(),
        "-binary".into(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        path_str(&sig)?.into(),
        "-content".into(),
        path_str(&data)?.into(),
        "-CAfile".into(),
        path_str(&ctx.world.root_pem)?.into(),
        "-purpose".into(),
        "any".into(),
        "-attime".into(),
        NOW.to_string(),
        "-out".into(),
        "/dev/null".into(),
    ])?;
    ensure!(
        openssl.ok() && openssl.stderr.contains("Verification successful"),
        "OpenSSL: {}",
        openssl.brief()
    );
    let stream = ctx.py_json(&[
        "cms-stream-verify".to_owned(),
        path_str(&sig)?.to_owned(),
        "--content".into(),
        data_arg.clone(),
    ])?;
    ensure!(
        stream["ok"] == true,
        "streamed digest + RSA check: {stream}"
    );
    // The counterexample: one bit in the middle of the signed data.
    flip(&data, ctx.large_bytes / 2)?;
    let bad = oncl_run(
        ctx,
        &dir,
        &verify_words("cms", &sig, &["--detached", &data_arg])?,
    )?;
    ensure!(
        bad.code == Some(INVALID),
        "oncl on the altered data: {}",
        bad.brief()
    );
    let openssl_bad = ctx.openssl(&[
        "cms".to_owned(),
        "-verify".into(),
        "-binary".into(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        path_str(&sig)?.into(),
        "-content".into(),
        path_str(&data)?.into(),
        "-noverify".into(),
        "-out".into(),
        "/dev/null".into(),
    ])?;
    ensure!(!openssl_bad.ok(), "OpenSSL accepted the altered data");
    let stream_bad = ctx.py_json(&[
        "cms-stream-verify".to_owned(),
        path_str(&sig)?.to_owned(),
        "--content".into(),
        data_arg,
    ])?;
    ensure!(
        stream_bad["ok"] == false,
        "streamed digest accepted the altered data: {stream_bad}"
    );
    let size = ctx.large_bytes;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(Observed {
        grade: grade(&[
            ("size", gib(size)),
            ("crypto", "ok".to_owned()),
            ("ours", "Valid".to_owned()),
            ("openssl", "streamed -content verified".to_owned()),
            (
                "decomposition",
                "streamed sha256 = messageDigest, RSA over signedAttrs ok".to_owned(),
            ),
            (
                "altered",
                "rejected by oncl, OpenSSL and the streamed digest".to_owned(),
            ),
        ]),
        ours: format!("signed {size} bytes in {sign_seconds}s"),
        oracle: "OpenSSL cms -verify -content; Python streamed digest".to_owned(),
        detail: String::new(),
    })
}

/// `<root>` of `item` elements in canonical form already (no declaration inside the document
/// element, sorted single attribute, no characters that need escaping, no empty elements),
/// so that its canonical octets are exactly its bytes.
fn write_xml(path: &Path, bytes: u64) -> anyhow::Result<u64> {
    let mut out = BufWriter::with_capacity(1 << 20, std::fs::File::create(path)?);
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let mut written = 0_u64;
    let head = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>";
    out.write_all(head)?;
    written += head.len() as u64;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789 ";
    let mut n = 0_u64;
    while written + 200 < bytes {
        let mut text = Vec::with_capacity(160);
        for _ in 0..(40 + rng.next() % 100) {
            text.push(alphabet[(rng.next() % alphabet.len() as u64) as usize]);
        }
        let item = format!("<item n=\"{n}\">{}</item>", std::str::from_utf8(&text)?);
        out.write_all(item.as_bytes())?;
        written += item.len() as u64;
        n += 1;
    }
    out.write_all(b"</root>")?;
    out.flush()?;
    Ok(written + 7)
}

fn large_xml(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let dir = scratch(ctx, "large-xml")?;
    let (doc, signed) = (dir.join("doc.xml"), dir.join("signed.xml"));
    let size = write_xml(&doc, ctx.large_bytes)?;
    let started = Instant::now();
    let out = oncl_run(ctx, &dir, &sign_words(ctx, "xml", &doc, &signed, &[])?)?;
    ensure!(
        out.ok(),
        "oncl sign --profile xml of {size} bytes: {}",
        out.brief()
    );
    let seconds = started.elapsed().as_secs();
    let verified = oncl_run(ctx, &dir, &verify_words("xml", &signed, &[])?)?;
    ensure!(
        verified.code == Some(VALID),
        "oncl verify: {}",
        verified.brief()
    );
    let independent =
        ctx.py_json(&["xml-large-verify".to_owned(), path_str(&signed)?.to_owned()])?;
    ensure!(
        independent["ok"] == true,
        "streamed canonical digest + SignedInfo RSA: {independent}"
    );
    flip(&signed, size / 2)?;
    let bad = oncl_run(ctx, &dir, &verify_words("xml", &signed, &[])?)?;
    ensure!(
        bad.code == Some(INVALID),
        "oncl on the altered document: {}",
        bad.brief()
    );
    let independent_bad =
        ctx.py_json(&["xml-large-verify".to_owned(), path_str(&signed)?.to_owned()])?;
    ensure!(
        independent_bad["digest_ok"] == false,
        "independent digest accepted the altered document: {independent_bad}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(Observed {
        grade: grade(&[
            ("size", gib(size)),
            ("crypto", "ok".to_owned()),
            ("ours", "Valid".to_owned()),
            ("decomposition", "streamed sha256 of the bytes outside ds:Signature = DigestValue, SignedInfo RSA ok".to_owned()),
            ("altered", "rejected by oncl and the independent digest".to_owned()),
        ]),
        ours: format!("signed {size} bytes in {seconds}s"),
        oracle: "Python: streamed digest over the canonical-by-construction document, lxml C14N of SignedInfo, cryptography RSA".to_owned(),
        detail: String::new(),
    })
}

/// A PDF of many pages (each with its own content stream of pseudo-random text), classic
/// xref table: offsets below 10^10.
fn write_pdf(path: &Path, bytes: u64, stream_len: usize) -> anyhow::Result<u64> {
    let mut out = BufWriter::with_capacity(1 << 20, std::fs::File::create(path)?);
    let mut offsets: Vec<u64> = vec![0];
    let mut at = 0_u64;
    let put =
        |out: &mut BufWriter<std::fs::File>, data: &[u8], at: &mut u64| -> anyhow::Result<()> {
            out.write_all(data)?;
            *at += data.len() as u64;
            Ok(())
        };
    put(&mut out, b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", &mut at)?;
    let pages = (bytes / (stream_len as u64 + 200)).max(1);
    // Objects: 1 Catalog, 2 Pages, 3 Font, then page i = 4 + 2i, its stream 5 + 2i.
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut kids = String::new();
    let mut pending_objects: Vec<(u64, u64)> = Vec::new();
    for i in 0..pages {
        let (page, stream) = (4 + 2 * i, 5 + 2 * i);
        let mut body = Vec::with_capacity(stream_len + 100);
        body.extend_from_slice(b"BT /F1 9 Tf 20 800 Td 11 TL\n");
        while body.len() < stream_len {
            body.push(b'(');
            for _ in 0..70 {
                body.push(b'a' + (rng.next() % 26) as u8);
            }
            body.extend_from_slice(b") Tj T*\n");
        }
        body.extend_from_slice(b"ET\n");
        let page_obj = format!(
            "{page} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {stream} 0 R >>\nendobj\n"
        );
        pending_objects.push((page, at));
        put(&mut out, page_obj.as_bytes(), &mut at)?;
        let head = format!("{stream} 0 obj\n<< /Length {} >>\nstream\n", body.len());
        pending_objects.push((stream, at));
        put(&mut out, head.as_bytes(), &mut at)?;
        put(&mut out, &body, &mut at)?;
        put(&mut out, b"endstream\nendobj\n", &mut at)?;
        kids.push_str(&format!("{page} 0 R "));
    }
    let tail: [(u64, String); 3] = [
        (
            1,
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_owned(),
        ),
        (
            2,
            format!("2 0 obj\n<< /Type /Pages /Count {pages} /Kids [{kids}] >>\nendobj\n"),
        ),
        (
            3,
            "3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n".to_owned(),
        ),
    ];
    let total = 4 + 2 * pages;
    let mut table = vec![0_u64; total as usize];
    for (n, offset) in pending_objects {
        table[n as usize] = offset;
    }
    for (n, text) in tail {
        table[n as usize] = at;
        put(&mut out, text.as_bytes(), &mut at)?;
    }
    let xref_at = at;
    let mut xref = format!("xref\n0 {total}\n0000000000 65535 f \n");
    for entry in table.iter().skip(1) {
        xref.push_str(&format!("{entry:010} 00000 n \n"));
    }
    xref.push_str(&format!(
        "trailer\n<< /Size {total} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
    ));
    put(&mut out, xref.as_bytes(), &mut at)?;
    out.flush()?;
    let _ = offsets.pop();
    Ok(at)
}

fn large_pdf(ctx: &mut Ctx, stream: usize, bytes: u64) -> anyhow::Result<Observed> {
    let dir = scratch(ctx, &format!("large-pdf-{stream}-{bytes}"))?;
    let (doc, signed) = (dir.join("doc.pdf"), dir.join("signed.pdf"));
    let size = write_pdf(&doc, bytes, stream)?;
    let started = Instant::now();
    let out = oncl_run(ctx, &dir, &sign_words(ctx, "pdf", &doc, &signed, &[])?)?;
    ensure!(
        out.ok(),
        "oncl sign --profile pdf of {size} bytes: {}",
        out.brief()
    );
    let seconds = started.elapsed().as_secs();
    let verified = oncl_run(ctx, &dir, &verify_words("pdf", &signed, &[])?)?;
    ensure!(
        verified.code == Some(VALID),
        "oncl verify: {}",
        verified.brief()
    );
    let decomposition =
        ctx.py_json(&["pdf-byterange".to_owned(), path_str(&signed)?.to_owned()])?;
    ensure!(
        decomposition["ok"] == true,
        "ByteRange decomposition: {decomposition}"
    );
    let covered = decomposition["signatures"][0]["byte_range"][1]
        .as_u64()
        .unwrap_or(0);
    ensure!(
        covered > size / 2,
        "the first range covers only {covered} of {size} bytes"
    );
    flip(&signed, size / 3)?;
    let bad = oncl_run(ctx, &dir, &verify_words("pdf", &signed, &[])?)?;
    ensure!(
        bad.code == Some(INVALID),
        "oncl on the altered PDF: {}",
        bad.brief()
    );
    let decomposition_bad =
        ctx.py_json(&["pdf-byterange".to_owned(), path_str(&signed)?.to_owned()])?;
    ensure!(
        decomposition_bad["signatures"][0]["digest_ok"] == false,
        "independent ByteRange digest accepted the altered PDF: {decomposition_bad}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(Observed {
        grade: grade(&[
            ("size", gib(size)),
            ("crypto", "ok".to_owned()),
            ("ours", "Valid".to_owned()),
            ("decomposition", "streamed ByteRange sha256 = messageDigest, RSA over signedAttrs ok, range covers the file".to_owned()),
            ("altered", "rejected by oncl and the independent ByteRange digest".to_owned()),
        ]),
        ours: format!("signed {size} bytes in {seconds}s"),
        oracle: "Python: memory-mapped ByteRange decomposition (no PDF library, no copy of the file)".to_owned(),
        detail: String::new(),
    })
}
