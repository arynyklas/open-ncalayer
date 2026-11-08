//! The case matrix: the same scenarios on the SDK probe, the CLI and the HTTP server.

use super::{
    DataSet, Facts,
    env::Env,
    exec::{Cancel, Case, CaseResult, Input, Op, Outcome, Profile, Spec, Target, refused},
};
use anyhow::{Context, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};

pub fn sha256_file(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        total += n as u64;
    }
    Ok((crate::platform::generate::hex(&hash.finalize()), total))
}

fn sha256_pattern(byte: u8, len: u64) -> String {
    let chunk = vec![byte; 1 << 20];
    let mut hash = Sha256::new();
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        hash.update(&chunk[..n]);
        left -= n as u64;
    }
    crate::platform::generate::hex(&hash.finalize())
}

fn openssl() -> PathBuf {
    if let Ok(p) = std::env::var("ONCL_OPENSSL") {
        return p.into();
    }
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432"] {
            if let Ok(base) = std::env::var(var) {
                let candidate = Path::new(&base).join("Git/usr/bin/openssl.exe");
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    "openssl".into()
}

/// `openssl cms -verify -noverify`: the signature over the content with the signer
/// certificate carried in the CMS. Chain trust is the SDK's job: OpenSSL has no GOST root.
pub(super) fn openssl_cms_signature(
    sig: &Path,
    content: Option<&Path>,
    out: &Path,
) -> anyhow::Result<bool> {
    let mut c = Command::new(openssl());
    c.args([
        "cms",
        "-verify",
        "-noverify",
        "-binary",
        "-inform",
        "DER",
        "-in",
    ])
    .arg(sig);
    if let Some(content) = content {
        c.arg("-content").arg(content);
    }
    c.arg("-out").arg(out);
    let output = c.output().context("running openssl")?;
    Ok(output.status.success())
}

fn flip(path: &Path, offset: u64, to: u8) -> anyhow::Result<u8> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut old = [0u8];
    f.read_exact(&mut old)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&[to])?;
    f.sync_all()?;
    Ok(old[0])
}

fn read_byte(path: &Path, offset: u64) -> anyhow::Result<u8> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut b = [0u8];
    f.read_exact(&mut b)?;
    Ok(b[0])
}

fn other_byte(old: u8) -> u8 {
    if old == b'7' { b'8' } else { b'7' }
}

fn guarded<'e>(
    mut case: Case<'e>,
    body: impl FnOnce(&mut Case<'e>) -> anyhow::Result<()>,
) -> CaseResult {
    if let Err(e) = body(&mut case) {
        case.check("the case ran to completion", false, format!("{e:#}"));
    }
    case.finish()
}

fn expect_completed(case: &mut Case<'_>, label: &str, o: &Outcome) {
    case.check(
        label,
        o.completed,
        format!(
            "exit {:?}, code {:?}, applied {:?} {}",
            o.exit, o.code, o.applied, o.stderr_line
        ),
    );
}

fn expect_valid(case: &mut Case<'_>, label: &str, o: &Outcome) {
    case.check(
        label,
        o.completed && o.verdict.as_deref() == Some("Valid"),
        format!(
            "verdict {:?}, signatures {:?}, exit {:?} {}",
            o.verdict, o.signature_checks, o.exit, o.stderr_line
        ),
    );
}

fn expect_invalid(case: &mut Case<'_>, label: &str, o: &Outcome) {
    case.check(
        label,
        o.completed
            && o.verdict.as_deref() == Some("Invalid")
            && o.signature_checks.iter().any(|s| s == "Failed"),
        format!(
            "verdict {:?}, signatures {:?}, exit {:?} {}",
            o.verdict, o.signature_checks, o.exit, o.stderr_line
        ),
    );
}

/// After a signature the key must have been applied exactly once (SDK: the guard's count;
/// CLI: the report's `applied`; HTTP: the report here and the server journal in `finish`).
fn expect_applied_once(case: &mut Case<'_>, o: &Outcome) {
    let detail = format!(
        "applied {:?}, key begins {:?}, key applied {:?}",
        o.applied, o.key_begins, o.key_applied
    );
    let sdk_ok = o.key_begins.is_none_or(|b| b == 1) && o.key_applied.is_none_or(|a| a == 1);
    case.check(
        "the key was applied exactly once",
        o.applied.as_deref() == Some("Applied") && sdk_ok,
        detail,
    );
}

fn expect_not_applied(case: &mut Case<'_>, o: &Outcome) {
    let sdk_ok = o.key_begins.is_none_or(|b| b == 0) && o.key_applied.is_none_or(|a| a == 0);
    case.check(
        "the key was not applied",
        o.applied.as_deref().is_none_or(|a| a == "NotApplied") && sdk_ok,
        format!("applied {:?}, key begins {:?}", o.applied, o.key_begins),
    );
}

fn size_of(path: &Path) -> anyhow::Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

fn d(env: &Env) -> u64 {
    env.manifest.document_bytes
}

/// Where the shared (surface independent) mutated copies live.
fn shared_dir(env: &Env) -> anyhow::Result<PathBuf> {
    let dir = env.work_dir.join("shared");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

static MUTATED: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A copy of the blob with one byte changed 1 MiB before its end (in the last MiB at full size).
fn mutated_blob(env: &Env) -> anyhow::Result<(PathBuf, u64)> {
    let _once = MUTATED.lock().unwrap();
    let blob = env.doc("blob")?;
    let offset = if d(env) > 2 << 20 {
        d(env) - (1 << 20)
    } else {
        d(env) / 2
    };
    let path = shared_dir(env)?.join("blob-mutated.bin");
    if !path.exists() {
        let partial = path.with_extension("partial");
        std::fs::copy(&blob.path, &partial)?;
        let old = read_byte(&partial, offset)?;
        flip(&partial, offset, old ^ 0x5A)?;
        std::fs::rename(&partial, &path)?;
    }
    Ok((path, offset))
}

// ---------------------------------------------------------------------------- hash

pub fn hash_basic(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "hash-sha256-blob",
        "SHA-256 of the framed full-size byte stream (known length)",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let o = c.op(&Spec::new(
            Op::Hash("sha256"),
            Input::File(blob.path.clone()),
        ))?;
        expect_completed(c, "hash completed", &o);
        c.check(
            "digest equals the generator's sha256",
            o.digest.as_deref() == Some(&blob.digests.sha256),
            format!("{:?}", o.digest),
        );
        c.check(
            "bytes_in is the document size",
            o.bytes_in == Some(d(env)),
            format!("{:?}", o.bytes_in),
        );
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn hash_unknown_length(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "hash-unknown-length",
        "SHA-256 of the same stream with no declared length (stdin / chunked upload)",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let o = c.op(&Spec::new(
            Op::Hash("sha256"),
            Input::Unknown(blob.path.clone()),
        ))?;
        expect_completed(c, "hash completed", &o);
        c.check(
            "digest equals the generator's sha256",
            o.digest.as_deref() == Some(&blob.digests.sha256),
            format!("{:?}", o.digest),
        );
        c.check(
            "bytes_in is the document size",
            o.bytes_in == Some(d(env)),
            format!("{:?}", o.bytes_in),
        );
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn hash_gost(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "hash-streebog512-blob",
        "GOST R 34.11-2015 (512) digest of the byte stream",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let o = c.op(&Spec::new(Op::Hash("gost"), Input::File(blob.path.clone())))?;
        expect_completed(c, "hash completed", &o);
        c.check(
            "a 512-bit digest was produced",
            o.digest.as_ref().is_some_and(|d| d.len() == 128),
            format!("{:?}", o.digest),
        );
        c.note("digest", json!(o.digest));
        c.note("independent_oracle", json!("none: no Streebog implementation independent of the project exists on this machine; the digest is compared across surfaces by the report reader"));
        Ok(())
    }))
}

/// The SDK, CLI and server default limit on one document (docs/dev/sdk.md section 5).
fn input_limit() -> u64 {
    oncl_pki::resource::ResourceLimits::default().input_bytes
}

pub fn hash_boundaries(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "hash-u64-boundaries",
        "Digests at the 32-bit offset boundaries that fit the document size, and at the size itself (unknown-length streams)",
    )?;
    Ok(guarded(case, |c| {
        let cap = d(env);
        // The 2 GiB and 4 GiB boundaries are beyond the 1 GiB guarantee: they are hashed only
        // when --document-bytes is raised above them; otherwise the size itself and its
        // neighbour are the boundaries, and the rest are reported as skipped.
        let mut sizes = vec![
            (1u64 << 31) - 1,
            1 << 31,
            (1 << 31) + 1,
            (1 << 32) - 1,
            1 << 32,
            (1 << 32) + 1,
            cap.saturating_sub(1),
            cap,
        ];
        sizes.sort_unstable();
        sizes.dedup();
        for n in sizes {
            if n > cap {
                c.note(
                    &format!("skipped_{n}"),
                    json!("larger than --document-bytes (beyond the guaranteed document size when above 1 GiB)"),
                );
                continue;
            }
            let expected = sha256_pattern(0xA5, n);
            let o = c.op(&Spec::new(
                Op::Hash("sha256"),
                Input::Pattern { byte: 0xA5, len: n },
            ))?;
            c.check(
                &format!("{n} bytes hashed correctly"),
                o.completed && o.digest.as_deref() == Some(&expected) && o.bytes_in == Some(n),
                format!("digest {:?}, bytes_in {:?}", o.digest, o.bytes_in),
            );
        }
        c.check(
            "the document size itself is hashed correctly",
            c.checks
                .iter()
                .any(|k| k.name == format!("{cap} bytes hashed correctly") && k.ok),
            format!("--document-bytes is {cap}"),
        );
        Ok(())
    }))
}

pub fn hash_limit(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "hash-limit-plus-one",
        "limit + 1 byte of unknown length is refused without reading it all",
    )?;
    Ok(guarded(case, |c| {
        let o = c.op(&Spec::new(
            Op::Hash("sha256"),
            Input::Pattern {
                byte: 0x3C,
                len: input_limit() + 1,
            },
        ))?;
        let proc = c.procs.last().cloned();
        let typed = refused(&o, "InputLimit");
        // Over HTTP the server may close the connection while the client still uploads: the
        // documented outcome is then a transport failure, `NotApplied` (docs/user/cli.md).
        let transport =
            target == Target::Http && !o.completed && o.applied.as_deref() == Some("NotApplied");
        c.check(
            "the document over the limit is refused, nothing applied",
            typed || transport,
            format!(
                "exit {:?}, code {:?}, applied {:?} {}",
                o.exit, o.code, o.applied, o.stderr_line
            ),
        );
        c.note("typed_input_limit", json!(typed));
        if let Some(p) = proc {
            c.note("refusal_seconds", json!(p.wall_seconds));
        }
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

// ---------------------------------------------------------------------------- CMS

pub fn cms_detached(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "cms-detached",
        "CMS detached signature of the full-size stream: sign, verify, OpenSSL, tampered copy",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let sig = c.work.join("blob.p7s");
        let o =
            c.op(&Spec::new(Op::Sign(Profile::Cms), Input::File(blob.path.clone())).output(&sig))?;
        expect_completed(c, "sign completed", &o);
        expect_applied_once(c, &o);
        c.check(
            "bytes_in is the document size",
            o.bytes_in == Some(d(env)),
            format!("{:?}", o.bytes_in),
        );
        c.check(
            "the signature is small",
            size_of(&sig).is_ok_and(|n| n > 0 && n < 65536),
            format!("{:?}", size_of(&sig)),
        );
        let v = c.op(
            &Spec::new(Op::Verify(Profile::Cms), Input::File(sig.clone())).detached(&blob.path),
        )?;
        expect_valid(c, "verify is Valid", &v);
        let nul = c.work.join("oracle.out");
        let ok = openssl_cms_signature(&sig, Some(&blob.path), &nul)?;
        c.check(
            "OpenSSL verifies the signature over the full-size content (independent)",
            ok,
            "openssl cms -verify -noverify -binary",
        );
        let (mutated, offset) = mutated_blob(env)?;
        let v = c.op(
            &Spec::new(Op::Verify(Profile::Cms), Input::File(sig.clone())).detached(&mutated),
        )?;
        expect_invalid(
            c,
            &format!("a one-byte change at offset {offset} makes it Invalid"),
            &v,
        );
        let ok = openssl_cms_signature(&sig, Some(&mutated), &nul)?;
        c.check("OpenSSL also rejects the changed copy", !ok, "");
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn cms_attached(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "cms-attached",
        "CMS attached signature: output above the document size, read back by extract and verify",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let p7m = c.work.join("blob.p7m");
        let o = c.op(
            &Spec::new(Op::Sign(Profile::Cms), Input::File(blob.path.clone()))
                .output(&p7m)
                .attached(),
        )?;
        expect_completed(c, "sign completed", &o);
        expect_applied_once(c, &o);
        let out_len = size_of(&p7m)?;
        c.check(
            "the output is larger than the document (container surcharge)",
            out_len > d(env),
            format!("{out_len} bytes for {} bytes", d(env)),
        );
        c.check(
            "bytes_out is the file size",
            o.bytes_out.is_none_or(|b| b == out_len),
            format!("{:?} vs {out_len}", o.bytes_out),
        );
        c.note("surcharge_bytes", json!(out_len.saturating_sub(d(env))));
        let v = c.op(&Spec::new(
            Op::Verify(Profile::Cms),
            Input::File(p7m.clone()),
        ))?;
        expect_valid(c, "verifying the over-limit output is Valid", &v);
        let extracted = c.work.join("extracted.bin");
        let e = c.op(&Spec::new(Op::Extract, Input::File(p7m.clone())).output(&extracted))?;
        expect_completed(c, "extract completed", &e);
        let (sha, len) = sha256_file(&extracted)?;
        c.check(
            "the extracted content is the original document",
            sha == blob.digests.sha256 && len == d(env),
            format!("{sha} {len}"),
        );
        let _ = std::fs::remove_file(&extracted);
        if size_of(&p7m)? < i32::MAX as u64 {
            let oracle_out = c.work.join("oracle-content.bin");
            let ok = openssl_cms_signature(&p7m, None, &oracle_out)?;
            c.check(
                "OpenSSL verifies the attached signature (independent)",
                ok,
                "",
            );
            if ok {
                let (sha, len) = sha256_file(&oracle_out)?;
                c.check(
                    "OpenSSL's content is the original document",
                    sha == blob.digests.sha256 && len == d(env),
                    sha,
                );
            }
            let _ = std::fs::remove_file(&oracle_out);
        } else {
            // OpenSSL 3.5.4 `cms -verify` refuses a DER container of 2 GiB or more
            // ("asn1_d2i_read_bio: too long", crypto/asn1/a_d2i_fp.c: length above INT_MAX).
            // The independent check is decomposed: the content digest (hashlib) equals the
            // signed messageDigest and the RSA signature over the signedAttrs verifies
            // (asn1crypto + cryptography).
            match c.env.oracle(&[
                "cms-attached-check".as_ref(),
                p7m.as_os_str(),
                blob.digests.sha256.as_ref(),
            ]) {
                Ok(v) => {
                    c.check("decomposed independent check: content digest = signed messageDigest = original, RSA signature verifies (hashlib + asn1crypto + cryptography; OpenSSL cannot read >= 2 GiB DER)", v["ok"] == true, v.to_string());
                    c.note("independent_cms_attached", v);
                }
                Err(e) => c.check("decomposed independent CMS check", false, format!("{e:#}")),
            }
        }
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn cms_gost(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "cms-gost2015",
        "CMS detached signature with the GOST R 34.10-2015 key",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let sig = c.work.join("gost.p7s");
        let o = c.op(
            &Spec::new(Op::Sign(Profile::Cms), Input::File(blob.path.clone()))
                .output(&sig)
                .gost(),
        )?;
        expect_completed(c, "sign completed", &o);
        expect_applied_once(c, &o);
        let v = c.op(
            &Spec::new(Op::Verify(Profile::Cms), Input::File(sig.clone())).detached(&blob.path),
        )?;
        expect_valid(c, "verify is Valid", &v);
        let (mutated, _) = mutated_blob(env)?;
        let v = c.op(
            &Spec::new(Op::Verify(Profile::Cms), Input::File(sig.clone())).detached(&mutated),
        )?;
        expect_invalid(c, "the changed copy is Invalid", &v);
        c.note("independent_oracle", json!("none: no GOST R 34.10-2015 implementation independent of the project exists on this machine (OpenSSL has no GOST provider here)"));
        Ok(())
    }))
}

pub fn cms_limit(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "cms-sign-limit-plus-one",
        "signing limit + 1 byte of unknown length is refused before any key use",
    )?;
    Ok(guarded(case, |c| {
        let sig = c.work.join("limit.p7s");
        let o = c.op(&Spec::new(
            Op::Sign(Profile::Cms),
            Input::Pattern {
                byte: 0x3C,
                len: input_limit() + 1,
            },
        )
        .output(&sig))?;
        let typed = refused(&o, "InputLimit");
        let transport =
            target == Target::Http && !o.completed && o.applied.as_deref() == Some("NotApplied");
        c.check(
            "refused with the key never applied",
            typed || transport,
            format!(
                "code {:?}, applied {:?} {}",
                o.code, o.applied, o.stderr_line
            ),
        );
        expect_not_applied(c, &o);
        c.check("no signature file was published", !sig.exists(), "");
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn cms_output_limit(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "cms-attached-output-limit",
        "an attached result over the output limit is refused, nothing published",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let p7m = c.work.join("limited.p7m");
        let mut spec = Spec::new(Op::Sign(Profile::Cms), Input::File(blob.path.clone()))
            .output(&p7m)
            .attached();
        // one byte below what the container needs
        spec.output_limit = Some(d(env));
        let o = c.op(&spec)?;
        c.check(
            "refused with an output limit",
            !o.completed
                && o.code
                    .as_deref()
                    .is_some_and(|code| code.contains("OutputLimit")),
            format!(
                "code {:?}, applied {:?} {}",
                o.code, o.applied, o.stderr_line
            ),
        );
        c.note("applied_after_output_limit", json!(o.applied));
        c.check("no result file was published", !p7m.exists(), "");
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

// ---------------------------------------------------------------------------- XML

fn xml_independent(
    c: &mut Case<'_>,
    signed: &Path,
    set: &DataSet,
    mode: &str,
) -> anyhow::Result<()> {
    let manifest = c.env.data_dir.join("manifest.json");
    let v = c.env.oracle(&[
        "xml-signature".as_ref(),
        signed.as_os_str(),
        manifest.as_os_str(),
        set.name.as_ref(),
        mode.as_ref(),
        "rsa".as_ref(),
    ]);
    match v {
        Ok(v) => {
            c.check(
                "independent check: digests equal the generator's canonical digests, RSA signature verifies (lxml + cryptography)",
                v["ok"].as_bool() == Some(true),
                v.to_string(),
            );
            c.note("independent_xml_signature", v);
        }
        Err(e) => c.check("independent XML signature check", false, format!("{e:#}")),
    }
    Ok(())
}

fn xml_set<'a>(
    env: &'a Env,
    name: &str,
) -> anyhow::Result<(&'a DataSet, &'a crate::platform::generate::xml::XmlFacts)> {
    let set = env.doc(name)?;
    match &set.facts {
        Facts::Xml(f) => Ok((set, f)),
        _ => bail!("{name} is not XML"),
    }
}

/// One signed-XML scenario of the matrix.
struct XmlScenario<'a> {
    id: &'a str,
    title: &'a str,
    set_name: &'a str,
    profile: Profile,
    target_id: Option<&'a str>,
    mode: &'a str,
    gost: bool,
}

fn xml_signed_case(
    env: &Env,
    target: Target,
    scenario: XmlScenario<'_>,
) -> anyhow::Result<CaseResult> {
    let XmlScenario {
        id,
        title,
        set_name,
        profile,
        target_id,
        mode,
        gost,
    } = scenario;
    let case = Case::new(env, target, id, title)?;
    Ok(guarded(case, |c| {
        let (set, facts) = xml_set(env, set_name)?;
        let signed = c.work.join("signed.xml");
        let mut spec = Spec::new(Op::Sign(profile), Input::File(set.path.clone())).output(&signed);
        if let Some(t) = target_id {
            spec = spec.target(t);
        }
        if gost {
            spec = spec.gost();
        }
        let o = c.op(&spec)?;
        expect_completed(c, "sign completed", &o);
        expect_applied_once(c, &o);
        c.check(
            "bytes_in is the document size",
            o.bytes_in == Some(d(env)),
            format!("{:?}", o.bytes_in),
        );
        let out_len = size_of(&signed)?;
        c.note("output_bytes", json!(out_len));
        c.check(
            "only a bounded signature was added",
            out_len > d(env) && out_len - d(env) < (1 << 20),
            format!("{} extra bytes", out_len as i64 - d(env) as i64),
        );
        if !gost {
            xml_independent(c, &signed, set, mode)?;
        }
        let verify_profile = if matches!(profile, Profile::Wsse) {
            Profile::Wsse
        } else {
            Profile::Xml
        };
        let v = c.op(&Spec::new(
            Op::Verify(verify_profile),
            Input::File(signed.clone()),
        ))?;
        expect_valid(c, "verify is Valid", &v);
        if let (Some(id), Target::Sdk) = (target_id, target) {
            let element = facts.elements.iter().find(|e| e.id == id);
            if let Some(e) = element {
                c.check(
                    "the reference targeted exactly the element's source span (XmlReferenceResult.target is a source Region, not a canonical length; the canonical digest is checked by the independent oracle)",
                    v.reference_lens.first() == Some(&(e.end - e.start)),
                    format!("{:?} vs source span {} (canonical {})", v.reference_lens, e.end - e.start, e.canonical_len),
                );
                c.check(
                    "the referenced element starts in the second half of the document (after 4 GiB only when --document-bytes is above 8 GiB)",
                    e.start >= d(env) / 2,
                    format!("start {}", e.start),
                );
            }
        }
        // tamper: a signed byte after the half of the document, then an unsigned byte
        let shift = if profile == Profile::Wsse {
            out_len - d(env)
        } else {
            0
        };
        let far = facts.far_tamper_offset + shift;
        let old = read_byte(&signed, far)?;
        c.check(
            "the tamper position holds the generator's byte",
            old == facts.far_tamper_byte,
            format!("offset {far}"),
        );
        flip(&signed, far, other_byte(old))?;
        let v = c.op(&Spec::new(
            Op::Verify(verify_profile),
            Input::File(signed.clone()),
        ))?;
        expect_invalid(
            c,
            &format!("a signed byte changed at offset {far} makes it Invalid"),
            &v,
        );
        flip(&signed, far, old)?;
        // one more full verification pass per surface is pure repetition: the SDK surface shows
        // that a change outside the signed element leaves the signature intact
        if target_id.is_some() && target == Target::Sdk {
            let un =
                facts.uncovered_tamper_offset + if profile == Profile::Wsse { shift } else { 0 };
            let old = read_byte(&signed, un)?;
            flip(&signed, un, other_byte(old))?;
            let v = c.op(&Spec::new(
                Op::Verify(verify_profile),
                Input::File(signed.clone()),
            ))?;
            c.check(
                "an unsigned byte changed leaves the signature intact",
                v.completed && v.signature_checks.iter().all(|s| s == "Passed"),
                format!(
                    "verdict {:?}, signatures {:?}",
                    v.verdict, v.signature_checks
                ),
            );
            flip(&signed, un, old)?;
        }
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn xml_far(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    xml_signed_case(
        env,
        target,
        XmlScenario {
            id: "xml-far-reference",
            title: "XMLDSig over an Id'd element that starts after the first half of the full-size XML",
            set_name: "xml-archive",
            profile: Profile::Xml,
            target_id: Some("section-2"),
            mode: "archive-end",
            gost: false,
        },
    )
}

pub fn xml_whole(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    xml_signed_case(
        env,
        target,
        XmlScenario {
            id: "xml-whole-document",
            title: "enveloped XMLDSig over the whole full-size document",
            set_name: "xml-archive",
            profile: Profile::Xml,
            target_id: None,
            mode: "archive-end",
            gost: false,
        },
    )
}

pub fn xml_gost(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    xml_signed_case(
        env,
        target,
        XmlScenario {
            id: "xml-far-gost2015",
            title: "XMLDSig with the GOST-2015 key over the far element",
            set_name: "xml-archive",
            profile: Profile::Xml,
            target_id: Some("section-2"),
            mode: "archive-end",
            gost: true,
        },
    )
}

pub fn wsse(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    xml_signed_case(
        env,
        target,
        XmlScenario {
            id: "wsse-body",
            title: "WS-Security signature of a SOAP Body that starts in the second half of the document",
            set_name: "xml-soap",
            profile: Profile::Wsse,
            target_id: None,
            mode: "wsse",
            gost: false,
        },
    )
}

pub fn xml_unknown_length(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "xml-unknown-length",
        "XML signed from a stream of unknown length (stdin / chunked upload)",
    )?;
    Ok(guarded(case, |c| {
        let (set, _) = xml_set(env, "xml-archive")?;
        let signed = c.work.join("signed.xml");
        let o = c.op(
            &Spec::new(Op::Sign(Profile::Xml), Input::Unknown(set.path.clone()))
                .target("section-2")
                .output(&signed),
        )?;
        expect_completed(c, "sign completed", &o);
        expect_applied_once(c, &o);
        xml_independent(c, &signed, set, "archive-end")?;
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn xml_cancel(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "xml-cancel",
        "cancellation in the middle of a signing: no key use, no result, no leftover",
    )?;
    Ok(guarded(case, |c| {
        let (set, _) = xml_set(env, "xml-archive")?;
        let signed = c.work.join("cancelled.xml");
        let mut spec = Spec::new(Op::Sign(Profile::Xml), Input::File(set.path.clone()))
            .target("section-2")
            .output(&signed);
        if target == Target::Http {
            c.expect_begins = Some(0);
        }
        spec.cancel = match target {
            Target::Sdk => Cancel::SdkAfterBytes(d(env) / 4),
            _ => Cancel::WhenScratchBytes((d(env) / 16).max(1 << 20)),
        };
        let o = c.op(&spec)?;
        let cancelled = match target {
            Target::Sdk => !o.completed && o.code.as_deref() == Some("Cancelled"),
            _ => o.exit == Some(130),
        };
        c.check(
            "the operation ended as cancelled",
            cancelled,
            format!("exit {:?}, code {:?} {}", o.exit, o.code, o.stderr_line),
        );
        c.check(
            "no key application was reported",
            o.applied.as_deref().is_none_or(|a| a == "NotApplied")
                && o.key_begins.is_none_or(|b| b == 0),
            format!("applied {:?}", o.applied),
        );
        c.check("no result was published", !signed.exists(), "");
        if target == Target::Http {
            // the server notices the closed connection and releases its spool
            let started = std::time::Instant::now();
            loop {
                let (_, files) = crate::platform::measure::tree_usage(&c.scratch);
                if files == 0 || started.elapsed().as_secs() > 300 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn xml_temp_limit(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "xml-temp-quota",
        "a temporary-store quota too small for the operation is refused before any key use",
    )?;
    Ok(guarded(case, |c| {
        let (set, _) = xml_set(env, "xml-archive")?;
        let signed = c.work.join("quota.xml");
        let mut spec = Spec::new(Op::Sign(Profile::Xml), Input::File(set.path.clone()))
            .target("section-2")
            .output(&signed);
        // meaningful only when the document is larger than the quota: an eighth of it, which the
        // far element's canonical staging (about half the document) exceeds before any key use
        let quota = (d(env) / 8).max(1 << 20);
        spec.temp_limit = Some(quota);
        c.note("quota_bytes", json!(quota));
        c.check(
            "the document is larger than the quota",
            d(env) > quota,
            format!("{} > {quota}", d(env)),
        );
        if target == Target::Http {
            c.server_settings.temp_per_operation = quota;
            c.server_settings.total_temp = quota;
            c.expect_begins = Some(0);
        }
        let o = c.op(&spec)?;
        // Over HTTP the server may close the connection while the client still uploads: the
        // documented outcome is then a transport failure, NotApplied; the audit journal then
        // proves that no key was used (`expect_begins`).
        let transport =
            target == Target::Http && !o.completed && o.code.as_deref() == Some("TransportFailed");
        c.check(
            "refused with a temporary-disk limit",
            !o.completed
                && (transport
                    || o.code
                        .as_deref()
                        .is_some_and(|code| code.contains("TempLimit") || code.contains("Limit"))),
            format!(
                "code {:?}, applied {:?} {}",
                o.code, o.applied, o.stderr_line
            ),
        );
        expect_not_applied(c, &o);
        c.check("no result was published", !signed.exists(), "");
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

// ---------------------------------------------------------------------------- PDF

fn pdf_independent(
    c: &mut Case<'_>,
    signed: &Path,
    set: &DataSet,
    pyhanko: bool,
) -> anyhow::Result<()> {
    let manifest = c.env.data_dir.join("manifest.json");
    match c.env.oracle(&[
        "pdf-signature".as_ref(),
        signed.as_os_str(),
        manifest.as_os_str(),
        set.name.as_ref(),
        "rsa".as_ref(),
    ]) {
        Ok(v) => {
            c.check(
                "independent check: ByteRange arithmetic, digest of the covered bytes, RSA signature, untouched original bytes (hashlib + asn1crypto + cryptography)",
                v["ok"].as_bool() == Some(true),
                v.to_string(),
            );
            c.note("independent_pdf_signature", v);
        }
        Err(e) => c.check("independent PDF signature check", false, format!("{e:#}")),
    }
    if pyhanko {
        match c.env.oracle(&["pdf-pyhanko".as_ref(), signed.as_os_str()]) {
            Ok(v) => {
                c.check(
                    "pyHanko validates the signature's integrity",
                    v["ok"].as_bool() == Some(true),
                    v.to_string(),
                );
                c.note("pyhanko", v);
            }
            Err(e) => c.check("pyHanko integrity validation", false, format!("{e:#}")),
        }
    }
    Ok(())
}

pub fn pdf_case(
    env: &Env,
    target: Target,
    set_name: &str,
    profile: Profile,
    id: &str,
    title: &str,
) -> anyhow::Result<CaseResult> {
    let case = Case::new(env, target, id, title)?;
    Ok(guarded(case, |c| {
        let set = env.doc(set_name)?;
        let facts = match &set.facts {
            Facts::Pdf(f) => f,
            _ => bail!("{set_name} is not a PDF"),
        };
        let signed = c.work.join("signed.pdf");
        let o =
            c.op(&Spec::new(Op::Sign(profile), Input::File(set.path.clone())).output(&signed))?;
        expect_completed(c, "sign completed", &o);
        expect_applied_once(c, &o);
        let out_len = size_of(&signed)?;
        c.check(
            "the incremental update is bounded",
            out_len > d(env) && out_len - d(env) < (1 << 20),
            format!("{} extra bytes", out_len as i64 - d(env) as i64),
        );
        pdf_independent(c, &signed, set, true)?;
        let v = c.op(&Spec::new(Op::Verify(profile), Input::File(signed.clone())))?;
        expect_valid(c, "verify is Valid", &v);
        // a covered byte inside the embedded file, far into the document
        let covered = facts.embedded_offset + facts.embedded_len / 2;
        let old = read_byte(&signed, covered)?;
        flip(&signed, covered, old ^ 0x5A)?;
        let v = c.op(&Spec::new(Op::Verify(profile), Input::File(signed.clone())))?;
        expect_invalid(
            c,
            &format!("a covered byte changed at offset {covered} makes it Invalid"),
            &v,
        );
        flip(&signed, covered, old)?;
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

// ---------------------------------------------------------------------------- evidence levels

use super::exec::Level;

/// T sign, then keyless LT and LTA extension, verifying every level.
/// Inputs of one T -> LT -> LTA chain.
struct Chain<'a> {
    profile: fn(Level) -> Profile,
    format: &'static str,
    input: &'a Path,
    detached: Option<&'a Path>,
    first: &'a Path,
    target_id: Option<&'a str>,
    extension: &'a str,
}

fn level_chain(c: &mut Case<'_>, chain: Chain<'_>) -> anyhow::Result<Vec<PathBuf>> {
    let Chain {
        profile,
        format,
        input,
        detached,
        first,
        target_id,
        extension,
    } = chain;
    let mut sign =
        Spec::new(Op::Sign(profile(Level::T)), Input::File(input.to_owned())).output(first);
    if let Some(t) = target_id {
        sign = sign.target(t);
    }
    let o = c.op(&sign)?;
    expect_completed(c, "T level sign completed", &o);
    expect_applied_once(c, &o);
    let mut verify = Spec::new(Op::Verify(profile(Level::T)), Input::File(first.to_owned()));
    if let Some(d) = detached {
        verify = verify.detached(d);
    }
    let v = c.op(&verify)?;
    expect_valid(c, "T level verifies as Valid", &v);
    let mut outputs = vec![first.to_owned()];
    let mut previous = first.to_owned();
    for level in [Level::Lt, Level::Lta] {
        let next = c.work.join(format!("level-{}.{extension}", level.text()));
        let mut extend =
            Spec::new(Op::Extend(format, level), Input::File(previous.clone())).output(&next);
        if let Some(d) = detached {
            extend = extend.detached(d);
        }
        let o = c.op(&extend)?;
        expect_completed(
            c,
            &format!("keyless extension to {} completed", level.text()),
            &o,
        );
        c.check(
            &format!("extension to {} used no private key", level.text()),
            o.applied.as_deref().is_none_or(|a| a == "NotApplied")
                && o.key_begins.is_none_or(|b| b == 0),
            format!("applied {:?}", o.applied),
        );
        let mut verify = Spec::new(Op::Verify(profile(level)), Input::File(next.clone()));
        if let Some(d) = detached {
            verify = verify.detached(d);
        }
        let v = c.op(&verify)?;
        expect_valid(c, &format!("{} verifies as Valid", level.text()), &v);
        if previous != *first {
            let _ = std::fs::remove_file(&previous);
        }
        previous = next.clone();
        outputs.push(next);
    }
    Ok(outputs)
}

pub fn cades_levels(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "cades-levels",
        "CAdES-T signature of the full-size stream, keyless extension to LT and LTA, every level verified",
    )?;
    Ok(guarded(case, |c| {
        let blob = env.doc("blob")?;
        let first = c.work.join("level-t.p7s");
        let outputs = level_chain(
            c,
            Chain {
                profile: Profile::Cades,
                format: "cms",
                input: &blob.path,
                detached: Some(&blob.path),
                first: &first,
                target_id: None,
                extension: "p7s",
            },
        )?;
        let last = outputs.last().context("outputs")?;
        let nul = c.work.join("oracle.out");
        c.check(
            "OpenSSL verifies the signature of the LTA container over the full-size content (independent)",
            openssl_cms_signature(last, Some(&blob.path), &nul)?,
            "openssl cms -verify -noverify",
        );
        let (mutated, _) = mutated_blob(env)?;
        let v = c.op(&Spec::new(
            Op::Verify(Profile::Cades(Level::Lta)),
            Input::File(last.clone()),
        )
        .detached(&mutated))?;
        c.check(
            "the LTA container does not verify against the changed document",
            v.completed && v.verdict.as_deref() != Some("Valid"),
            format!("verdict {:?}", v.verdict),
        );
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn pades_levels(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "pades-levels",
        "PAdES-T signature of the large-page full-size PDF, keyless extension to LT and LTA, every level verified",
    )?;
    // docs/user/http-api.md: PAdES LT/LTA need about 380-600 MiB of per-operation memory
    case.server_settings.memory_per_operation = 640 << 20;
    case.server_settings.total_memory = 1280 << 20;
    Ok(guarded(case, |c| {
        let set = env.doc("pdf-compact")?;
        let first = c.work.join("level-t.pdf");
        let outputs = level_chain(
            c,
            Chain {
                profile: Profile::Pades,
                format: "pdf",
                input: &set.path,
                detached: None,
                first: &first,
                target_id: None,
                extension: "pdf",
            },
        )?;
        // pyHanko cannot read the GOST digest of the loopback TSA's timestamp token, so the
        // timestamped levels get only the hashlib/asn1crypto/cryptography check
        pdf_independent(c, outputs.first().context("outputs")?, set, false)?;
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}

pub fn xades_levels(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let case = Case::new(
        env,
        target,
        "xades-levels",
        "XAdES-T over the far element of the full-size XML, keyless extension to LT and LTA, every level verified",
    )?;
    Ok(guarded(case, |c| {
        let (set, _) = xml_set(env, "xml-archive")?;
        let first = c.work.join("level-t.xml");
        let outputs = level_chain(
            c,
            Chain {
                profile: Profile::Xades,
                format: "xml",
                input: &set.path,
                detached: None,
                first: &first,
                target_id: Some("section-2"),
                extension: "xml",
            },
        )?;
        xml_independent(c, outputs.first().context("outputs")?, set, "archive-end")?;
        c.check_scratch_clean("scratch is empty afterwards");
        Ok(())
    }))
}
