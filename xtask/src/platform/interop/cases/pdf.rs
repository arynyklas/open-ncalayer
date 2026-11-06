//! PDF / PAdES: `/pdf/sign`, `/pdf/verify`, `/pdf/extend`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};

use super::super::oncl::{INVALID, VALID, Verified, path_str};
use super::super::world::{NOW, Profile};
use super::super::{Case, Ctx, Observed};
use super::common::{
    NC_CHAIN_INCOMPLETE, NC_EXPIRED, NC_REJECTED, b64, evidence_args, grade, nc_key, signer_grades,
    trust_summary, tsa_args, unb64,
};

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for profile in Profile::ALL {
        cases.push(Case::new(
            format!("pdf-sign-{}", profile.label()),
            move |ctx| ours_signs(ctx, profile, "pdf"),
        ));
        cases.push(Case::new(
            format!("pdf-tamper-{}", profile.label()),
            move |ctx| tampered(ctx, profile),
        ));
        cases.push(Case::new(
            format!("pdf-second-signature-{}", profile.label()),
            move |ctx| second_signature(ctx, profile),
        ));
        for level in ["b", "t", "lt", "lta"] {
            cases.push(Case::new(
                format!("pades-sign-{}-{level}", profile.label()),
                move |ctx| ours_signs(ctx, profile, &format!("pades-{level}")),
            ));
        }
        cases.push(Case::new(
            format!("pades-extend-ours-{}", profile.label()),
            move |ctx| extend_ours(ctx, profile),
        ));
        for level in ["b", "t", "lt"] {
            cases.push(Case::new(
                format!("pdf-verify-ncanode-{}-{level}", profile.label()),
                move |ctx| oracle_signs(ctx, profile, level),
            ));
        }
        for level in ["t", "lt", "lta"] {
            cases.push(Case::new(
                format!("pdf-extend-ncanode-{}-{level}", profile.label()),
                move |ctx| extend_ncanode(ctx, profile, level),
            ));
        }
    }
    for level in ["b", "t", "lt", "lta"] {
        cases.push(Case::new(
            format!("pdf-verify-fixture-{level}"),
            move |ctx| fixture(ctx, level),
        ));
    }
    cases
}

/// The fixture document: NCANode's `sample.pdf`.
fn sample(ctx: &Ctx) -> anyhow::Result<PathBuf> {
    let bytes = std::fs::read(crate::fetch::ncanode_dir().join("sample.pdf"))
        .context("run `cargo xtask fetch-fixtures`")?;
    ctx.write("sample.pdf", &bytes)
}

fn ours_verify(ctx: &Ctx, profile: &str, file: &Path) -> anyhow::Result<Verified> {
    ctx.oncl.verify(&ctx.world, profile, file, &[] as &[&str])
}

/// NCANode's `/pdf/verify`: `(HTTP status, grades of the signers, levels, whole answer)`.
fn nc_verify(ctx: &mut Ctx, pdf: &[u8]) -> anyhow::Result<(u16, Vec<String>, Vec<String>, Value)> {
    let (status, answer) = ctx.nc_post("/pdf/verify", &json!({ "pdf": b64(pdf) }))?;
    let grades = signer_grades(&answer);
    let levels = answer["signers"]
        .as_array()
        .map(|s| {
            s.iter()
                .map(|x| x["adesLevel"].as_str().unwrap_or("none").to_owned())
                .collect()
        })
        .unwrap_or_default();
    Ok((status, grades, levels, answer))
}

/// The independent decomposition of a PDF's signatures (ByteRange, digest, CMS).
fn byterange(ctx: &Ctx, file: &Path) -> anyhow::Result<Value> {
    ctx.py_json(&["pdf-byterange".to_owned(), path_str(file)?.to_owned()])
}

/// pyHanko's judgement under our root at the matrix's instant.
fn pyhanko(ctx: &Ctx, file: &Path) -> anyhow::Result<Value> {
    ctx.py_json(&[
        "pdf-verify".to_owned(),
        path_str(file)?.to_owned(),
        "--root".to_owned(),
        path_str(&ctx.world.root)?.to_owned(),
        "--at".to_owned(),
        NOW.to_string(),
    ])
}

fn level_of(report: &Verified) -> String {
    report.report["ades_level"]
        .as_str()
        .unwrap_or("none")
        .to_owned()
}

/// Our PDF signature (`pdf` or `pades-<level>`), judged by us, NCANode, the independent
/// ByteRange decomposition and (RSA) pyHanko.
fn ours_signs(ctx: &mut Ctx, profile: Profile, kind: &str) -> anyhow::Result<Observed> {
    let input = sample(ctx)?;
    let signed = ctx.file("signed.pdf");
    let level = kind.strip_prefix("pades-");
    let mut extra: Vec<String> = Vec::new();
    if matches!(level, Some("t" | "lt" | "lta")) {
        extra.extend(tsa_args(ctx));
    }
    if matches!(level, Some("lt" | "lta")) {
        extra.extend(evidence_args(ctx, ctx.world.signer(profile))?);
    }
    ctx.oncl.sign(
        &ctx.world,
        kind,
        ctx.world.signer(profile),
        &input,
        &signed,
        &extra,
    )?;
    let ours = ours_verify(ctx, kind, &signed)?;
    ensure!(
        ours.code() == Some(VALID) && ours.check(0, "signature") == "Passed",
        "our verification of `{kind}`: {}",
        ours.summary()
    );
    let bytes = std::fs::read(&signed)?;
    let (status, grades, levels, answer) = nc_verify(ctx, &bytes)?;
    ensure!(
        status == 200 && grades == [NC_CHAIN_INCOMPLETE],
        "NCANode: HTTP {status} {grades:?} {answer}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        (
            "ours",
            format!("{}/level={}", ours.verdict(), level_of(&ours)),
        ),
        ("ncanode", format!("{}/level={}", grades[0], levels[0])),
    ];
    let decomposition = byterange(ctx, &signed)?;
    ensure!(
        decomposition["ok"] == true,
        "ByteRange decomposition: {decomposition}"
    );
    verdicts.push((
        "byterange",
        format!(
            "{}x digest=ok subfilter={}",
            decomposition["signatures"].as_array().map_or(0, Vec::len),
            decomposition["signatures"][0]["subfilter"]
                .as_str()
                .unwrap_or("?")
        ),
    ));
    if profile == Profile::Rsa {
        let hanko = pyhanko(ctx, &signed)?;
        ensure!(hanko["ok"] == true, "pyHanko: {hanko}");
        verdicts.push((
            "pyhanko",
            format!(
                "trusted dss={} doc-timestamps={}",
                hanko["dss"].is_object(),
                hanko["doc_timestamps"]
            ),
        ));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {} level {}", grades[0], levels[0]),
        detail: String::new(),
    })
}

/// A counterexample: one byte inside the signed ByteRange altered.
fn tampered(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let input = sample(ctx)?;
    let signed = ctx.file("signed.pdf");
    ctx.oncl.sign(
        &ctx.world,
        "pdf",
        ctx.world.signer(profile),
        &input,
        &signed,
        &[] as &[&str],
    )?;
    let mut bytes = std::fs::read(&signed)?;
    // The middle of the first range: inside the document's own bytes, before the signature
    // dictionary, so that the structure (xref offsets, lengths) is unchanged.
    let at = bytes.len() / 4;
    bytes[at] ^= 0x01;
    let bad = ctx.write("tampered.pdf", &bytes)?;
    let ours = ours_verify(ctx, "pdf", &bad)?;
    ensure!(
        ours.code() == Some(INVALID),
        "our verification of the altered PDF: {}",
        ours.summary()
    );
    let (status, grades, _, answer) = nc_verify(ctx, &bytes)?;
    // NCANode rejects the altered PDF either as a graded signature or, when the message
    // digest attribute no longer matches, with a verification error and no grade.
    let nc = if status == 200 && grades == [NC_REJECTED] {
        NC_REJECTED.to_owned()
    } else if status == 200
        && answer["valid"] == false
        && answer["signers"][0]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("content hash found in signed attributes different"))
    {
        "VerifyError/content-hash-differs".to_owned()
    } else {
        bail!("NCANode on the altered PDF: HTTP {status} {grades:?} {answer}");
    };
    let decomposition = byterange(ctx, &bad)?;
    // GOST 34.11-94 (GOST 2004) has no independent implementation here: its digest is
    // undetermined (`null`), judged by NCANode only.
    ensure!(
        decomposition["signatures"][0]["digest_ok"] != true,
        "the independent ByteRange digest accepted the altered PDF: {decomposition}"
    );
    let decomposed = if decomposition["signatures"][0]["digest_ok"] == false {
        "digest-mismatch"
    } else {
        "digest-undetermined"
    };
    let mut verdicts = vec![
        ("crypto", "failure".to_owned()),
        (
            "ours",
            format!("{}/{}", ours.verdict(), ours.check(0, "signature")),
        ),
        ("ncanode", nc.clone()),
        ("byterange", decomposed.to_owned()),
    ];
    if profile == Profile::Rsa {
        let hanko = pyhanko(ctx, &bad)?;
        ensure!(
            hanko["ok"] == false && hanko["signatures"][0]["intact"] == false,
            "pyHanko accepted the altered PDF: {hanko}"
        );
        verdicts.push(("pyhanko", "not-intact".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {nc}"),
        detail: String::new(),
    })
}

/// A second signature (an incremental revision): two signers, each valid.
fn second_signature(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let input = sample(ctx)?;
    let first = ctx.file("first.pdf");
    let second = ctx.file("second.pdf");
    ctx.oncl.sign(
        &ctx.world,
        "pdf",
        ctx.world.signer(Profile::Rsa),
        &input,
        &first,
        &[] as &[&str],
    )?;
    ctx.oncl.sign(
        &ctx.world,
        "pdf",
        ctx.world.signer(profile),
        &first,
        &second,
        &[] as &[&str],
    )?;
    let ours = ours_verify(ctx, "pdf", &second)?;
    ensure!(
        ours.code() == Some(VALID)
            && ours.signers().len() == 2
            && ours.check(0, "signature") == "Passed"
            && ours.check(1, "signature") == "Passed",
        "our verification of the two-signature PDF: {}",
        ours.summary()
    );
    let bytes = std::fs::read(&second)?;
    let (status, grades, _, answer) = nc_verify(ctx, &bytes)?;
    ensure!(
        status == 200 && grades == [NC_CHAIN_INCOMPLETE, NC_CHAIN_INCOMPLETE],
        "NCANode: HTTP {status} {grades:?} {answer}"
    );
    let decomposition = byterange(ctx, &second)?;
    ensure!(
        decomposition["ok"] == true
            && decomposition["signatures"].as_array().map(Vec::len) == Some(2),
        "ByteRange decomposition: {decomposition}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours-signers", ours.signers().len().to_string()),
        ("ours", ours.verdict().to_owned()),
        ("ncanode", format!("{}+{}", grades[0], grades[1])),
        ("byterange", "2x digest=ok".to_owned()),
    ];
    if profile == Profile::Rsa {
        let hanko = pyhanko(ctx, &second)?;
        ensure!(
            hanko["ok"] == true && hanko["signatures"].as_array().map(Vec::len) == Some(2),
            "pyHanko: {hanko}"
        );
        verdicts.push(("pyhanko", "2x trusted".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}, {}", grades[0], grades[1]),
        detail: String::new(),
    })
}

/// `oncl extend --profile pdf` B -> T -> LT -> LTA.
fn extend_ours(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let input = sample(ctx)?;
    let mut current = ctx.file("step-b.pdf");
    ctx.oncl.sign(
        &ctx.world,
        "pades-b",
        ctx.world.signer(profile),
        &input,
        &current,
        &[] as &[&str],
    )?;
    let mut steps = Vec::new();
    let mut nc_steps = Vec::new();
    for level in ["t", "lt", "lta"] {
        let next = ctx.file(&format!("step-{level}.pdf"));
        let mut args = ctx.world.trust_args();
        args.extend(tsa_args(ctx));
        if level != "t" {
            args.extend(evidence_args(ctx, ctx.world.signer(profile))?);
        }
        args.extend([
            "extend".to_owned(),
            "--profile".into(),
            "pdf".into(),
            "--level".into(),
            level.into(),
            "--input".into(),
            path_str(&current)?.into(),
            "--output".into(),
            path_str(&next)?.into(),
        ]);
        let out = ctx.oncl.run(&args)?;
        ensure!(
            out.ok(),
            "oncl extend --profile pdf --level {level}: {}",
            out.brief()
        );
        let verified = ours_verify(ctx, &format!("pades-{level}"), &next)?;
        ensure!(
            verified.code() == Some(VALID),
            "our verification after extending to {level}: {}",
            verified.summary()
        );
        steps.push(level_of(&verified));
        let bytes = std::fs::read(&next)?;
        let (status, grades, levels, answer) = nc_verify(ctx, &bytes)?;
        ensure!(
            status == 200 && !grades.is_empty(),
            "NCANode after {level}: HTTP {status} {answer}"
        );
        nc_steps.push(format!("{}:{}", levels[0], grades[0]));
        current = next;
    }
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", format!("Valid@{}", steps.join("+"))),
        ("ncanode", nc_steps.join(" ")),
    ];
    let decomposition = byterange(ctx, &current)?;
    ensure!(
        decomposition["ok"] == true,
        "ByteRange decomposition: {decomposition}"
    );
    verdicts.push((
        "byterange",
        format!(
            "{}x digest=ok",
            decomposition["signatures"].as_array().map_or(0, Vec::len)
        ),
    ));
    if profile == Profile::Rsa {
        let hanko = pyhanko(ctx, &current)?;
        ensure!(hanko["ok"] == true, "pyHanko: {hanko}");
        verdicts.push((
            "pyhanko",
            format!(
                "trusted dss-certs={} doc-timestamps={}",
                hanko["dss"]["certs"], hanko["doc_timestamps"]
            ),
        ));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: format!("Valid at {}", steps.join(", ")),
        oracle: format!("NCANode {}", nc_steps.join(", ")),
        detail: String::new(),
    })
}

/// NCANode's PAdES (`/pdf/sign` at `level`), judged by us.
fn oracle_signs(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let input = sample(ctx)?;
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/pdf/sign",
        &json!({
            "pdf": b64(&std::fs::read(&input)?),
            "signers": [{ "signer": key.request(), "reason": "interop", "location": "Astana" }],
            "padesLevel": level.to_uppercase(),
            "withTsp": level != "b",
            "tsaPolicy": "TSA_GOST2015_POLICY",
        }),
    )?;
    if status != 200 {
        return Ok(Observed {
            grade: grade(&[("ncanode", format!("HTTP{status}"))]),
            ours: "not reached".to_owned(),
            oracle: format!("NCANode /pdf/sign {level}: HTTP {status} {answer}"),
            detail: String::new(),
        });
    }
    let pdf = unb64(answer["pdf"].as_str().context("no pdf in the answer")?)?;
    let path = ctx.write("ncanode.pdf", &pdf)?;
    judge_oracle_pdf(ctx, profile, level, &pdf, &path)
}

/// The tail of the rows that have us verify an oracle's PDF at `level`.
fn judge_oracle_pdf(
    ctx: &mut Ctx,
    profile: Profile,
    level: &str,
    pdf: &[u8],
    path: &Path,
) -> anyhow::Result<Observed> {
    let ours = ours_verify(ctx, &format!("pades-{level}"), path)?;
    ensure!(
        ours.check(0, "signature") == "Passed",
        "our verification of NCANode's PAdES-{level}: {}",
        ours.summary()
    );
    let (status, grades, levels, answer) = nc_verify(ctx, pdf)?;
    ensure!(
        status == 200 && !grades.is_empty(),
        "NCANode: HTTP {status} {answer}"
    );
    let decomposition = byterange(ctx, path)?;
    ensure!(
        decomposition["ok"] == true,
        "ByteRange decomposition: {decomposition}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        (
            "ours",
            format!(
                "{}/{}/ts={}/level={}",
                ours.verdict(),
                trust_summary(&ours, 0),
                ours.check(0, "timestamp"),
                level_of(&ours)
            ),
        ),
        ("ncanode", format!("{}/level={}", grades[0], levels[0])),
        (
            "byterange",
            format!(
                "{}x digest={}",
                decomposition["signatures"].as_array().map_or(0, Vec::len),
                if decomposition["signatures"]
                    .as_array()
                    .is_some_and(|s| s.iter().all(|x| x["digest_ok"] == true))
                {
                    "ok"
                } else {
                    "n/a"
                }
            ),
        ),
    ];
    if profile == Profile::Rsa && level == "b" {
        // pyHanko with the NCANode test CA unknown: integrity only.
        let hanko = pyhanko(ctx, path)?;
        let intact = hanko["signatures"][0]["intact"] == true;
        verdicts.push(("pyhanko-intact", intact.to_string()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {} level {}", grades[0], levels[0]),
        detail: String::new(),
    })
}

/// NCANode's PAdES fixtures (Kalkan, GOST): verified by us at each level.
fn fixture(ctx: &mut Ctx, level: &str) -> anyhow::Result<Observed> {
    let pdf = std::fs::read(crate::fetch::ncanode_dir().join(format!("sample-signed-{level}.pdf")))
        .context("run `cargo xtask fetch-fixtures`")?;
    let path = ctx.write("fixture.pdf", &pdf)?;
    judge_oracle_pdf(ctx, Profile::Gost2015, level, &pdf, &path)
}

/// NCANode extends our PAdES-B (`/pdf/extend`); we verify the result at that level.
fn extend_ncanode(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let input = sample(ctx)?;
    let b = ctx.file("b.pdf");
    ctx.oncl.sign(
        &ctx.world,
        "pades-b",
        ctx.world.signer(profile),
        &input,
        &b,
        &[] as &[&str],
    )?;
    let (status, answer) = ctx.nc_post(
        "/pdf/extend",
        &json!({
            "pdf": b64(&std::fs::read(&b)?),
            "padesLevel": level.to_uppercase(),
            "tsaPolicy": "TSA_GOST2015_POLICY",
        }),
    )?;
    if status != 200 {
        let message: String = answer["message"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(90)
            .collect();
        return Ok(Observed {
            grade: grade(&[("ncanode", format!("HTTP{status} {message}"))]),
            ours: "not reached".to_owned(),
            oracle: format!("NCANode /pdf/extend {level}: HTTP {status} {answer}"),
            detail: String::new(),
        });
    }
    let pdf = unb64(answer["pdf"].as_str().context("no pdf")?)?;
    let path = ctx.write("extended.pdf", &pdf)?;
    let ours = ours_verify(ctx, &format!("pades-{level}"), &path)?;
    let (nc_status, grades, levels, _) = nc_verify(ctx, &pdf)?;
    let nc = if nc_status == 200 && !grades.is_empty() {
        format!("{}/level={}", grades[0], levels[0])
    } else {
        format!("HTTP{nc_status}")
    };
    let _ = (NC_EXPIRED, evidence_args);
    Ok(Observed {
        grade: grade(&[
            (
                "ours",
                format!(
                    "{}/{}/ts={}/level={}",
                    ours.verdict(),
                    trust_summary(&ours, 0),
                    ours.check(0, "timestamp"),
                    level_of(&ours)
                ),
            ),
            ("ncanode-verify", nc),
        ]),
        ours: ours.summary(),
        oracle: format!("NCANode extended to {level}"),
        detail: String::new(),
    })
}
