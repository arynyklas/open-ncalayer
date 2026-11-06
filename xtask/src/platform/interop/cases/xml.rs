//! XML: `/xml/sign` and `/xml/verify` — XMLDSig, XAdES-B/T/LT/LTA.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};

use super::super::oncl::{INVALID, VALID, Verified, path_str};
use super::super::world::Profile;
use super::super::{Case, Ctx, Observed};
use super::common::{
    NC_CHAIN_INCOMPLETE, NC_EXPIRED, NC_REJECTED, evidence_args, grade, nc_key, trust_summary,
    tsa_args,
};

/// The document of the XML cases: declaration, default namespace, a comment, an `Id`-carrying
/// element with unordered attributes, Cyrillic text, an entity, an empty element. It has no
/// `xml:*` attribute: Kalkan's Canonical XML treats the `xml:*` attributes of omitted
/// ancestors differently from the W3C text (docs/dev/interop-ncanode.md), which a
/// libxml2-based oracle would count as a disagreement about the signature.
pub const DOC: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root xmlns=\"urn:oncl:interop\"><!-- c --><data Id=\"payload\" b=\"2\" a=\"1\">Привет &amp; hello</data><empty/></root>";

/// The document NCANode signs: [`DOC`] without the comment. Kalkan declares the
/// `...#WithComments` canonicalization on its references but digests the document without its
/// comments (an oracle quirk, `coverage.toml`): the W3C-conformant lxml oracle would then
/// disagree with the digest of a signature that Kalkan and we both accept.
pub const DOC_NC: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root xmlns=\"urn:oncl:interop\"><data Id=\"payload\" b=\"2\" a=\"1\">Привет &amp; hello</data><empty/></root>";

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for profile in Profile::ALL {
        cases.push(Case::new(
            format!("xml-sign-{}-document", profile.label()),
            move |ctx| ours_signs(ctx, profile, false),
        ));
        cases.push(Case::new(
            format!("xml-sign-{}-element", profile.label()),
            move |ctx| ours_signs(ctx, profile, true),
        ));
        for tamper in [XmlTamper::Content, XmlTamper::Digest, XmlTamper::Signature] {
            cases.push(Case::new(
                format!("xml-tamper-{}-{}", profile.label(), tamper.label()),
                move |ctx| tampered(ctx, profile, tamper),
            ));
        }
        cases.push(Case::new(
            format!("xml-add-ours-{}", profile.label()),
            move |ctx| add_second(ctx, profile),
        ));
        for element in [false, true] {
            cases.push(Case::new(
                format!(
                    "xml-verify-ncanode-{}-{}",
                    profile.label(),
                    if element { "element" } else { "document" }
                ),
                move |ctx| oracle_signs(ctx, profile, element),
            ));
        }
        for level in ["b", "t", "lt", "lta"] {
            cases.push(Case::new(
                format!("xades-sign-{}-{level}", profile.label()),
                move |ctx| xades_ours(ctx, profile, level),
            ));
        }
        cases.push(Case::new(
            format!("xades-extend-ours-{}", profile.label()),
            move |ctx| xades_extend_ours(ctx, profile),
        ));
        for level in ["b", "t", "lt"] {
            cases.push(Case::new(
                format!("xades-verify-ncanode-{}-{level}", profile.label()),
                move |ctx| xades_oracle(ctx, profile, level),
            ));
        }
    }
    cases.push(Case::new(
        "xml-add-whole-document-refused",
        add_whole_document_refused,
    ));
    for level in ["b", "t", "lt", "lta"] {
        cases.push(Case::new(
            format!("xades-verify-fixture-gost2015-{level}"),
            move |ctx| xades_fixture(ctx, level),
        ));
    }
    cases
}

#[derive(Clone, Copy)]
enum XmlTamper {
    /// A character of the signed content.
    Content,
    /// A character of the first DigestValue.
    Digest,
    /// A character of the SignatureValue.
    Signature,
}

impl XmlTamper {
    fn label(self) -> &'static str {
        match self {
            XmlTamper::Content => "content",
            XmlTamper::Digest => "digest",
            XmlTamper::Signature => "signature",
        }
    }
}

/// `xml` with the first `from` replaced by `to`.
fn replace_first(xml: &str, from: &str, to: &str) -> anyhow::Result<String> {
    let at = xml
        .find(from)
        .with_context(|| format!("`{from}` not found"))?;
    Ok(format!("{}{to}{}", &xml[..at], &xml[at + from.len()..]))
}

/// The first character of the text of the first `<tag ...>text</tag>`, changed to another
/// base64 character.
fn alter_text_of(xml: &str, tag: &str) -> anyhow::Result<String> {
    let open = xml
        .find(&format!("<{tag}"))
        .with_context(|| format!("no {tag}"))?;
    let start = xml[open..].find('>').context("unterminated tag")? + open + 1;
    let first = xml[start..].chars().next().context("empty value")?;
    let replacement = if first == 'A' { 'B' } else { 'A' };
    Ok(format!(
        "{}{replacement}{}",
        &xml[..start],
        &xml[start + first.len_utf8()..]
    ))
}

/// An internal DTD subset that declares the `Id` attributes ID-typed: NCANode's
/// `/xml/verify` does not register `Id` attributes (an oracle limitation, not our
/// behaviour), so it cannot resolve `URI="#id"` without it. The subset changes no
/// canonical form.
fn with_id_dtd(xml: &str) -> anyhow::Result<String> {
    let mut names: Vec<String> = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find('<') {
        rest = &rest[open + 1..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        if tag.starts_with(['/', '?', '!']) {
            continue;
        }
        if tag.contains(" Id=\"") || tag.contains(" Id='") {
            let name = tag.split([' ', '/', '\n']).next().unwrap_or_default();
            if !names.iter().any(|n| n == name) {
                names.push(name.to_owned());
            }
        }
    }
    ensure!(!names.is_empty(), "no element with an Id");
    let root_start = xml.find("?>").map_or(0, |i| i + 2);
    let tail = &xml[root_start..];
    let root = tail
        .trim_start()
        .strip_prefix('<')
        .and_then(|t| t.split([' ', '>', '/']).next())
        .context("no root element")?;
    let attlists: String = names
        .iter()
        .map(|n| format!("<!ATTLIST {n} Id ID #IMPLIED>"))
        .collect();
    Ok(format!(
        "{}\n<!DOCTYPE {root} [{attlists}]>{}",
        &xml[..root_start],
        tail.trim_start()
    ))
}

/// NCANode's `/xml/verify`: `(grade of the first signature, signers, adesLevel, valid)`.
struct NcXml {
    status: u16,
    grade: String,
    signers: usize,
    level: String,
    valid: bool,
    answer: Value,
}

fn nc_xml_verify(ctx: &mut Ctx, xml: &str) -> anyhow::Result<NcXml> {
    let (status, answer) = ctx.nc_post("/xml/verify", &json!({ "xml": xml }))?;
    Ok(NcXml {
        status,
        grade: super::common::grade_of(
            answer["adesStatus"].as_str(),
            answer["adesSubIndication"].as_str(),
        ),
        signers: answer["signers"].as_array().map_or(0, Vec::len),
        level: answer["adesLevel"].as_str().unwrap_or("none").to_owned(),
        valid: answer["valid"].as_bool().unwrap_or(false),
        answer,
    })
}

fn ours_verify(ctx: &Ctx, profile: &str, file: &Path) -> anyhow::Result<Verified> {
    ctx.oncl.verify(&ctx.world, profile, file, &[] as &[&str])
}

/// The Python oracle's XMLDSig verdict of `file` (RSA signatures).
fn lxml_verify(ctx: &Ctx, file: &Path) -> anyhow::Result<Value> {
    ctx.py_json(&["xmldsig-verify".to_owned(), path_str(file)?.to_owned()])
}

/// Our XMLDSig of the document (whole document, or the `payload` element), judged by
/// NCANode and, for RSA, by lxml + cryptography.
fn ours_signs(ctx: &mut Ctx, profile: Profile, element: bool) -> anyhow::Result<Observed> {
    let input = ctx.write("doc.xml", DOC.as_bytes())?;
    let out = ctx.file("signed.xml");
    let signer = ctx.world.signer(profile);
    let extra: &[&str] = if element {
        &["--target-id", "payload"]
    } else {
        &[]
    };
    ctx.oncl
        .sign(&ctx.world, "xml", signer, &input, &out, extra)?;
    let signed = std::fs::read_to_string(&out)?;
    let ours = ours_verify(ctx, "xml", &out)?;
    ensure!(
        ours.code() == Some(VALID) && ours.check(0, "signature") == "Passed",
        "our verification: {}",
        ours.summary()
    );
    let to_nc = if element {
        with_id_dtd(&signed)?
    } else {
        signed.clone()
    };
    let nc = nc_xml_verify(ctx, &to_nc)?;
    ensure!(
        nc.status == 200 && nc.grade == NC_CHAIN_INCOMPLETE && nc.signers == 1 && !nc.valid,
        "NCANode: HTTP {} {} signers={} {}",
        nc.status,
        nc.grade,
        nc.signers,
        nc.answer
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", ours.verdict().to_owned()),
        ("ncanode", nc.grade.clone()),
    ];
    if profile == Profile::Rsa {
        let python = lxml_verify(ctx, &out)?;
        ensure!(python["ok"] == true, "lxml/cryptography oracle: {python}");
        let signed_element = python["signatures"][0]["references"][0]["signed_element"]
            .as_str()
            .unwrap_or("?")
            .to_owned();
        verdicts.push(("lxml-rsa", format!("ok/{signed_element}")));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}", nc.grade),
        detail: String::new(),
    })
}

/// A counterexample: signed content, a digest or the signature altered.
fn tampered(ctx: &mut Ctx, profile: Profile, tamper: XmlTamper) -> anyhow::Result<Observed> {
    let input = ctx.write("doc.xml", DOC.as_bytes())?;
    let out = ctx.file("signed.xml");
    let signer = ctx.world.signer(profile);
    ctx.oncl.sign(
        &ctx.world,
        "xml",
        signer,
        &input,
        &out,
        &["--target-id", "payload"],
    )?;
    let signed = std::fs::read_to_string(&out)?;
    let bad = match tamper {
        XmlTamper::Content => replace_first(&signed, "hello", "hellp")?,
        XmlTamper::Digest => alter_text_of(&signed, "ds:DigestValue")?,
        XmlTamper::Signature => alter_text_of(&signed, "ds:SignatureValue")?,
    };
    let bad_path = ctx.write("tampered.xml", bad.as_bytes())?;
    let ours = ours_verify(ctx, "xml", &bad_path)?;
    ensure!(
        ours.code() == Some(INVALID),
        "our verification of the altered document: {}",
        ours.summary()
    );
    let nc = nc_xml_verify(ctx, &with_id_dtd(&bad)?)?;
    ensure!(
        nc.status == 200 && nc.grade == NC_REJECTED,
        "NCANode on the altered document: HTTP {} {} {}",
        nc.status,
        nc.grade,
        nc.answer
    );
    let mut verdicts = vec![
        ("crypto", "failure".to_owned()),
        ("ours", ours.verdict().to_owned()),
        ("ncanode", nc.grade.clone()),
    ];
    if profile == Profile::Rsa {
        let python = lxml_verify(ctx, &bad_path)?;
        ensure!(
            python["ok"] == false,
            "lxml/cryptography oracle accepted it: {python}"
        );
        verdicts.push(("lxml-rsa", "rejected".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}", nc.grade),
        detail: String::new(),
    })
}

/// A second signature added by `oncl sign --add` to a document whose first signature
/// references the element `payload` by Id (an Add keeps existing signatures valid only when
/// they do not cover the whole document): we verify both signatures; NCANode counts two
/// signers and grades the first by document order (its documented behaviour).
fn add_second(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let input = ctx.write("doc.xml", DOC.as_bytes())?;
    let first = ctx.file("first.xml");
    let two = ctx.file("two.xml");
    ctx.oncl.sign(
        &ctx.world,
        "xml",
        ctx.world.signer(Profile::Rsa),
        &input,
        &first,
        &["--target-id", "payload"] as &[&str],
    )?;
    ctx.oncl.sign(
        &ctx.world,
        "xml",
        ctx.world.signer(profile),
        &first,
        &two,
        &["--add", "--target-id", "payload"] as &[&str],
    )?;
    let ours = ours_verify(ctx, "xml", &two)?;
    ensure!(
        ours.code() == Some(VALID)
            && ours.signers().len() == 2
            && ours.check(0, "signature") == "Passed"
            && ours.check(1, "signature") == "Passed",
        "our verification of the two-signature document: {}",
        ours.summary()
    );
    let signed = std::fs::read_to_string(&two)?;
    let nc = nc_xml_verify(ctx, &with_id_dtd(&signed)?)?;
    ensure!(
        nc.status == 200 && nc.signers == 2 && nc.grade == NC_CHAIN_INCOMPLETE,
        "NCANode: HTTP {} {} signers={} {}",
        nc.status,
        nc.grade,
        nc.signers,
        nc.answer
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours-signers", ours.signers().len().to_string()),
        ("ours", ours.verdict().to_owned()),
        (
            "ncanode",
            format!("signers={} first={}", nc.signers, nc.grade),
        ),
    ];
    if profile == Profile::Rsa {
        let python = lxml_verify(ctx, &two)?;
        ensure!(
            python["ok"] == true && python["count"] == 2,
            "lxml/cryptography oracle: {python}"
        );
        verdicts.push(("lxml-rsa", "ok+ok".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}", nc.grade),
        detail: String::new(),
    })
}

/// `oncl sign --add` onto a document whose first signature covers the whole document would
/// invalidate that signature: it is refused, nothing is published, and the first
/// signature still verifies independently (lxml + cryptography).
fn add_whole_document_refused(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let input = ctx.write("doc.xml", DOC.as_bytes())?;
    let first = ctx.file("first.xml");
    let two = ctx.file("two.xml");
    ctx.oncl.sign(
        &ctx.world,
        "xml",
        ctx.world.signer(Profile::Rsa),
        &input,
        &first,
        &[] as &[&str],
    )?;
    let out = ctx.oncl.sign_raw(
        &ctx.world,
        "xml",
        ctx.world.signer(Profile::Rsa),
        &first,
        &two,
        &["--add"],
    )?;
    ensure!(
        out.code == Some(1) && !two.exists(),
        "oncl sign --add: {}",
        out.brief()
    );
    let python = lxml_verify(ctx, &first)?;
    ensure!(
        python["ok"] == true,
        "lxml/cryptography oracle on the first signature: {python}"
    );
    let applied = if out.stderr.contains("applied=Applied") {
        "Applied"
    } else {
        "NotApplied"
    };
    Ok(Observed {
        grade: grade(&[
            ("ours", "refused/InvalidInput".to_owned()),
            ("key", applied.to_owned()),
            ("published", "nothing".to_owned()),
            ("first-signature", "still-valid(lxml-rsa)".to_owned()),
        ]),
        ours: out.brief(),
        oracle: "lxml + cryptography: the first signature is intact".to_owned(),
        detail: String::new(),
    })
}

/// NCANode's XMLDSig (`/xml/sign`, whole document or `#payload`), judged by us.
fn oracle_signs(ctx: &mut Ctx, profile: Profile, element: bool) -> anyhow::Result<Observed> {
    let key = nc_key(profile)?;
    let mut signer = key.request();
    if element {
        signer["referenceUri"] = json!("#payload");
    }
    let (status, answer) =
        ctx.nc_post("/xml/sign", &json!({ "xml": DOC_NC, "signers": [signer] }))?;
    ensure!(status == 200, "NCANode /xml/sign: HTTP {status} {answer}");
    let signed = answer["xml"]
        .as_str()
        .context("no xml in the answer")?
        .to_owned();
    let path = ctx.write("ncanode.xml", signed.as_bytes())?;
    let mut ours = Vec::new();
    for profile_name in ["xml", "xml-kalkan"] {
        let verified = ours_verify(ctx, profile_name, &path)?;
        ensure!(
            verified.check(0, "signature") == "Passed",
            "our `{profile_name}` verification of NCANode's XML: {}",
            verified.summary()
        );
        ours.push(format!(
            "{profile_name}:{}/{}",
            verified.verdict(),
            trust_summary(&verified, 0)
        ));
    }
    let nc = nc_xml_verify(
        ctx,
        &if element {
            with_id_dtd(&signed)?
        } else {
            signed.clone()
        },
    )?;
    ensure!(
        nc.status == 200 && nc.grade == NC_EXPIRED,
        "NCANode on its own XML: HTTP {} {} {}",
        nc.status,
        nc.grade,
        nc.answer
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", ours.join(" ")),
        ("ncanode", nc.grade.clone()),
    ];
    if profile == Profile::Rsa {
        let python = lxml_verify(ctx, &path)?;
        ensure!(python["ok"] == true, "lxml/cryptography oracle: {python}");
        verdicts.push(("lxml-rsa", "ok".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.join("; "),
        oracle: format!("NCANode {}", nc.grade),
        detail: String::new(),
    })
}

fn level_name(level: &str) -> &'static str {
    match level {
        "b" => "B",
        "t" => "T",
        "lt" => "LT",
        _ => "LTA",
    }
}

/// The part of a row about an XAdES our side made, once it is at `level`: judged at that
/// level by us, by NCANode (level, grade) and, for RSA, by the Python structure oracle.
fn judge_ours_xades(
    ctx: &mut Ctx,
    profile: Profile,
    level: &str,
    current: &Path,
) -> anyhow::Result<Observed> {
    let ours = ctx.oncl.verify(
        &ctx.world,
        &format!("xades-{level}"),
        current,
        &[] as &[&str],
    )?;
    ensure!(
        ours.code() == Some(VALID) && ours.check(0, "signature") == "Passed",
        "our verification at level {level}: {}",
        ours.summary()
    );
    let signed_xml = std::fs::read_to_string(current)?;
    let nc = nc_xml_verify(ctx, &with_id_dtd(&signed_xml)?)?;
    ensure!(
        nc.status == 200,
        "NCANode: HTTP {} {}",
        nc.status,
        nc.answer
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        (
            "ours",
            format!(
                "{}/level={}",
                ours.verdict(),
                ours.report["ades_level"].as_str().unwrap_or("none")
            ),
        ),
        ("ncanode", format!("{}/level={}", nc.grade, nc.level)),
    ];
    if profile == Profile::Rsa {
        let python = lxml_verify(ctx, current)?;
        ensure!(python["ok"] == true, "lxml/cryptography oracle: {python}");
        let info = ctx.py_json(&["xades-info".to_owned(), path_str(current)?.to_owned()])?;
        ensure!(
            info["signing_certificate_digest_ok"] == true,
            "xades-info: {info}"
        );
        verdicts.push((
            "xades-structure",
            format!(
                "certdigest-ok timestamps={} certs={} ocsp={} archive={}",
                info["signature_timestamps"].as_array().map_or(0, Vec::len),
                info["certificate_values"],
                info["ocsp_values"],
                info["archive_timestamps"]
            ),
        ));
        for ts in info["signature_timestamps"]
            .as_array()
            .into_iter()
            .flatten()
        {
            ensure!(
                ts["imprint_covers_signature"] == true && ts["signature"]["signature_ok"] == true,
                "signature timestamp: {ts}"
            );
        }
        verdicts.push(("lxml-rsa", "ok".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {} level {}", nc.grade, nc.level),
        detail: String::new(),
    })
}

/// Our XAdES signed directly at `level` (the signature id is required by the baseline
/// profiles; the TSA policy by every level above B).
fn xades_ours(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let input = ctx.write("doc.xml", DOC.as_bytes())?;
    let signed = ctx.file("signed.xml");
    let mut extra = vec![
        "--target-id".to_owned(),
        "payload".to_owned(),
        "--signature-id".to_owned(),
        "sig-1".to_owned(),
    ];
    if level != "b" {
        extra.extend(tsa_args(ctx));
    }
    ctx.oncl.sign(
        &ctx.world,
        &format!("xades-{level}"),
        ctx.world.signer(profile),
        &input,
        &signed,
        &extra,
    )?;
    judge_ours_xades(ctx, profile, level, &signed)
}

/// `oncl extend --profile xml` of our XAdES-T to LT and LTA: every step is judged at its
/// level by us and NCANode, the last by the independent oracles.
fn xades_extend_ours(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let input = ctx.write("doc.xml", DOC.as_bytes())?;
    let mut current = ctx.file("xades-t.xml");
    let mut extra = vec![
        "--target-id".to_owned(),
        "payload".to_owned(),
        "--signature-id".to_owned(),
        "sig-1".to_owned(),
    ];
    extra.extend(tsa_args(ctx));
    ctx.oncl.sign(
        &ctx.world,
        "xades-t",
        ctx.world.signer(profile),
        &input,
        &current,
        &extra,
    )?;
    let mut steps = Vec::new();
    for step in ["lt", "lta"] {
        let next = ctx.file(&format!("xades-{step}.xml"));
        let mut args = ctx.world.trust_args();
        args.extend(tsa_args(ctx));
        args.extend(evidence_args(ctx, ctx.world.signer(profile))?);
        args.extend([
            "extend".to_owned(),
            "--profile".into(),
            "xml".into(),
            "--level".into(),
            step.into(),
            "--input".into(),
            path_str(&current)?.into(),
            "--output".into(),
            path_str(&next)?.into(),
        ]);
        let out = ctx.oncl.run(&args)?;
        ensure!(
            out.ok(),
            "oncl extend --profile xml --level {step}: {}",
            out.brief()
        );
        let observed = judge_ours_xades(ctx, profile, step, &next)?;
        steps.push(observed.grade);
        current = next;
    }
    Ok(Observed {
        grade: steps.join(" ;; "),
        ours: "extended T -> LT -> LTA".to_owned(),
        oracle: "see grade".to_owned(),
        detail: String::new(),
    })
}

/// NCANode's XAdES (`/xml/sign` with xadesLevel), judged at that level by us.
fn xades_oracle(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/xml/sign",
        &json!({
            "xml": DOC_NC,
            "signers": [key.request()],
            "xadesLevel": level_name(level),
            "tsaPolicy": "TSA_GOST2015_POLICY",
        }),
    )?;
    if status != 200 {
        return Ok(Observed {
            grade: grade(&[("ncanode", format!("HTTP{status}"))]),
            ours: "not reached".to_owned(),
            oracle: format!(
                "NCANode /xml/sign xadesLevel {}: HTTP {status} {answer}",
                level_name(level)
            ),
            detail: String::new(),
        });
    }
    let signed = answer["xml"].as_str().context("no xml")?.to_owned();
    let path = ctx.write("ncanode-xades.xml", signed.as_bytes())?;
    judge_xades(ctx, level, &signed, &path)
}

/// The tail of the rows that have us verify NCANode's XAdES: us at the level, NCANode's own
/// verdict and level.
fn judge_xades(ctx: &mut Ctx, level: &str, signed: &str, path: &Path) -> anyhow::Result<Observed> {
    let ours = ctx
        .oncl
        .verify(&ctx.world, &format!("xades-{level}"), path, &[] as &[&str])?;
    ensure!(
        ours.check(0, "signature") == "Passed",
        "our verification of NCANode's XAdES-{}: {}",
        level_name(level),
        ours.summary()
    );
    let nc = nc_xml_verify(
        ctx,
        &with_id_dtd(signed).unwrap_or_else(|_| signed.to_owned()),
    )?;
    if nc.status != 200 {
        bail!("NCANode on the XAdES: HTTP {} {}", nc.status, nc.answer);
    }
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            (
                "ours",
                format!(
                    "{}/{}/ts={}/level={}",
                    ours.verdict(),
                    trust_summary(&ours, 0),
                    ours.check(0, "timestamp"),
                    ours.report["ades_level"].as_str().unwrap_or("none")
                ),
            ),
            ("ncanode", format!("{}/level={}", nc.grade, nc.level)),
        ]),
        ours: ours.summary(),
        oracle: format!("NCANode {} level {}", nc.grade, nc.level),
        detail: String::new(),
    })
}

/// The Kalkan-made XAdES of NCANode's repository (GOST 2015, B/T/LT/LTA).
fn xades_fixture(ctx: &mut Ctx, level: &str) -> anyhow::Result<Observed> {
    let dir = crate::fetch::ncanode_dir();
    let signed = std::fs::read_to_string(dir.join(format!("xades-test-signed-{level}.xml")))
        .context("run `cargo xtask fetch-fixtures`")?;
    let path = ctx.write("fixture.xml", signed.as_bytes())?;
    judge_xades(ctx, level, &signed, &path)
}
