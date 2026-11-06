//! WS-Security: `/wsse/sign` and `/wsse/verify`.

use std::path::Path;

use anyhow::{Context, ensure};
use serde_json::{Value, json};

use super::super::oncl::{INVALID, VALID, Verified, path_str};
use super::super::world::Profile;
use super::super::{Case, Ctx, Observed, blocked};
use super::common::{grade, nc_key, trust_summary};

/// The SOAP 1.1 request NCANode's own tests use, shortened.
const SOAP11: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><SOAP-ENV:Body><ns3:SendMessage xmlns:ns3=\"http://bip.bee.kz/SyncChannel/v10/Types\"><request><messageId>ccb1010b</messageId><iin>931002451325</iin></request></ns3:SendMessage></SOAP-ENV:Body></SOAP-ENV:Envelope>";
const SOAP12: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<env:Envelope xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\"><env:Header/><env:Body><ns3:SendMessage xmlns:ns3=\"http://bip.bee.kz/SyncChannel/v10/Types\"><request><messageId>ccb1010b</messageId></request></ns3:SendMessage></env:Body></env:Envelope>";

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for profile in Profile::ALL {
        cases.push(Case::new(
            format!("wsse-sign-{}", profile.label()),
            move |ctx| ours_signs(ctx, profile, Variant::KeyIdentifier),
        ));
        for tamper in ["body", "signature"] {
            cases.push(Case::new(
                format!("wsse-tamper-{}-{tamper}", profile.label()),
                move |ctx| tampered(ctx, profile, tamper),
            ));
        }
        cases.push(Case::new(
            format!("wsse-verify-ncanode-{}", profile.label()),
            move |ctx| oracle_signs(ctx, profile),
        ));
    }
    cases.push(Case::new("wsse-sign-rsa-binary-security-token", |ctx| {
        ours_signs(ctx, Profile::Rsa, Variant::BinarySecurityToken)
    }));
    cases.push(Case::new("wsse-sign-rsa-soap12", |ctx| {
        ours_signs(ctx, Profile::Rsa, Variant::Soap12)
    }));
    cases.push(Case::new("wsse-verify-fixture-rsa", fixture));
    cases
}

#[derive(Clone, Copy)]
enum Variant {
    KeyIdentifier,
    BinarySecurityToken,
    Soap12,
}

/// Our GOST WS-Security signatures have no discriminating external verifier.
fn no_gost_judge(profile: Profile) -> anyhow::Result<()> {
    if profile == Profile::Rsa {
        return Ok(());
    }
    blocked(
        "no external verifier that discriminates GOST WS-Security signatures: NCANode's \
         /wsse/verify answers HTTP 200 `valid=false` for good and altered messages alike (its \
         `valid` folds the certificate chain, which is untrusted for every key here), and \
         Kalkan is reachable only through that route; OpenSSL/Python have no GOST R 34.10",
    )
}

fn verify_ours(ctx: &Ctx, file: &Path, soap12: bool) -> anyhow::Result<Verified> {
    let mut extra: Vec<&str> = Vec::new();
    if soap12 {
        extra.extend(["--soap-version", "soap12"]);
    }
    ctx.oncl.verify(&ctx.world, "wsse", file, &extra)
}

/// NCANode's `/wsse/verify`: `(status, valid, signer count, message)`; an HTTP error is
/// data (NCANode refuses tokens it cannot handle).
fn nc_verify(ctx: &mut Ctx, xml: &str) -> anyhow::Result<(u16, bool, usize, String)> {
    let (status, answer) = ctx.nc_post("/wsse/verify", &json!({ "xml": xml }))?;
    Ok((
        status,
        answer["valid"].as_bool().unwrap_or(false),
        answer["signers"].as_array().map_or(0, Vec::len),
        answer["message"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(120)
            .collect(),
    ))
}

fn lxml(ctx: &Ctx, file: &Path) -> anyhow::Result<Value> {
    ctx.py_json(&["xmldsig-verify".to_owned(), path_str(file)?.to_owned()])
}

fn sign(
    ctx: &Ctx,
    profile: Profile,
    variant: Variant,
) -> anyhow::Result<(std::path::PathBuf, String)> {
    let soap = if matches!(variant, Variant::Soap12) {
        SOAP12
    } else {
        SOAP11
    };
    let input = ctx.write("soap.xml", soap.as_bytes())?;
    let out = ctx.file("signed.xml");
    let mut extra: Vec<&str> = Vec::new();
    match variant {
        Variant::KeyIdentifier => {
            extra.extend(["--wsse-token-reference", "ncanode-x509-key-identifier"])
        }
        Variant::BinarySecurityToken => {
            extra.extend(["--wsse-token-reference", "binary-security-token"])
        }
        Variant::Soap12 => extra.extend(["--soap-version", "soap12"]),
    }
    ctx.oncl.sign(
        &ctx.world,
        "wsse",
        ctx.world.signer(profile),
        &input,
        &out,
        &extra,
    )?;
    let xml = std::fs::read_to_string(&out)?;
    Ok((out, xml))
}

/// Our WS-Security signature, judged by us (strict), NCANode and (RSA) lxml + cryptography,
/// which also names the signed node.
fn ours_signs(ctx: &mut Ctx, profile: Profile, variant: Variant) -> anyhow::Result<Observed> {
    no_gost_judge(profile)?;
    let (out, xml) = sign(ctx, profile, variant)?;
    let soap12 = matches!(variant, Variant::Soap12);
    let ours = verify_ours(ctx, &out, soap12)?;
    ensure!(
        ours.code() == Some(VALID) && ours.check(0, "signature") == "Passed",
        "our verification: {}",
        ours.summary()
    );
    let (status, valid, signers, message) = nc_verify(ctx, &xml)?;
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", ours.verdict().to_owned()),
        (
            "ncanode",
            if status == 200 {
                format!("HTTP200 signers={signers} valid={valid}")
            } else if message.contains("SOAP 1.1") {
                format!("HTTP{status}/soap11-only")
            } else {
                format!("HTTP{status}/token-form-unsupported")
            },
        ),
    ];
    if status == 200 {
        ensure!(
            signers == 1 && !valid,
            "NCANode: signers={signers} valid={valid}"
        );
    } else {
        ensure!(
            (matches!(variant, Variant::BinarySecurityToken)
                && message.contains("Security token supported but currently not handled"))
                || (matches!(variant, Variant::Soap12) && message.contains("SOAP 1.1")),
            "NCANode: HTTP {status} {message}"
        );
    }
    if profile == Profile::Rsa {
        let python = lxml(ctx, &out)?;
        ensure!(python["ok"] == true, "lxml/cryptography oracle: {python}");
        let signed = python["signatures"][0]["references"][0]["signed_element"]
            .as_str()
            .unwrap_or("?");
        ensure!(
            signed == "Body",
            "the signed node is {signed}, not the SOAP Body"
        );
        verdicts.push(("lxml-rsa", format!("ok/{signed}")));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode HTTP {status} {message}"),
        detail: String::new(),
    })
}

fn alter(xml: &str, tamper: &str) -> anyhow::Result<String> {
    let (from, to) = if tamper == "body" {
        ("931002451325", "931002451326")
    } else {
        ("<ds:SignatureValue>", "<ds:SignatureValue>A")
    };
    let at = xml.find(from).context("nothing to alter")?;
    let mut out = xml.to_owned();
    if tamper == "body" {
        out.replace_range(at..at + from.len(), to);
    } else {
        // Change the first character of the value (still base64).
        let start = at + from.len();
        let c = out[start..].chars().next().context("empty")?;
        out.replace_range(start..start + 1, if c == 'A' { "B" } else { "A" });
    }
    Ok(out)
}

fn tampered(ctx: &mut Ctx, profile: Profile, tamper: &str) -> anyhow::Result<Observed> {
    no_gost_judge(profile)?;
    let (_, xml) = sign(ctx, profile, Variant::KeyIdentifier)?;
    let bad = alter(&xml, tamper)?;
    let path = ctx.write("tampered.xml", bad.as_bytes())?;
    let ours = verify_ours(ctx, &path, false)?;
    ensure!(
        ours.code() == Some(INVALID),
        "our verification of the altered message: {}",
        ours.summary()
    );
    let (status, valid, _, message) = nc_verify(ctx, &bad)?;
    let nc = if status == 200 {
        format!("HTTP200 valid={valid}")
    } else {
        format!("HTTP{status}")
    };
    let mut verdicts = vec![
        ("crypto", "failure".to_owned()),
        (
            "ours",
            format!("{}/{}", ours.verdict(), ours.check(0, "signature")),
        ),
        ("ncanode", nc),
    ];
    if profile == Profile::Rsa {
        let python = lxml(ctx, &path)?;
        ensure!(
            python["ok"] == false,
            "lxml/cryptography oracle accepted it: {python}"
        );
        verdicts.push(("lxml-rsa", "rejected".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode HTTP {status} valid={valid} {message}"),
        detail: String::new(),
    })
}

/// NCANode signs (`/wsse/sign`); we verify.
fn oracle_signs(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/wsse/sign",
        &json!({ "xml": SOAP11, "key": b64key(&key), "password": key.password }),
    )?;
    ensure!(status == 200, "NCANode /wsse/sign: HTTP {status} {answer}");
    let signed = answer["xml"].as_str().context("no xml")?.to_owned();
    let path = ctx.write("ncanode.xml", signed.as_bytes())?;
    judge_oracle(ctx, profile, &signed, &path, true)
}

fn b64key(key: &super::common::NcKey) -> String {
    key.request()["key"].as_str().unwrap_or_default().to_owned()
}

fn judge_oracle(
    ctx: &mut Ctx,
    profile: Profile,
    xml: &str,
    path: &Path,
    lxml_applies: bool,
) -> anyhow::Result<Observed> {
    let ours = verify_ours(ctx, path, false)?;
    ensure!(
        ours.check(0, "signature") == "Passed",
        "our verification of NCANode's message: {}",
        ours.summary()
    );
    let (status, valid, signers, _) = nc_verify(ctx, xml)?;
    ensure!(
        status == 200 && signers == 1,
        "NCANode on its own message: HTTP {status} signers={signers}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        (
            "ours",
            format!("{}/{}", ours.verdict(), trust_summary(&ours, 0)),
        ),
        ("ncanode", format!("HTTP200 signers=1 valid={valid}")),
    ];
    if profile == Profile::Rsa && lxml_applies {
        let python = lxml(ctx, path)?;
        ensure!(python["ok"] == true, "lxml/cryptography oracle: {python}");
        let signed = python["signatures"][0]["references"][0]["signed_element"]
            .as_str()
            .unwrap_or("?");
        verdicts.push(("lxml-rsa", format!("ok/{signed}")));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: "NCANode".to_owned(),
        detail: String::new(),
    })
}

/// The Kalkan-made message of NCANode's repository (RSA).
fn fixture(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let xml = std::fs::read_to_string(crate::fetch::ncanode_dir().join("wsse-ncanode.xml"))
        .context("run `cargo xtask fetch-fixtures`")?;
    let path = ctx.write("fixture.xml", xml.as_bytes())?;
    judge_oracle(ctx, Profile::Rsa, &xml, &path, true)
}
