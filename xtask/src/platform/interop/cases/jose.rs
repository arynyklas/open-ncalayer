//! JWS and JWT: `/jws/sign`, `/jws/sign/add`, `/jws/verify`, `/jwt/encode`, `/jwt/decode`.
//!
//! oncl implements RS256 and the NCALayer/AcBank identifier `ECGOST3410-2015-512` (the one
//! the original commonUtils module uses); NCANode names its GOST algorithms `GG2015` and
//! `GG2004`. The two do not interoperate by name: the GOST rows record that.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::super::oncl::path_str;
use super::super::world::Profile;
use super::super::{Case, Ctx, Observed, blocked};
use super::common::{b64, grade, nc_key};

const PAYLOAD: &[u8] = br#"{"a":1}"#;
/// `nbf` in the past and `exp` in 2099: valid on NCANode's real clock and on `--as-of`.
const CLAIMS: &str =
    r#"{"iss":"operator","aud":"service","sub":"x","exp":4102444799,"nbf":1735689600}"#;

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (name, serialization, detached) in [
        ("compact", "compact", false),
        ("flattened", "flattened", false),
        ("general", "general", false),
        ("detached", "general", true),
    ] {
        cases.push(Case::new(format!("jws-sign-rsa-{name}"), move |ctx| {
            ours_signs(ctx, serialization, detached)
        }));
    }
    for target in ["payload", "signature"] {
        cases.push(Case::new(format!("jws-tamper-rsa-{target}"), move |ctx| {
            jws_tampered(ctx, target)
        }));
    }
    for detached in [false, true] {
        cases.push(Case::new(
            format!(
                "jws-verify-ncanode-rsa-{}",
                if detached { "detached" } else { "general" }
            ),
            move |ctx| oracle_signs(ctx, detached),
        ));
    }
    cases.push(Case::new("jws-add-ours-rsa", add_ours));
    cases.push(Case::new("jws-add-ncanode-rsa", add_ncanode));
    cases.push(Case::new("jws-add-ncanode-untrusted-refused", add_refused));
    cases.push(Case::new("jwt-encode-ours-rsa", jwt_ours));
    cases.push(Case::new("jwt-tamper-rsa", jwt_tampered));
    cases.push(Case::new("jwt-verify-ncanode-rsa", jwt_oracle));
    cases.push(Case::new("jwt-alg-none-refused", alg_none));
    cases.push(Case::new("jws-gost2015-name-mismatch", gost_name));
    cases.push(Case::new("jws-gost2015-independent-signature", |_| {
        blocked(
            "no external verifier accepts ECGOST3410-2015-512: NCANode only accepts GG2015, \
             GG2004, ES256/384/512 and RS256/384/512 (JwtAlgorithmUtil.java at the pinned \
             commit; HTTP 400 `Unsupported algorithm` for ours), the `alg` is inside the \
             signed header so a signature cannot be relabelled, and OpenSSL/Python have no \
             GOST R 34.10-2015. The identifier is the NCALayer/AcBank one (oncl-builtin-\
             commonutils), a documented compatibility choice, not an oncl defect",
        )
    }));
    cases
}

fn run_json(ctx: &Ctx, args: &[String]) -> anyhow::Result<(Option<i32>, Value, String)> {
    let mut all: Vec<String> = vec!["--json".into()];
    all.extend(ctx.world.trust_args());
    all.extend(args.iter().cloned());
    let out = ctx.oncl.run(&all)?;
    let report = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    Ok((out.code, report, out.brief()))
}

fn jws_verify(
    ctx: &Ctx,
    serialization: &str,
    file: &Path,
    detached: Option<&Path>,
    certificate: Option<&Path>,
) -> anyhow::Result<(Option<i32>, Value, String)> {
    let mut args: Vec<String> = vec![
        "jws".into(),
        "verify".into(),
        "--serialization".into(),
        serialization.into(),
        "--input".into(),
        path_str(file)?.into(),
    ];
    if let Some(d) = detached {
        args.extend(["--detached-input".into(), path_str(d)?.into()]);
    }
    if let Some(c) = certificate {
        args.extend(["--certificate".into(), path_str(c)?.into()]);
    }
    run_json(ctx, &args)
}

/// `verdict/crypto per signer` of a JWS report: `Valid/[Passed,Passed]`.
fn summary(report: &Value) -> String {
    let crypto: Vec<&str> = report["signers"]
        .as_array()
        .map(|s| {
            s.iter()
                .map(|x| x["crypto"].as_str().unwrap_or("?"))
                .collect()
        })
        .unwrap_or_default();
    format!(
        "{}/crypto=[{}]",
        report["verdict"].as_str().unwrap_or("?"),
        crypto.join(",")
    )
}

fn ours_sign_jws(
    ctx: &Ctx,
    serialization: &str,
    detached: bool,
    input: &Path,
    output: &Path,
    add: bool,
    profile: Profile,
) -> anyhow::Result<()> {
    let mut args = ctx.world.trust_args();
    args.extend([
        "jws".into(),
        "sign".into(),
        "--serialization".into(),
        serialization.into(),
        "--input".into(),
        path_str(input)?.into(),
        "--output".into(),
        path_str(output)?.into(),
        "--key".into(),
        path_str(&ctx.world.signer(profile).p12)?.into(),
        "--secret-file".into(),
        path_str(&ctx.world.secret)?.into(),
        "--authorize".into(),
    ]);
    if detached {
        args.push("--detached".into());
    }
    if add {
        args.push("--add".into());
    }
    let out = ctx.oncl.run(&args)?;
    ensure!(out.ok(), "oncl jws sign: {}", out.brief());
    Ok(())
}

/// `openssl dgst -sha256 -verify` of an RS256 signature with the key of `cert_der`.
fn openssl_rs256(
    ctx: &Ctx,
    input: &[u8],
    signature: &[u8],
    cert_der: &Path,
) -> anyhow::Result<bool> {
    let pubkey = ctx.file("rs256.pub");
    let pem = std::fs::read(cert_der)?.starts_with(b"-----");
    let out = ctx.openssl(&[
        "x509".to_owned(),
        "-inform".into(),
        if pem { "PEM" } else { "DER" }.into(),
        "-in".into(),
        path_str(cert_der)?.into(),
        "-pubkey".into(),
        "-noout".into(),
        "-out".into(),
        path_str(&pubkey)?.into(),
    ])?;
    ensure!(out.ok(), "openssl x509: {}", out.brief());
    let data = ctx.write("rs256.in", input)?;
    let sig = ctx.write("rs256.sig", signature)?;
    let check = ctx.openssl(&[
        "dgst".to_owned(),
        "-sha256".into(),
        "-verify".into(),
        path_str(&pubkey)?.into(),
        "-signature".into(),
        path_str(&sig)?.into(),
        path_str(&data)?.into(),
    ])?;
    Ok(check.ok())
}

fn unb(text: &str) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).context("not base64url")
}

/// A JWS in any serialization as `(payload b64url or None, protected, signature)` of its
/// first signature.
fn parts(text: &str) -> anyhow::Result<(Option<String>, String, String)> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(trimmed)?;
        let payload = v["payload"].as_str().map(str::to_owned);
        let (p, s) = if let Some(sig) = v["signatures"].get(0) {
            (sig["protected"].clone(), sig["signature"].clone())
        } else {
            (v["protected"].clone(), v["signature"].clone())
        };
        return Ok((
            payload,
            p.as_str().context("protected")?.to_owned(),
            s.as_str().context("signature")?.to_owned(),
        ));
    }
    let mut it = trimmed.split('.');
    let (p, pl, s) = (
        it.next().context("p")?,
        it.next().context("pl")?,
        it.next().context("s")?,
    );
    Ok((
        (!pl.is_empty()).then(|| pl.to_owned()),
        p.to_owned(),
        s.to_owned(),
    ))
}

/// The general JSON form NCANode's `/jws/verify` takes.
fn general(text: &str) -> anyhow::Result<Value> {
    let (payload, protected, signature) = parts(text)?;
    let mut v = json!({ "signatures": [{ "protected": protected, "signature": signature }] });
    if let Some(p) = payload {
        v["payload"] = json!(p);
    }
    Ok(v)
}

fn nc_jws_verify(
    ctx: &mut Ctx,
    jws: &Value,
    payload: Option<Value>,
) -> anyhow::Result<(u16, Value)> {
    let mut body = json!({ "jws": jws });
    if let Some(p) = payload {
        body["payload"] = p;
    }
    ctx.nc_post("/jws/verify", &body)
}

fn ours_signs(ctx: &mut Ctx, serialization: &str, detached: bool) -> anyhow::Result<Observed> {
    let payload = ctx.write("payload.json", PAYLOAD)?;
    let out = ctx.file("signed.jws");
    ours_sign_jws(
        ctx,
        serialization,
        detached,
        &payload,
        &out,
        false,
        Profile::Rsa,
    )?;
    let text = std::fs::read_to_string(&out)?;
    let (code, report, brief) = jws_verify(
        ctx,
        serialization,
        &out,
        detached.then_some(payload.as_path()),
        None,
    )?;
    ensure!(code == Some(0), "our verification: {brief}");
    let (pl, protected, signature) = parts(&text)?;
    let payload_b64 = pl.unwrap_or_else(|| URL_SAFE_NO_PAD.encode(PAYLOAD));
    let header: Value = serde_json::from_slice(&unb(&protected)?)?;
    ensure!(header["alg"] == "RS256", "header {header}");
    let ok = openssl_rs256(
        ctx,
        format!("{protected}.{payload_b64}").as_bytes(),
        &unb(&signature)?,
        &ctx.world.signer(Profile::Rsa).cert_der,
    )?;
    ensure!(ok, "OpenSSL rejected the RS256 signature");
    let mut jws = general(&text)?;
    if detached {
        jws.as_object_mut().map(|o| o.remove("payload"));
    }
    let (status, answer) = nc_jws_verify(ctx, &jws, detached.then(|| json!({"a": 1})))?;
    ensure!(
        status == 200 && answer["valid"] == true && answer["signers"][0]["valid"] == true,
        "NCANode /jws/verify: HTTP {status} {answer}"
    );
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("ours", summary(&report)),
            ("ncanode", "valid=true".to_owned()),
            ("openssl", "RS256-verified".to_owned()),
        ]),
        ours: summary(&report),
        oracle: "NCANode valid=true; OpenSSL dgst -verify".to_owned(),
        detail: String::new(),
    })
}

fn jws_tampered(ctx: &mut Ctx, target: &str) -> anyhow::Result<Observed> {
    let payload = ctx.write("payload.json", PAYLOAD)?;
    let out = ctx.file("signed.jws");
    ours_sign_jws(ctx, "general", false, &payload, &out, false, Profile::Rsa)?;
    let mut v: Value = serde_json::from_slice(&std::fs::read(&out)?)?;
    if target == "payload" {
        v["payload"] = json!(URL_SAFE_NO_PAD.encode(br#"{"a":2}"#));
    } else {
        let sig = v["signatures"][0]["signature"]
            .as_str()
            .context("sig")?
            .to_owned();
        let mut raw = unb(&sig)?;
        raw[0] ^= 1;
        v["signatures"][0]["signature"] = json!(URL_SAFE_NO_PAD.encode(raw));
    }
    let bad = ctx.write("tampered.jws", serde_json::to_string(&v)?.as_bytes())?;
    let (code, report, brief) = jws_verify(ctx, "general", &bad, None, None)?;
    ensure!(
        code == Some(2),
        "our verification of the altered JWS: {brief}"
    );
    let (status, answer) = nc_jws_verify(ctx, &general(&serde_json::to_string(&v)?)?, None)?;
    ensure!(
        status == 200 && answer["valid"] == false,
        "NCANode on the altered JWS: HTTP {status} {answer}"
    );
    let (_, protected, signature) = parts(&serde_json::to_string(&v)?)?;
    let accepted = openssl_rs256(
        ctx,
        format!("{protected}.{}", v["payload"].as_str().unwrap_or_default()).as_bytes(),
        &unb(&signature)?,
        &ctx.world.signer(Profile::Rsa).cert_der,
    )?;
    ensure!(!accepted, "OpenSSL accepted the altered JWS");
    Ok(Observed {
        grade: grade(&[
            ("crypto", "failure".to_owned()),
            ("ours", summary(&report)),
            ("ncanode", "valid=false".to_owned()),
            ("openssl", "rejected".to_owned()),
        ]),
        ours: summary(&report),
        oracle: "NCANode valid=false; OpenSSL rejects".to_owned(),
        detail: String::new(),
    })
}

/// NCANode's RS256 JWS (`/jws/sign`, general; or detached), verified by us.
fn oracle_signs(ctx: &mut Ctx, detached: bool) -> anyhow::Result<Observed> {
    let key = nc_key(Profile::Rsa)?;
    let mut signer = key.request();
    signer["alg"] = json!("RS256");
    let (status, answer) = ctx.nc_post(
        "/jws/sign",
        &json!({ "payload": {"a": 1}, "signers": [signer], "detached": detached }),
    )?;
    ensure!(status == 200, "NCANode /jws/sign: HTTP {status} {answer}");
    let jws = ctx.write(
        "ncanode.jws",
        serde_json::to_string(&answer["jws"])?.as_bytes(),
    )?;
    let payload = ctx.write("payload.json", PAYLOAD)?;
    let (code, report, brief) = jws_verify(
        ctx,
        "general",
        &jws,
        detached.then_some(payload.as_path()),
        None,
    )?;
    ensure!(
        report["signers"][0]["crypto"] == "Passed",
        "our verification of NCANode's JWS: {brief} {report}"
    );
    let text = serde_json::to_string(&answer["jws"])?;
    let (pl, protected, signature) = parts(&text)?;
    let payload_b64 = pl.unwrap_or_else(|| URL_SAFE_NO_PAD.encode(PAYLOAD));
    let cert = nc_rsa_cert(ctx)?;
    let ok = openssl_rs256(
        ctx,
        format!("{protected}.{payload_b64}").as_bytes(),
        &unb(&signature)?,
        &cert,
    )?;
    ensure!(ok, "OpenSSL rejected NCANode's RS256 signature");
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("ours", format!("{}/exit={:?}", summary(&report), code)),
            ("openssl", "RS256-verified".to_owned()),
        ]),
        ours: summary(&report),
        oracle: "NCANode signed; OpenSSL dgst -verify with its certificate".to_owned(),
        detail: String::new(),
    })
}

/// A second signer added by `oncl jws sign --add`: both verify, by us and NCANode.
fn add_ours(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let payload = ctx.write("payload.json", PAYLOAD)?;
    let first = ctx.file("first.jws");
    let two = ctx.file("two.jws");
    ours_sign_jws(ctx, "general", false, &payload, &first, false, Profile::Rsa)?;
    ours_sign_jws(ctx, "general", false, &first, &two, true, Profile::Rsa)?;
    let (code, report, brief) = jws_verify(ctx, "general", &two, None, None)?;
    ensure!(
        code == Some(0) && report["signers"].as_array().map(Vec::len) == Some(2),
        "our verification: {brief}"
    );
    let text = std::fs::read_to_string(&two)?;
    let (status, answer) = nc_jws_verify(ctx, &serde_json::from_str(&text)?, None)?;
    ensure!(
        status == 200
            && answer["valid"] == true
            && answer["signers"].as_array().map(Vec::len) == Some(2),
        "NCANode: HTTP {status} {answer}"
    );
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("ours-signers", "2".to_owned()),
            ("ours", summary(&report)),
            ("ncanode", "valid=true signers=2".to_owned()),
        ]),
        ours: summary(&report),
        oracle: "NCANode valid=true, 2 signers".to_owned(),
        detail: String::new(),
    })
}

/// NCANode adds its signer to our JWS (`/jws/sign/add`); we verify both.
fn add_ncanode(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let payload = ctx.write("payload.json", PAYLOAD)?;
    let first = ctx.file("first.jws");
    ours_sign_jws(ctx, "general", false, &payload, &first, false, Profile::Rsa)?;
    let key = nc_key(Profile::Rsa)?;
    let mut signer = key.request();
    signer["alg"] = json!("RS256");
    let (status, answer) = ctx.nc_post(
        "/jws/sign/add",
        &json!({ "jws": serde_json::from_slice::<Value>(&std::fs::read(&first)?)?, "signers": [signer] }),
    )?;
    ensure!(
        status == 200,
        "NCANode /jws/sign/add: HTTP {status} {answer}"
    );
    let two = ctx.write("two.jws", serde_json::to_string(&answer["jws"])?.as_bytes())?;
    let (_, report, brief) = jws_verify(ctx, "general", &two, None, None)?;
    ensure!(
        report["signers"].as_array().map(Vec::len) == Some(2)
            && report["signers"]
                .as_array()
                .is_some_and(|s| s.iter().all(|x| x["crypto"] == "Passed")),
        "our verification of the two-signer JWS: {brief} {report}"
    );
    let (status, answer) = nc_jws_verify(ctx, &answer["jws"], None)?;
    ensure!(
        status == 200 && answer["valid"] == true,
        "NCANode: HTTP {status} {answer}"
    );
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("ours-signers", "2".to_owned()),
            ("ours", summary(&report)),
            ("ncanode", "valid=true signers=2".to_owned()),
        ]),
        ours: summary(&report),
        oracle: "NCANode valid=true".to_owned(),
        detail: String::new(),
    })
}

/// `oncl jws sign --add` onto a JWS whose existing signature it cannot trust is refused.
fn add_refused(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let key = nc_key(Profile::Rsa)?;
    let mut signer = key.request();
    signer["alg"] = json!("RS256");
    let (status, answer) = ctx.nc_post(
        "/jws/sign",
        &json!({ "payload": {"a": 1}, "signers": [signer] }),
    )?;
    ensure!(status == 200, "NCANode /jws/sign: HTTP {status} {answer}");
    let first = ctx.write(
        "ncanode.jws",
        serde_json::to_string(&answer["jws"])?.as_bytes(),
    )?;
    let two = ctx.file("two.jws");
    let mut args = ctx.world.trust_args();
    args.extend([
        "jws".into(),
        "sign".into(),
        "--serialization".into(),
        "general".into(),
        "--add".into(),
        "--input".into(),
        path_str(&first)?.into(),
        "--output".into(),
        path_str(&two)?.into(),
        "--key".into(),
        path_str(&ctx.world.signer(Profile::Rsa).p12)?.into(),
        "--secret-file".into(),
        path_str(&ctx.world.secret)?.into(),
        "--authorize".into(),
    ]);
    let out = ctx.oncl.run(&args)?;
    ensure!(
        out.code == Some(1) && out.stderr.contains("applied=NotApplied") && !two.exists(),
        "oncl jws sign --add: {}",
        out.brief()
    );
    Ok(Observed {
        grade: grade(&[
            ("ours", "refused".to_owned()),
            ("key", "not-applied".to_owned()),
            ("published", "nothing".to_owned()),
        ]),
        ours: out.brief(),
        oracle: "no oracle: documented design (every old signature and host trust are checked before a new key opens)".to_owned(),
        detail: String::new(),
    })
}

/// The certificate of NCANode's RSA test key (the key of its JWS and JWT), as DER.
fn nc_rsa_cert(ctx: &Ctx) -> anyhow::Result<std::path::PathBuf> {
    let p12 = crate::fetch::ncanode_dir().join("individual_valid_sign_2004.p12");
    let pem = ctx.file("nc-rsa.pem");
    let out = ctx.openssl(&[
        "pkcs12".to_owned(),
        "-legacy".into(),
        "-in".into(),
        path_str(&p12)?.into(),
        "-nokeys".into(),
        "-passin".into(),
        "pass:Qwerty12".into(),
        "-out".into(),
        path_str(&pem)?.into(),
    ])?;
    ensure!(out.ok(), "openssl pkcs12: {}", out.brief());
    let der = ctx.file("nc-rsa.cer");
    let conv = ctx.openssl(&[
        "x509".to_owned(),
        "-in".into(),
        path_str(&pem)?.into(),
        "-outform".into(),
        "DER".into(),
        "-out".into(),
        path_str(&der)?.into(),
    ])?;
    ensure!(conv.ok(), "openssl x509: {}", conv.brief());
    Ok(der)
}

fn nc_cert_b64(profile: Profile) -> anyhow::Result<String> {
    let file = match profile {
        Profile::Rsa => "individual_valid_sign_2004_rsa.cer",
        _ => bail!("only the RSA certificate fixture is used"),
    };
    Ok(b64(&std::fs::read(crate::fetch::ncanode_dir().join(file))?))
}

fn jwt_encode_ours(ctx: &Ctx) -> anyhow::Result<(std::path::PathBuf, String)> {
    let claims = ctx.write("claims.json", CLAIMS.as_bytes())?;
    let out = ctx.file("ours.jwt");
    let mut args = ctx.world.trust_args();
    args.extend([
        "jwt".into(),
        "encode".into(),
        "--input".into(),
        path_str(&claims)?.into(),
        "--output".into(),
        path_str(&out)?.into(),
        "--key".into(),
        path_str(&ctx.world.signer(Profile::Rsa).p12)?.into(),
        "--secret-file".into(),
        path_str(&ctx.world.secret)?.into(),
        "--authorize".into(),
    ]);
    let run = ctx.oncl.run(&args)?;
    ensure!(run.ok(), "oncl jwt encode: {}", run.brief());
    let token = std::fs::read_to_string(&out)?.trim().to_owned();
    Ok((out, token))
}

fn jwt_verify_ours(
    ctx: &Ctx,
    file: &Path,
    certificate: Option<&Path>,
) -> anyhow::Result<(Option<i32>, Value, String)> {
    let mut args: Vec<String> = vec![
        "jwt".into(),
        "verify".into(),
        "--input".into(),
        path_str(file)?.into(),
        "--issuer".into(),
        "operator".into(),
        "--audience".into(),
        "service".into(),
    ];
    if let Some(c) = certificate {
        args.extend(["--certificate".into(), path_str(c)?.into()]);
    }
    run_json(ctx, &args)
}

/// Our JWT (RS256): we verify strictly and decode; NCANode decodes it with our certificate
/// (`/jwt/decode` verifies the signature and times); OpenSSL verifies RS256.
fn jwt_ours(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let (path, token) = jwt_encode_ours(ctx)?;
    let (code, report, brief) = jwt_verify_ours(ctx, &path, None)?;
    ensure!(code == Some(0), "our verification: {brief}");
    let cert_b64 = b64(&std::fs::read(&ctx.world.signer(Profile::Rsa).cert_der)?);
    let (status, answer) = ctx.nc_post("/jwt/decode", &json!({ "jwt": token, "key": cert_b64 }))?;
    // NCANode checks exp/nbf against the real clock: the matrix's claims lie in 2026-11-02.
    let valid = answer["valid"].as_bool();
    ensure!(status == 200, "NCANode /jwt/decode: HTTP {status} {answer}");
    ensure!(
        answer["jwt"]["payload"]["iss"] == "operator",
        "claims: {answer}"
    );
    let mut it = token.split('.');
    let (p, pl, s) = (
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
    );
    let ok = openssl_rs256(
        ctx,
        format!("{p}.{pl}").as_bytes(),
        &unb(s)?,
        &ctx.world.signer(Profile::Rsa).cert_der,
    )?;
    ensure!(ok, "OpenSSL rejected the RS256 signature");
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("ours", report["verdict"].as_str().unwrap_or("?").to_owned()),
            (
                "ncanode-decode",
                format!(
                    "claims-equal valid={}",
                    valid.map_or("?".to_owned(), |v| v.to_string())
                ),
            ),
            ("openssl", "RS256-verified".to_owned()),
        ]),
        ours: summary(&report["jws"]),
        oracle: "NCANode decoded the claims; OpenSSL dgst -verify".to_owned(),
        detail: String::new(),
    })
}

fn jwt_tampered(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let (_, token) = jwt_encode_ours(ctx)?;
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    parts[1] = URL_SAFE_NO_PAD.encode(CLAIMS.replace("operator", "intruder"));
    let bad = parts.join(".");
    let bad_path = ctx.write("tampered.jwt", bad.as_bytes())?;
    let (code, report, brief) = jwt_verify_ours(ctx, &bad_path, None)?;
    ensure!(
        code == Some(2),
        "our verification of the altered JWT: {brief}"
    );
    let cert_b64 = b64(&std::fs::read(&ctx.world.signer(Profile::Rsa).cert_der)?);
    let (status, answer) = ctx.nc_post("/jwt/decode", &json!({ "jwt": bad, "key": cert_b64 }))?;
    ensure!(
        status == 200 && answer["valid"] == false,
        "NCANode on the altered JWT: HTTP {status} {answer}"
    );
    let ok = openssl_rs256(
        ctx,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &unb(&parts[2])?,
        &ctx.world.signer(Profile::Rsa).cert_der,
    )?;
    ensure!(!ok, "OpenSSL accepted the altered JWT");
    Ok(Observed {
        grade: grade(&[
            ("crypto", "failure".to_owned()),
            ("ours", report["verdict"].as_str().unwrap_or("?").to_owned()),
            ("ncanode-decode", "valid=false".to_owned()),
            ("openssl", "rejected".to_owned()),
        ]),
        ours: summary(&report["jws"]),
        oracle: "NCANode valid=false; OpenSSL rejects".to_owned(),
        detail: String::new(),
    })
}

/// NCANode's JWT (`/jwt/encode`, RS256): we verify with the certificate named by the
/// operator (`--certificate`: the token carries none).
fn jwt_oracle(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let key = nc_key(Profile::Rsa)?;
    let (status, answer) = ctx.nc_post(
        "/jwt/encode",
        &json!({
            "jwt": { "header": {"alg": "RS256", "typ": "JWT"},
                     "payload": {"claims": {"iss": "operator", "aud": "service", "sub": "x"}} },
            "key": key.request()["key"], "password": key.password,
        }),
    )?;
    ensure!(status == 200, "NCANode /jwt/encode: HTTP {status} {answer}");
    let token = answer["jwt"].as_str().context("no jwt")?.to_owned();
    let path = ctx.write("ncanode.jwt", token.as_bytes())?;
    let cert = nc_rsa_cert(ctx)?;
    let (code, report, brief) = jwt_verify_ours(ctx, &path, Some(&cert))?;
    ensure!(
        report["jws"]["signers"][0]["crypto"] == "Passed",
        "our verification of NCANode's JWT: {brief} {report}"
    );
    let _ = nc_cert_b64;
    let mut it = token.split('.');
    let (p, pl, s) = (
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
    );
    let ok = openssl_rs256(ctx, format!("{p}.{pl}").as_bytes(), &unb(s)?, &cert)?;
    ensure!(ok, "OpenSSL rejected NCANode's RS256 signature");
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            (
                "ours",
                format!("{}/exit={:?}", summary(&report["jws"]), code),
            ),
            ("openssl", "RS256-verified".to_owned()),
        ]),
        ours: summary(&report["jws"]),
        oracle: "NCANode signed; OpenSSL dgst -verify".to_owned(),
        detail: String::new(),
    })
}

/// An unsigned token (`alg: none`) is never accepted as a verified JWT.
fn alg_none(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(CLAIMS)
    );
    let path = ctx.write("none.jwt", token.as_bytes())?;
    let (code, report, brief) = jwt_verify_ours(ctx, &path, None)?;
    ensure!(
        code != Some(0) && report["verdict"] != "Valid",
        "oncl accepted alg=none: {brief} {report}"
    );
    let cert_b64 = b64(&std::fs::read(&ctx.world.signer(Profile::Rsa).cert_der)?);
    let (status, answer) = ctx.nc_post("/jwt/decode", &json!({ "jwt": token, "key": cert_b64 }))?;
    let nc = if status == 200 {
        format!("HTTP200 valid={}", answer["valid"])
    } else {
        format!("HTTP{status}")
    };
    Ok(Observed {
        grade: grade(&[
            ("ours", format!("refused/exit={code:?}")),
            ("ncanode-decode", nc.clone()),
        ]),
        ours: brief,
        oracle: format!("NCANode {nc}"),
        detail: String::new(),
    })
}

/// GOST JOSE: oncl's `ECGOST3410-2015-512` against NCANode's `GG2015`: neither verifies the
/// other's tokens (an algorithm-name difference), each round-trips with itself.
fn gost_name(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let payload = ctx.write("payload.json", PAYLOAD)?;
    let out = ctx.file("gost.jws");
    ours_sign_jws(
        ctx,
        "general",
        false,
        &payload,
        &out,
        false,
        Profile::Gost2015,
    )?;
    let (code, report, brief) = jws_verify(ctx, "general", &out, None, None)?;
    ensure!(code == Some(0), "our own GOST JWS: {brief}");
    let jws: Value = serde_json::from_slice(&std::fs::read(&out)?)?;
    let (status, answer) = nc_jws_verify(ctx, &jws, None)?;
    ensure!(
        status == 400
            && answer["message"]
                .as_str()
                .is_some_and(|m| m.contains("Unsupported algorithm")),
        "NCANode on ECGOST3410-2015-512: HTTP {status} {answer}"
    );
    let key = nc_key(Profile::Gost2015)?;
    let mut signer = key.request();
    signer["alg"] = json!("GG2015");
    let (status, answer) = ctx.nc_post(
        "/jws/sign",
        &json!({ "payload": {"a": 1}, "signers": [signer] }),
    )?;
    ensure!(status == 200, "NCANode GG2015 sign: HTTP {status} {answer}");
    let gg = ctx.write(
        "gg2015.jws",
        serde_json::to_string(&answer["jws"])?.as_bytes(),
    )?;
    let (code_gg, _, brief_gg) = jws_verify(ctx, "general", &gg, None, None)?;
    ensure!(code_gg == Some(1), "oncl on a GG2015 JWS: {brief_gg}");
    Ok(Observed {
        grade: grade(&[
            ("ours-roundtrip", summary(&report)),
            ("ncanode-on-ours", "HTTP400/unsupported-alg".to_owned()),
            ("ours-on-gg2015", "refused/exit=1".to_owned()),
        ]),
        ours: summary(&report),
        oracle: "NCANode: Unsupported algorithm: ECGOST3410-2015-512; GG2015 JWS refused by oncl"
            .to_owned(),
        detail: String::new(),
    })
}
