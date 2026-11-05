//! CMS / CAdES: `/cms/sign`, `/cms/sign/add`, `/cms/extract`, `/cms/verify`, `/cms/extend`.

use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};

use super::super::oncl::{INVALID, VALID, Verified, path_str};
use super::super::world::{NOW, Profile};
use super::super::{Case, Ctx, Observed};
use super::common::{
    CONTENT, NC_CHAIN_INCOMPLETE, NC_EXPIRED, NC_REJECTED, b64, evidence_args, flip_in, grade,
    nc_key, signer_grades, trust_summary, tsa_args, unb64,
};

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for profile in Profile::ALL {
        for attached in [true, false] {
            let name = if attached { "attached" } else { "detached" };
            cases.push(Case::new(
                format!("cms-sign-{}-{name}", profile.label()),
                move |ctx| ours_signs(ctx, profile, attached),
            ));
        }
        for tamper in [Tamper::Content, Tamper::DetachedData, Tamper::Signature] {
            cases.push(Case::new(
                format!("cms-tamper-{}-{}", profile.label(), tamper.label()),
                move |ctx| tampered(ctx, profile, tamper),
            ));
        }
    }
    for profile in Profile::ALL {
        for attached in [true, false] {
            let name = if attached { "attached" } else { "detached" };
            cases.push(Case::new(
                format!("cms-verify-ncanode-{}-{name}", profile.label()),
                move |ctx| oracle_signs(ctx, profile, attached),
            ));
        }
        cases.push(Case::new(
            format!("cms-verify-ncanode-{}-tamper", profile.label()),
            move |ctx| oracle_signed_tampered(ctx, profile),
        ));
        cases.push(Case::new(
            format!("cms-add-ours-then-ncanode-{}", profile.label()),
            move |ctx| add_ncanode(ctx, profile),
        ));
        cases.push(Case::new(
            format!("cms-add-openssl-then-ours-{}", profile.label()),
            move |ctx| add_ours(ctx, profile),
        ));
        cases.push(Case::new(
            format!("cms-extract-{}", profile.label()),
            move |ctx| extract(ctx, profile),
        ));
        for level in ["t", "lt", "lta"] {
            cases.push(Case::new(
                format!("cms-cades-{}-{level}", profile.label()),
                move |ctx| cades_level(ctx, profile, level),
            ));
        }
    }
    for attached in [true, false] {
        let name = if attached { "attached" } else { "detached" };
        cases.push(Case::new(
            format!("cms-verify-openssl-rsa-{name}"),
            move |ctx| openssl_signs(ctx, attached, false),
        ));
    }
    cases.push(Case::new("cms-verify-openssl-rsa-tamper", |ctx| {
        openssl_signs(ctx, true, true)
    }));
    cases.push(Case::new("cms-add-ncanode-untrusted-refused", add_refused));
    for profile in Profile::ALL {
        cases.push(Case::new(
            format!("cms-extend-ours-{}", profile.label()),
            move |ctx| extend_ours(ctx, profile),
        ));
        for level in ["t", "lt"] {
            cases.push(Case::new(
                format!("cms-verify-ncanode-{}-{level}", profile.label()),
                move |ctx| oracle_levels(ctx, profile, level),
            ));
        }
        for level in ["t", "lt", "lta"] {
            cases.push(Case::new(
                format!("cms-extend-ncanode-{}-{level}", profile.label()),
                move |ctx| extend_ncanode(ctx, profile, level),
            ));
        }
    }
    for level in ["b", "t", "lt", "lta"] {
        cases.push(Case::new(
            format!("cms-verify-fixture-gost2015-{level}"),
            move |ctx| fixture_level(ctx, level),
        ));
    }
    cases
}

#[derive(Clone, Copy)]
enum Tamper {
    /// A byte of the attached content.
    Content,
    /// A byte of the data a detached signature covers.
    DetachedData,
    /// A byte of the signature value.
    Signature,
}

impl Tamper {
    fn label(self) -> &'static str {
        match self {
            Tamper::Content => "content",
            Tamper::DetachedData => "detached-data",
            Tamper::Signature => "signature",
        }
    }
}

/// The detached-content arguments of `oncl verify`.
fn detached_args(data: &Path) -> anyhow::Result<Vec<String>> {
    Ok(vec![
        "--detached".to_owned(),
        super::super::oncl::path_str(data)?.to_owned(),
    ])
}

/// `oncl --json verify --profile cms` of `sig` (with `data` when detached).
fn ours_verify(ctx: &Ctx, sig: &Path, data: Option<&Path>) -> anyhow::Result<Verified> {
    let extra = match data {
        Some(data) => detached_args(data)?,
        None => Vec::new(),
    };
    ctx.oncl.verify(&ctx.world, "cms", sig, &extra)
}

/// NCANode's judgement of a CMS: `(HTTP status, grades per signer, valid, whole answer)`.
fn nc_verify(
    ctx: &mut Ctx,
    cms: &[u8],
    data: Option<&[u8]>,
) -> anyhow::Result<(u16, Vec<String>, bool, Value)> {
    let mut body = json!({ "cms": b64(cms) });
    if let Some(data) = data {
        body["data"] = json!(b64(data));
    }
    let (status, response) = ctx.nc_post("/cms/verify", &body)?;
    let grades = signer_grades(&response);
    let valid = response["valid"].as_bool().unwrap_or(false);
    Ok((status, grades, valid, response))
}

/// OpenSSL's verdict on a DER CMS under our root at the matrix's instant: `Ok(content)` or
/// the error text.
fn openssl_verify(
    ctx: &Ctx,
    sig: &Path,
    data: Option<&Path>,
) -> anyhow::Result<Result<Vec<u8>, String>> {
    let out_path = ctx.file("openssl.out");
    let mut args: Vec<String> = vec![
        "cms".into(),
        "-verify".into(),
        "-binary".into(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        sig.display().to_string(),
        "-CAfile".into(),
        ctx.world.root_pem.display().to_string(),
        "-purpose".into(),
        "any".into(),
        "-attime".into(),
        NOW.to_string(),
        "-out".into(),
        out_path.display().to_string(),
    ];
    if let Some(data) = data {
        args.push("-content".into());
        args.push(data.display().to_string());
    }
    let out = ctx.openssl(&args)?;
    if out.ok() && out.stderr.contains("Verification successful") {
        Ok(Ok(std::fs::read(&out_path)?))
    } else {
        Ok(Err(out.stderr.trim().to_owned()))
    }
}

/// The independent Python verification of a CMS (RSA math, message digests, timestamp).
fn python_verify(ctx: &Ctx, sig: &Path, data: Option<&Path>) -> anyhow::Result<Value> {
    let mut args = vec!["cms-verify".to_owned(), sig.display().to_string()];
    if let Some(data) = data {
        args.push("--content".into());
        args.push(data.display().to_string());
    }
    ctx.py_json(&args)
}

/// Our signature, judged by every oracle: a good signature.
fn ours_signs(ctx: &mut Ctx, profile: Profile, attached: bool) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let sig = ctx.file("signature.p7s");
    let extra: &[&str] = if attached { &[] } else { &["--detached"] };
    let signer = ctx.world.signer(profile);
    ctx.oncl
        .sign(&ctx.world, "cms", signer, &data, &sig, extra)?;
    let detached = (!attached).then_some(data.as_path());
    let ours = ours_verify(ctx, &sig, detached)?;
    ensure!(
        ours.code() == Some(VALID) && ours.check(0, "signature") == "Passed",
        "our own verification: {}",
        ours.summary()
    );
    let bytes = std::fs::read(&sig)?;
    let (status, grades, valid, answer) = nc_verify(ctx, &bytes, (!attached).then_some(CONTENT))?;
    ensure!(
        status == 200 && grades == [NC_CHAIN_INCOMPLETE] && !valid,
        "NCANode: HTTP {status} {grades:?} valid={valid} {answer}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", ours.verdict().to_owned()),
        ("ncanode", grades[0].clone()),
    ];
    let mut oracle = format!("NCANode {}", grades[0]);
    if profile == Profile::Rsa {
        let content = openssl_verify(ctx, &sig, detached)?
            .map_err(|e| anyhow::anyhow!("OpenSSL rejected our CMS: {e}"))?;
        ensure!(content == CONTENT, "OpenSSL returned other content");
        let python = python_verify(ctx, &sig, detached)?;
        ensure!(python["ok"] == true, "pyca/asn1crypto oracle: {python}");
        verdicts.push(("openssl", "verified".to_owned()));
        verdicts.push(("python-rsa", "ok".to_owned()));
        oracle.push_str("; OpenSSL: Verification successful; Python RSA math ok");
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle,
        detail: String::new(),
    })
}

/// A counterexample: signed data or the signature altered; every judge must reject it.
fn tampered(ctx: &mut Ctx, profile: Profile, tamper: Tamper) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let sig = ctx.file("signature.p7s");
    let attached = matches!(tamper, Tamper::Content);
    let extra: &[&str] = if attached { &[] } else { &["--detached"] };
    let signer = ctx.world.signer(profile);
    ctx.oncl
        .sign(&ctx.world, "cms", signer, &data, &sig, extra)?;
    let good = std::fs::read(&sig)?;
    // Content: the attached bytes (DER keeps them verbatim). Signature: a byte inside the
    // last OCTET STRING of the SignerInfo, which a CMS without unsigned attributes ends with.
    // Detached data: the signature stays, the data it covers changes.
    let mut bad_data = CONTENT.to_vec();
    let bad = match tamper {
        Tamper::Content => flip_in(&good, CONTENT)?,
        Tamper::DetachedData => {
            *bad_data.last_mut().expect("content") ^= 0x01;
            good.clone()
        }
        Tamper::Signature => {
            let mut bad = good.clone();
            let at = bad.len() - 10;
            bad[at] ^= 0x01;
            bad
        }
    };
    let bad_path = ctx.write("tampered.p7s", &bad)?;
    let bad_data_path = ctx.write("tampered.bin", &bad_data)?;
    let judged_data: &[u8] = if matches!(tamper, Tamper::DetachedData) {
        &bad_data
    } else {
        CONTENT
    };
    let judged_path = if matches!(tamper, Tamper::DetachedData) {
        bad_data_path.as_path()
    } else {
        data.as_path()
    };
    let detached_data = (!attached).then_some(judged_path);
    let ours = ours_verify(ctx, &bad_path, detached_data)?;
    ensure!(
        ours.code() == Some(INVALID) && ours.check(0, "signature") == "Failed",
        "our verification of the altered CMS: {}",
        ours.summary()
    );
    let (status, grades, valid, answer) = nc_verify(ctx, &bad, (!attached).then_some(judged_data))?;
    // NCANode rejects altered content either as a graded signature or, when the message
    // digest attribute no longer matches, with a 400 before grading.
    let rejection = if status == 200 && grades == [NC_REJECTED] && !valid {
        NC_REJECTED.to_owned()
    } else if status == 400
        && answer["message"]
            .as_str()
            .is_some_and(|m| m.contains("content hash found in signed attributes different"))
    {
        "HTTP400/content-hash-differs".to_owned()
    } else {
        bail!("NCANode on the altered CMS: HTTP {status} {grades:?} {answer}");
    };
    let mut verdicts = vec![
        ("crypto", "failure".to_owned()),
        (
            "ours",
            format!("{}/{}", ours.verdict(), ours.check(0, "signature")),
        ),
        ("ncanode", rejection.clone()),
    ];
    if profile == Profile::Rsa {
        let verdict = openssl_verify(ctx, &bad_path, detached_data)?;
        ensure!(verdict.is_err(), "OpenSSL accepted the altered CMS");
        let python = python_verify(ctx, &bad_path, detached_data)?;
        ensure!(
            python["ok"] == false,
            "pyca/asn1crypto oracle accepted it: {python}"
        );
        verdicts.push(("openssl", "rejected".to_owned()));
        verdicts.push(("python-rsa", "rejected".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {rejection}"),
        detail: String::new(),
    })
}

/// OpenSSL's verdict on a DER CMS's signatures and digests only (no path, no time).
fn openssl_noverify(
    ctx: &Ctx,
    sig: &Path,
    data: Option<&Path>,
) -> anyhow::Result<Result<Vec<u8>, String>> {
    let out_path = ctx.file("openssl-noverify.out");
    let mut args: Vec<String> = vec![
        "cms".into(),
        "-verify".into(),
        "-noverify".into(),
        "-binary".into(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        sig.display().to_string(),
        "-out".into(),
        out_path.display().to_string(),
    ];
    if let Some(data) = data {
        args.push("-content".into());
        args.push(data.display().to_string());
    }
    let out = ctx.openssl(&args)?;
    if out.ok() && out.stderr.contains("Verification successful") {
        Ok(Ok(std::fs::read(&out_path)?))
    } else {
        Ok(Err(out.stderr.trim().to_owned()))
    }
}

/// NCANode signs (`/cms/sign`, level B) with its test key; returns the CMS.
fn nc_sign(ctx: &mut Ctx, profile: Profile, attached: bool) -> anyhow::Result<Vec<u8>> {
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/cms/sign",
        &json!({
            "data": b64(CONTENT),
            "signers": [key.request()],
            "cadesLevel": "B",
            "detached": !attached,
        }),
    )?;
    ensure!(status == 200, "NCANode /cms/sign: HTTP {status} {answer}");
    unb64(answer["cms"].as_str().context("no cms in the answer")?)
}

/// A CMS made by NCANode (Kalkan), judged by us: the signature value and digests must pass,
/// the certificate (expired, issued by a CA we do not trust) must not.
fn oracle_signs(ctx: &mut Ctx, profile: Profile, attached: bool) -> anyhow::Result<Observed> {
    let cms = nc_sign(ctx, profile, attached)?;
    let sig = ctx.write("ncanode.p7s", &cms)?;
    let data = ctx.write("data.bin", CONTENT)?;
    let detached = (!attached).then_some(data.as_path());
    let ours = ours_verify(ctx, &sig, detached)?;
    ensure!(
        ours.check(0, "signature") == "Passed",
        "our verification of NCANode's CMS: {}",
        ours.summary()
    );
    ensure!(
        ours.check(0, "chain") == "Failed" && ours.check(0, "validity") == "Failed",
        "the certificate of NCANode's test key must fail chain and validity: {}",
        ours.summary()
    );
    let (status, grades, valid, answer) = nc_verify(ctx, &cms, (!attached).then_some(CONTENT))?;
    ensure!(
        status == 200 && grades == [NC_EXPIRED] && !valid,
        "NCANode on its own CMS: HTTP {status} {grades:?} {answer}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        (
            "ours",
            format!("{}/{}", ours.verdict(), trust_summary(&ours, 0)),
        ),
        ("ncanode", grades[0].clone()),
    ];
    if profile == Profile::Rsa {
        let content = openssl_noverify(ctx, &sig, detached)?
            .map_err(|e| anyhow::anyhow!("OpenSSL rejected NCANode's CMS: {e}"))?;
        ensure!(content == CONTENT, "OpenSSL returned other content");
        let python = python_verify(ctx, &sig, detached)?;
        ensure!(python["ok"] == true, "pyca/asn1crypto oracle: {python}");
        verdicts.push(("openssl-noverify", "verified".to_owned()));
        verdicts.push(("python-rsa", "ok".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}", grades[0]),
        detail: String::new(),
    })
}

/// A counterexample on a CMS made by NCANode: its attached content altered.
fn oracle_signed_tampered(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let cms = nc_sign(ctx, profile, true)?;
    let bad = flip_in(&cms, CONTENT)?;
    let bad_path = ctx.write("ncanode-tampered.p7s", &bad)?;
    let ours = ours_verify(ctx, &bad_path, None)?;
    ensure!(
        ours.code() == Some(INVALID) && ours.check(0, "signature") == "Failed",
        "our verification of the altered CMS: {}",
        ours.summary()
    );
    let (status, _, _, answer) = nc_verify(ctx, &bad, None)?;
    ensure!(
        status == 400
            && answer["message"]
                .as_str()
                .is_some_and(|m| m.contains("content hash found in signed attributes different")),
        "NCANode on its altered CMS: HTTP {status} {answer}"
    );
    let mut verdicts = vec![
        ("crypto", "failure".to_owned()),
        (
            "ours",
            format!("{}/{}", ours.verdict(), ours.check(0, "signature")),
        ),
        ("ncanode", "HTTP400/content-hash-differs".to_owned()),
    ];
    if profile == Profile::Rsa {
        ensure!(
            openssl_noverify(ctx, &bad_path, None)?.is_err(),
            "OpenSSL accepted the altered CMS"
        );
        let python = python_verify(ctx, &bad_path, None)?;
        ensure!(
            python["ok"] == false,
            "pyca/asn1crypto oracle accepted it: {python}"
        );
        verdicts.push(("openssl-noverify", "rejected".to_owned()));
        verdicts.push(("python-rsa", "rejected".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: "NCANode 400 content hash differs".to_owned(),
        detail: String::new(),
    })
}

/// A CMS signed by OpenSSL with our RSA key (the container is read with `-legacy`: our
/// PKCS#12 files carry the RC2-40 certificate bag the NCA's files carry).
fn openssl_sign_rsa(ctx: &Ctx, data: &Path, attached: bool) -> anyhow::Result<std::path::PathBuf> {
    let signer = ctx.world.signer(Profile::Rsa);
    let pem = ctx.file("rsa.pem");
    let exported = ctx.openssl(&[
        "pkcs12".to_owned(),
        "-legacy".into(),
        "-in".into(),
        path_str(&signer.p12)?.into(),
        "-nodes".into(),
        "-passin".into(),
        format!("file:{}", path_str(&ctx.world.secret)?),
        "-out".into(),
        path_str(&pem)?.into(),
    ])?;
    ensure!(
        exported.ok(),
        "OpenSSL cannot read our PKCS#12: {}",
        exported.brief()
    );
    let sig = ctx.file("openssl.p7s");
    let mut args: Vec<String> = vec![
        "cms".into(),
        "-sign".into(),
        "-binary".into(),
        "-in".into(),
        path_str(data)?.into(),
        "-signer".into(),
        path_str(&pem)?.into(),
        "-inkey".into(),
        path_str(&pem)?.into(),
        "-outform".into(),
        "DER".into(),
        "-out".into(),
        path_str(&sig)?.into(),
    ];
    if attached {
        args.push("-nodetach".into());
    }
    let signed = ctx.openssl(&args)?;
    ensure!(signed.ok(), "OpenSSL cms -sign: {}", signed.brief());
    Ok(sig)
}

/// A CMS signed by OpenSSL with our RSA key, judged by us under the loopback PKI.
fn openssl_signs(ctx: &mut Ctx, attached: bool, tamper: bool) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let sig = openssl_sign_rsa(ctx, &data, attached)?;
    let mut bytes = std::fs::read(&sig)?;
    if tamper {
        bytes = flip_in(&bytes, CONTENT)?;
        std::fs::write(&sig, &bytes)?;
    }
    let detached = (!attached).then_some(data.as_path());
    let ours = ours_verify(ctx, &sig, detached)?;
    if tamper {
        ensure!(
            ours.code() == Some(INVALID) && ours.check(0, "signature") == "Failed",
            "our verification of the altered CMS: {}",
            ours.summary()
        );
        ensure!(
            openssl_verify(ctx, &sig, detached)?.is_err(),
            "OpenSSL accepted its own altered CMS"
        );
        return Ok(Observed {
            grade: grade(&[
                ("crypto", "failure".to_owned()),
                (
                    "ours",
                    format!("{}/{}", ours.verdict(), ours.check(0, "signature")),
                ),
                ("openssl", "rejected".to_owned()),
            ]),
            ours: ours.summary(),
            oracle: "OpenSSL rejects its own altered CMS".to_owned(),
            detail: String::new(),
        });
    }
    ensure!(
        ours.code() == Some(VALID),
        "our verification of OpenSSL's CMS: {}",
        ours.summary()
    );
    let checked = openssl_verify(ctx, &sig, detached)?
        .map_err(|e| anyhow::anyhow!("OpenSSL rejects its own CMS: {e}"))?;
    ensure!(checked == CONTENT, "OpenSSL returned other content");
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("ours", ours.verdict().to_owned()),
            ("openssl", "signed+verified".to_owned()),
        ]),
        ours: ours.summary(),
        oracle: "OpenSSL signed and verified under our root".to_owned(),
        detail: String::new(),
    })
}

/// Our CMS gets a second signer from NCANode (`/cms/sign/add`): both must verify, by us
/// and by NCANode.
fn add_ncanode(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let first = ctx.file("first.p7s");
    let signer = ctx.world.signer(Profile::Rsa);
    ctx.oncl
        .sign(&ctx.world, "cms", signer, &data, &first, &[] as &[&str])?;
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/cms/sign/add",
        &json!({ "cms": b64(&std::fs::read(&first)?), "signers": [key.request()] }),
    )?;
    ensure!(
        status == 200,
        "NCANode /cms/sign/add: HTTP {status} {answer}"
    );
    let two = unb64(answer["cms"].as_str().context("no cms in the answer")?)?;
    let two_path = ctx.write("two.p7s", &two)?;
    let ours = ours_verify(ctx, &two_path, None)?;
    ensure!(
        ours.signers().len() == 2
            && ours.check(0, "signature") == "Passed"
            && ours.check(1, "signature") == "Passed",
        "our verification of the two-signer CMS: {}",
        ours.summary()
    );
    let (status, grades, _, answer) = nc_verify(ctx, &two, None)?;
    ensure!(
        status == 200 && grades.len() == 2,
        "NCANode: HTTP {status} {grades:?} {answer}"
    );
    ensure!(
        grades
            .iter()
            .all(|g| g == NC_CHAIN_INCOMPLETE || g == NC_EXPIRED),
        "NCANode graded the signers {grades:?}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours-signers", format!("{}", ours.signers().len())),
        ("ours", sorted_pair(&ours)),
        ("ncanode", sorted_join(&grades)),
    ];
    let python = python_verify(ctx, &two_path, None)?;
    verdicts.push(("python-rsa", python_summary(&python)));
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}", sorted_join(&grades)),
        detail: String::new(),
    })
}

/// A CMS signed by OpenSSL (a signature we trust) gets our signature (`oncl sign --add`):
/// both verify, by us and by NCANode.
fn add_ours(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let first = openssl_sign_rsa(ctx, &data, true)?;
    let two_path = ctx.file("two.p7s");
    let signer = ctx.world.signer(profile);
    ctx.oncl
        .sign(&ctx.world, "cms", signer, &first, &two_path, &["--add"])?;
    let two = std::fs::read(&two_path)?;
    let ours = ours_verify(ctx, &two_path, None)?;
    ensure!(
        ours.code() == Some(VALID)
            && ours.signers().len() == 2
            && ours.check(0, "signature") == "Passed"
            && ours.check(1, "signature") == "Passed",
        "our verification of the two-signer CMS: {}",
        ours.summary()
    );
    let (status, grades, _, answer) = nc_verify(ctx, &two, None)?;
    ensure!(
        status == 200 && grades == [NC_CHAIN_INCOMPLETE, NC_CHAIN_INCOMPLETE],
        "NCANode: HTTP {status} {grades:?} {answer}"
    );
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours-signers", format!("{}", ours.signers().len())),
        ("ours", ours.verdict().to_owned()),
        ("ncanode", sorted_join(&grades)),
    ];
    let python = python_verify(ctx, &two_path, None)?;
    verdicts.push(("python-rsa", python_summary(&python)));
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {}", sorted_join(&grades)),
        detail: String::new(),
    })
}

/// `oncl sign --add` onto a CMS whose existing signature it cannot validate (NCANode's
/// expired test key) is refused before any key is used: the design requires every existing
/// signature to validate first. Nothing is published.
fn add_refused(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let cms = nc_sign(ctx, Profile::Gost2015, true)?;
    let first = ctx.write("ncanode.p7s", &cms)?;
    let two_path = ctx.file("two.p7s");
    let signer = ctx.world.signer(Profile::Rsa);
    let out = ctx
        .oncl
        .sign_raw(&ctx.world, "cms", signer, &first, &two_path, &["--add"])?;
    ensure!(out.code == Some(1), "oncl sign --add: {}", out.brief());
    ensure!(
        out.stderr.contains("applied=NotApplied") && !two_path.exists(),
        "a refused add must not use the key or publish: {}",
        out.brief()
    );
    Ok(Observed {
        grade: grade(&[
            ("ours", "refused/InvalidInput".to_owned()),
            ("key", "not-applied".to_owned()),
            ("published", "nothing".to_owned()),
        ]),
        ours: out.brief(),
        oracle: "no oracle: documented difference of the design (existing signatures must validate before Add)".to_owned(),
        detail: String::new(),
    })
}

/// The per-signer trust summaries of a two-signer report, in a fixed order (a CMS keeps its
/// signers as a SET: the order is the encoding's, not the insertion's).
fn sorted_pair(v: &Verified) -> String {
    let mut parts: Vec<String> = (0..v.signers().len())
        .map(|i| trust_summary(v, i))
        .collect();
    parts.sort();
    parts.join(" | ")
}

fn sorted_join(grades: &[String]) -> String {
    let mut grades = grades.to_vec();
    grades.sort();
    grades.join("+")
}

/// The Python oracle's per-signer verdicts as `ok`, or the reason it could not judge.
fn python_summary(python: &Value) -> String {
    let mut parts: Vec<String> = python["signers"]
        .as_array()
        .map(|signers| {
            signers
                .iter()
                .map(|r| {
                    if r["signature_ok"] == true && r["digest_ok"] != false {
                        "ok".to_owned()
                    } else if let Some(reason) = r["skipped"].as_str() {
                        format!("skipped({reason})")
                    } else {
                        "failed".to_owned()
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    parts.sort();
    parts.join("+")
}

/// Content extraction from our attached CMS: ours, NCANode's `/cms/extract` and (RSA)
/// OpenSSL return the original bytes.
fn extract(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let sig = ctx.file("signature.p7s");
    let signer = ctx.world.signer(profile);
    ctx.oncl
        .sign(&ctx.world, "cms", signer, &data, &sig, &[] as &[&str])?;
    let out_path = ctx.file("extracted.bin");
    let extracted = ctx.oncl.run(&[
        "extract".to_owned(),
        "--input".into(),
        path_str(&sig)?.into(),
        "--output".into(),
        path_str(&out_path)?.into(),
    ])?;
    ensure!(extracted.ok(), "oncl extract: {}", extracted.brief());
    ensure!(
        std::fs::read(&out_path)? == CONTENT,
        "oncl extract returned other bytes"
    );
    let (status, answer) = ctx.nc_post(
        "/cms/extract",
        &json!({ "cms": b64(&std::fs::read(&sig)?) }),
    )?;
    ensure!(
        status == 200,
        "NCANode /cms/extract: HTTP {status} {answer}"
    );
    let theirs = unb64(answer["data"].as_str().context("no data in the answer")?)?;
    ensure!(theirs == CONTENT, "NCANode extracted other bytes");
    let mut verdicts = vec![
        ("ours", "bytes-equal".to_owned()),
        ("ncanode", "bytes-equal".to_owned()),
    ];
    if profile == Profile::Rsa {
        let content =
            openssl_noverify(ctx, &sig, None)?.map_err(|e| anyhow::anyhow!("OpenSSL: {e}"))?;
        ensure!(content == CONTENT, "OpenSSL returned other content");
        verdicts.push(("openssl", "bytes-equal".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: "extract = original".to_owned(),
        oracle: "NCANode /cms/extract = original".to_owned(),
        detail: String::new(),
    })
}

/// CAdES-T/LT/LTA signed by us, judged by us at that level, by NCANode (level and grade)
/// and by the independent Python oracle (RSA math of the signature and of the token,
/// imprint of the signature) and OpenSSL (RSA, full path).
fn cades_level(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let sig = ctx.file("cades.p7s");
    let signer = ctx.world.signer(profile);
    let mut extra = tsa_args(ctx);
    if level != "t" {
        extra.extend(evidence_args(ctx, signer)?);
    }
    ctx.oncl.sign(
        &ctx.world,
        &format!("cades-{level}"),
        signer,
        &data,
        &sig,
        &extra,
    )?;
    let ours = ctx
        .oncl
        .verify(&ctx.world, &format!("cades-{level}"), &sig, &[] as &[&str])?;
    ensure!(
        ours.code() == Some(VALID) && ours.check(0, "signature") == "Passed",
        "our verification at level {level}: {}",
        ours.summary()
    );
    let level_name = ours.report["ades_level"].as_str().unwrap_or("?").to_owned();
    let bytes = std::fs::read(&sig)?;
    let (status, grades, _, answer) = nc_verify(ctx, &bytes, None)?;
    ensure!(
        status == 200 && grades.len() == 1,
        "NCANode: HTTP {status} {grades:?} {answer}"
    );
    let nc_level = answer["signers"][0]["adesLevel"]
        .as_str()
        .unwrap_or("none")
        .to_owned();
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", format!("{}/level={level_name}", ours.verdict())),
        ("ncanode", format!("{}/level={nc_level}", grades[0])),
    ];
    let mut oracle = format!("NCANode {} level {nc_level}", grades[0]);
    // Independent structure (asn1crypto): the unsigned attributes the level requires.
    let info = ctx.py_json(&["cms-info".to_owned(), sig.display().to_string()])?;
    let unsigned: Vec<String> = info["signers"][0]["unsigned_attrs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    // Baseline B-LT carries the validation data in SignedData.certificates and
    // SignedData.crls (OCSP responses as otherRevInfo); B-LTA adds the archive timestamp
    // attribute (id-aa-ets-archiveTimestampV3).
    let required: &[&str] = match level {
        "t" | "lt" => &["signature_time_stamp_token"],
        _ => &["signature_time_stamp_token", "0.4.0.1733.2.4"],
    };
    for attribute in required {
        ensure!(
            unsigned.iter().any(|a| a == attribute),
            "the CAdES-{level} lacks the unsigned attribute {attribute}: {unsigned:?}"
        );
    }
    let (certificates, revocation) = (
        info["certificates"].as_u64().unwrap_or(0),
        info["crls"].as_u64().unwrap_or(0),
    );
    if level != "t" {
        ensure!(
            certificates >= 3 && revocation >= 2,
            "the CAdES-{level} carries {certificates} certificates and {revocation} revocation values (signer, root, TSA; OCSP for signer and TSA expected)"
        );
    }
    verdicts.push((
        "evidence",
        format!(
            "certs>={} revocation>={} unsigned={}",
            if level == "t" { 1 } else { 3 },
            if level == "t" { 0 } else { 2 },
            required.join("+")
        ),
    ));
    if profile == Profile::Rsa {
        let python = python_verify(ctx, &sig, None)?;
        ensure!(python["ok"] == true, "pyca/asn1crypto oracle: {python}");
        let ts = &python["signers"][0]["timestamp"];
        ensure!(
            ts["imprint_covers_signature"] == true && ts["signature"]["signature_ok"] == true,
            "the signature timestamp token: {ts}"
        );
        verdicts.push(("python-rsa", "ok+token".to_owned()));
        let content = openssl_verify(ctx, &sig, None)?
            .map_err(|e| anyhow::anyhow!("OpenSSL rejected our CAdES: {e}"))?;
        ensure!(content == CONTENT, "OpenSSL returned other content");
        verdicts.push(("openssl", "verified".to_owned()));
        oracle.push_str("; Python RSA signature+token ok; OpenSSL verified");
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle,
        detail: String::new(),
    })
}

/// `oncl extend --profile cms --level <level>` of a detached CAdES.
fn ours_extend(
    ctx: &Ctx,
    signer: &super::super::world::Signer,
    level: &str,
    input: &Path,
    output: &Path,
    data: &Path,
) -> anyhow::Result<super::super::tools::Out> {
    let mut args = ctx.world.trust_args();
    args.extend(tsa_args(ctx));
    if level != "t" {
        args.extend(evidence_args(ctx, signer)?);
    }
    args.extend([
        "extend".to_owned(),
        "--profile".into(),
        "cms".into(),
        "--level".into(),
        level.into(),
        "--input".into(),
        path_str(input)?.into(),
        "--output".into(),
        path_str(output)?.into(),
        "--detached".into(),
        path_str(data)?.into(),
    ]);
    ctx.oncl.run(&args)
}

fn level_label(level: &str) -> &'static str {
    match level {
        "b" => "B",
        "t" => "T",
        "lt" => "LT",
        _ => "LTA",
    }
}

/// Keyless extension B -> T -> LT -> LTA by `oncl extend`; every step is verified at its
/// level by us and by NCANode, the last also by OpenSSL and the Python oracles (RSA).
fn extend_ours(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let mut current = ctx.file("step-b.p7s");
    ctx.oncl.sign(
        &ctx.world,
        "cades-b",
        ctx.world.signer(profile),
        &data,
        &current,
        &["--detached"],
    )?;
    let mut steps = Vec::new();
    let mut nc_steps = Vec::new();
    for level in ["t", "lt", "lta"] {
        let next = ctx.file(&format!("step-{level}.p7s"));
        let out = ours_extend(
            ctx,
            ctx.world.signer(profile),
            level,
            &current,
            &next,
            &data,
        )?;
        ensure!(out.ok(), "oncl extend --level {level}: {}", out.brief());
        let verified = ctx.oncl.verify(
            &ctx.world,
            &format!("cades-{level}"),
            &next,
            &detached_args(&data)?,
        )?;
        ensure!(
            verified.code() == Some(VALID),
            "our verification after extending to {level}: {}",
            verified.summary()
        );
        let reported = verified.report["ades_level"]
            .as_str()
            .unwrap_or("?")
            .to_owned();
        let bytes = std::fs::read(&next)?;
        let (status, grades, _, answer) = nc_verify(ctx, &bytes, Some(CONTENT))?;
        ensure!(
            status == 200 && grades.len() == 1,
            "NCANode after {level}: HTTP {status} {grades:?} {answer}"
        );
        let nc_level = answer["signers"][0]["adesLevel"]
            .as_str()
            .unwrap_or("none")
            .to_owned();
        ensure!(
            nc_level == level_label(level),
            "NCANode reads the {level} extension as level {nc_level}"
        );
        steps.push(reported);
        nc_steps.push(format!("{nc_level}:{}", grades[0]));
        current = next;
    }
    let mut verdicts = vec![
        ("crypto", "ok".to_owned()),
        ("ours", format!("Valid@{}", steps.join("+"))),
        ("ncanode", nc_steps.join(" ")),
    ];
    if profile == Profile::Rsa {
        let python = python_verify(ctx, &current, Some(&data))?;
        ensure!(python["ok"] == true, "pyca/asn1crypto oracle: {python}");
        let content = openssl_verify(ctx, &current, Some(&data))?
            .map_err(|e| anyhow::anyhow!("OpenSSL rejected the LTA: {e}"))?;
        ensure!(content == CONTENT, "OpenSSL returned other content");
        verdicts.push(("python-rsa", "ok+token".to_owned()));
        verdicts.push(("openssl", "verified".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: format!("Valid at {}", steps.join(", ")),
        oracle: format!("NCANode {}", nc_steps.join(", ")),
        detail: String::new(),
    })
}

/// NCANode signs CAdES-T/LT with its test key (its TSA is the NCA's): we verify at that
/// level. NCANode cannot make CAdES-LTA with an expired test key (HTTP 500): not a row.
fn oracle_levels(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/cms/sign",
        &json!({
            "data": b64(CONTENT),
            "signers": [key.request()],
            "cadesLevel": level.to_uppercase(),
            "withTsp": true,
            "detached": false,
        }),
    )?;
    ensure!(
        status == 200,
        "NCANode /cms/sign {level}: HTTP {status} {answer}"
    );
    let cms = unb64(answer["cms"].as_str().context("no cms")?)?;
    let sig = ctx.write("ncanode.p7s", &cms)?;
    judge_oracle_cades(ctx, profile, level, &cms, &sig)
}

/// Verification at `level` of a CAdES made by the oracle (the shared tail of the rows that
/// have us verify NCANode's artifacts).
fn judge_oracle_cades(
    ctx: &mut Ctx,
    profile: Profile,
    level: &str,
    cms: &[u8],
    sig: &Path,
) -> anyhow::Result<Observed> {
    let ours = ctx
        .oncl
        .verify(&ctx.world, &format!("cades-{level}"), sig, &[] as &[&str])?;
    ensure!(
        ours.check(0, "signature") == "Passed",
        "our verification of NCANode's CAdES-{level}: {}",
        ours.summary()
    );
    let (status, grades, _, answer) = nc_verify(ctx, cms, None)?;
    ensure!(
        status == 200 && grades.len() == 1,
        "NCANode: HTTP {status} {grades:?} {answer}"
    );
    let nc_level = answer["signers"][0]["adesLevel"]
        .as_str()
        .unwrap_or("none")
        .to_owned();
    let mut verdicts = vec![
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
        ("ncanode", format!("{}/level={nc_level}", grades[0])),
    ];
    if profile == Profile::Rsa {
        let python = python_verify(ctx, sig, None)?;
        ensure!(python["ok"] == true, "pyca/asn1crypto oracle: {python}");
        verdicts.push(("python-rsa", "ok".to_owned()));
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.summary(),
        oracle: format!("NCANode {} level {nc_level}", grades[0]),
        detail: String::new(),
    })
}

/// The Kalkan-made CAdES of NCANode's repository (GOST 2015, B/T/LT/LTA): verified by us.
fn fixture_level(ctx: &mut Ctx, level: &str) -> anyhow::Result<Observed> {
    let dir = crate::fetch::ncanode_dir();
    let cms = std::fs::read(dir.join(format!("cades-test-signed-{level}.p7s")))
        .context("run `cargo xtask fetch-fixtures`")?;
    let sig = ctx.write("fixture.p7s", &cms)?;
    judge_oracle_cades(ctx, Profile::Gost2015, level, &cms, &sig)
}

/// NCANode extends our CAdES-B (`/cms/extend`); we verify the result at that level. NCANode
/// reaches the loopback responder of the matrix through the Docker bridge for revocation
/// data, but its timestamps are the NCA's.
fn extend_ncanode(ctx: &mut Ctx, profile: Profile, level: &str) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let b = ctx.file("b.p7s");
    let signer = ctx.world.signer(profile);
    ctx.oncl
        .sign(&ctx.world, "cades-b", signer, &data, &b, &["--detached"])?;
    let (status, answer) = ctx.nc_post(
        "/cms/extend",
        &json!({
            "cms": b64(&std::fs::read(&b)?),
            "data": b64(CONTENT),
            "cadesLevel": level.to_uppercase(),
            "tsaPolicy": "TSA_GOST2015_POLICY",
        }),
    )?;
    if status != 200 {
        return Ok(Observed {
            grade: grade(&[("ncanode", format!("HTTP{status}"))]),
            ours: "not reached".to_owned(),
            oracle: format!("NCANode /cms/extend: HTTP {status} {answer}"),
            detail: String::new(),
        });
    }
    let extended = unb64(answer["cms"].as_str().context("no cms")?)?;
    let sig = ctx.write("extended.p7s", &extended)?;
    let ours = ctx.oncl.verify(
        &ctx.world,
        &format!("cades-{level}"),
        &sig,
        &detached_args(&data)?,
    )?;
    let (nc_status, grades, _, nc_answer) = nc_verify(ctx, &extended, Some(CONTENT))?;
    let nc = if nc_status == 200 {
        format!(
            "{}/level={}",
            grades.first().map_or("none", String::as_str),
            nc_answer["signers"][0]["adesLevel"]
                .as_str()
                .unwrap_or("none")
        )
    } else {
        format!("HTTP{nc_status}")
    };
    Ok(Observed {
        grade: grade(&[
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
            ("ncanode-verify", nc),
        ]),
        ours: ours.summary(),
        oracle: format!("NCANode extended to {level}; its own verification HTTP {nc_status}"),
        detail: String::new(),
    })
}
