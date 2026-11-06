//! X.509 and PKCS#12: `/x509/info`, `/x509/sign`, `/x509/verify`, `/pkcs12/aliases`,
//! `/pkcs12/info`.

use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use serde_json::{Value, json};

use super::super::oncl::path_str;
use super::super::world::{PASSWORD, Profile};
use super::super::{Case, Ctx, Observed, blocked};
use super::common::{NcKey, b64, grade, nc_key, unb64};

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for profile in Profile::ALL {
        for source in ["ours", "ncanode"] {
            cases.push(Case::new(
                format!("x509-info-{source}-{}", profile.label()),
                move |ctx| info(ctx, profile, source == "ours"),
            ));
            cases.push(Case::new(
                format!("pkcs12-{source}-{}", profile.label()),
                move |ctx| pkcs12(ctx, profile, source == "ours"),
            ));
        }
        cases.push(Case::new(
            format!("x509-sign-ours-{}", profile.label()),
            move |ctx| sign_ours(ctx, profile),
        ));
        cases.push(Case::new(
            format!("x509-sign-ncanode-{}", profile.label()),
            move |ctx| sign_ncanode(ctx, profile),
        ));
    }
    cases.push(Case::new(
        "x509-verify-ncanode-discrimination",
        discrimination,
    ));
    cases.push(Case::new("pkcs12-wrong-password-rsa", wrong_password));
    cases
}

fn secret_for(ctx: &Ctx, profile: Profile) -> PathBuf {
    match profile {
        Profile::Gost2015 => ctx.world.private.join("nc-gost2015.secret"),
        _ => ctx.world.private.join("nc-rsa-gost2004.secret"),
    }
}

/// The certificate of NCANode's test key of `profile`, as DER, read by OpenSSL.
fn nc_cert(ctx: &Ctx, key: &NcKey, profile: Profile) -> anyhow::Result<PathBuf> {
    let p12 = ctx.write("nc.p12", &key.p12)?;
    let pem = ctx.file("nc-cert.pem");
    let out = ctx.openssl(&[
        "pkcs12".to_owned(),
        "-legacy".into(),
        "-in".into(),
        path_str(&p12)?.into(),
        "-nokeys".into(),
        "-passin".into(),
        format!("pass:{}", key.password),
        "-out".into(),
        path_str(&pem)?.into(),
    ])?;
    ensure!(
        out.ok(),
        "openssl pkcs12 ({}): {}",
        profile.label(),
        out.brief()
    );
    let der = ctx.file("nc-cert.cer");
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

/// Seconds since the epoch of `2021-01-18T13:09:14.000+00:00`.
fn unix(text: &str) -> anyhow::Result<i64> {
    let d = |a: usize, b: usize| -> anyhow::Result<i64> {
        text.get(a..b)
            .context("short date")?
            .parse::<i64>()
            .context("date digits")
    };
    let (y, m, day) = (d(0, 4)?, d(5, 7)?, d(8, 10)?);
    let (h, mi, s) = (d(11, 13)?, d(14, 16)?, d(17, 19)?);
    // Days from civil (Howard Hinnant).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + h * 3600 + mi * 60 + s)
}

fn strip(serial: &str) -> String {
    serial.trim_start_matches('0').to_lowercase()
}

/// Certificate facts from three readers: oncl, asn1crypto and NCANode `/x509/info`.
fn info(ctx: &mut Ctx, profile: Profile, ours: bool) -> anyhow::Result<Observed> {
    let der = if ours {
        ctx.world.signer(profile).cert_der.clone()
    } else {
        let key = nc_key(profile)?;
        nc_cert(ctx, &key, profile)?
    };
    let run = ctx.oncl.run(&[
        "--json".to_owned(),
        "inspect".into(),
        "--profile".into(),
        "certificate".into(),
        "--input".into(),
        path_str(&der)?.into(),
    ])?;
    ensure!(run.ok(), "oncl inspect: {}", run.brief());
    let report: Value = serde_json::from_slice(&run.stdout)?;
    let entry = &report["entries"][0];
    let reference = ctx.py_json(&["cert-info".to_owned(), path_str(&der)?.to_owned()])?;
    let (status, answer) = ctx.nc_post(
        "/x509/info",
        &json!({ "certs": [b64(&std::fs::read(&der)?)] }),
    )?;
    ensure!(status == 200, "NCANode /x509/info: HTTP {status} {answer}");
    let nc = &answer["signers"][0];
    let eq = |name: &str, a: bool| -> anyhow::Result<String> {
        ensure!(
            a,
            "{name} differs: oncl {entry} / asn1crypto {reference} / NCANode {nc}"
        );
        Ok("equal".to_owned())
    };
    let serial = eq(
        "serial",
        strip(entry["serial_hex"].as_str().unwrap_or(""))
            == strip(reference["serial_hex"].as_str().unwrap_or(""))
            && strip(nc["serialNumber"].as_str().unwrap_or(""))
                == strip(reference["serial_hex"].as_str().unwrap_or("")),
    )?;
    let from = eq(
        "notBefore",
        entry["not_before"] == reference["not_before"]
            && unix(nc["notBefore"].as_str().unwrap_or(""))?
                == reference["not_before"].as_i64().unwrap_or(-1),
    )?;
    let to = eq(
        "notAfter",
        entry["not_after"] == reference["not_after"]
            && unix(nc["notAfter"].as_str().unwrap_or(""))?
                == reference["not_after"].as_i64().unwrap_or(-1),
    )?;
    let cn = eq(
        "subject CN",
        entry["subject_cn"] == reference["subject_cn"]
            && nc["subject"]["commonName"] == reference["subject_cn"],
    )?;
    let alg = eq(
        "signature algorithm",
        entry["signature_algorithm_oid"] == reference["signature_oid"]
            && entry["public_key_algorithm_oid"] == reference["key_oid"],
    )?;
    Ok(Observed {
        grade: grade(&[
            ("serial", serial),
            ("not-before", from),
            ("not-after", to),
            ("subject-cn", cn),
            ("algorithms", alg),
            (
                "ncanode-signAlg",
                nc["signAlg"].as_str().unwrap_or("?").to_owned(),
            ),
            ("ncanode-valid", nc["valid"].to_string()),
        ]),
        ours: format!("{entry}"),
        oracle: format!("asn1crypto {reference}; NCANode {nc}"),
        detail: String::new(),
    })
}

/// Aliases and certificate of a PKCS#12 file: oncl, NCANode `/pkcs12/aliases` + `/info`,
/// OpenSSL (`-legacy`) and asn1crypto agree.
fn pkcs12(ctx: &mut Ctx, profile: Profile, ours: bool) -> anyhow::Result<Observed> {
    let (p12, password, secret, expected_alias): (PathBuf, String, PathBuf, Option<String>) =
        if ours {
            let signer = ctx.world.signer(profile);
            (
                signer.p12.clone(),
                PASSWORD.to_owned(),
                ctx.world.secret.clone(),
                Some(signer.entry.alias.clone()),
            )
        } else {
            let key = nc_key(profile)?;
            (
                ctx.write("nc.p12", &key.p12)?,
                key.password.to_owned(),
                secret_for(ctx, profile),
                None,
            )
        };
    let request = json!({ "key": b64(&std::fs::read(&p12)?), "password": password });
    let (status, aliases) =
        ctx.nc_post("/pkcs12/aliases", &json!({ "keys": [request.clone()] }))?;
    ensure!(
        status == 200,
        "NCANode /pkcs12/aliases: HTTP {status} {aliases}"
    );
    let alias = aliases["aliases"][0][0]
        .as_str()
        .context("no alias")?
        .to_owned();
    ensure!(
        aliases["aliases"][0].as_array().map(Vec::len) == Some(1),
        "aliases: {aliases}"
    );
    if let Some(expected) = &expected_alias {
        ensure!(&alias == expected, "NCANode alias {alias}, ours {expected}");
    }
    let (status, info) = ctx.nc_post("/pkcs12/info", &json!({ "keys": [request] }))?;
    ensure!(status == 200, "NCANode /pkcs12/info: HTTP {status} {info}");
    let run = ctx.oncl.run(&[
        "--json".to_owned(),
        "inspect".into(),
        "--profile".into(),
        "container".into(),
        "--input".into(),
        path_str(&p12)?.into(),
        "--alias".into(),
        alias.clone(),
        "--secret-file".into(),
        path_str(&secret)?.into(),
    ])?;
    ensure!(
        run.ok(),
        "oncl inspect --profile container: {}",
        run.brief()
    );
    let report: Value = serde_json::from_slice(&run.stdout)?;
    let entry = &report["entries"][0];
    let openssl = ctx.openssl(&[
        "pkcs12".to_owned(),
        "-legacy".into(),
        "-in".into(),
        path_str(&p12)?.into(),
        "-nokeys".into(),
        "-passin".into(),
        format!("pass:{password}"),
    ])?;
    ensure!(openssl.ok(), "openssl pkcs12: {}", openssl.brief());
    let friendly = openssl
        .stdout_text()
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("friendlyName:")
                .map(|v| v.trim().to_owned())
        })
        .context("no friendlyName in OpenSSL's output")?;
    ensure!(
        friendly == alias,
        "OpenSSL friendlyName {friendly}, alias {alias}"
    );
    // The certificate through OpenSSL's reader, then asn1crypto.
    let pem = ctx.file("p12-cert.pem");
    std::fs::write(&pem, openssl.stdout_text())?;
    let reference = ctx.py_json(&["cert-info".to_owned(), path_str(&pem)?.to_owned()])?;
    let want = strip(reference["serial_hex"].as_str().unwrap_or(""));
    ensure!(
        strip(entry["serial_hex"].as_str().unwrap_or("")) == want
            && strip(info["signers"][0]["serialNumber"].as_str().unwrap_or("")) == want,
        "serials differ: oncl {entry} / NCANode {} / OpenSSL+asn1crypto {reference}",
        info["signers"][0]["serialNumber"]
    );
    Ok(Observed {
        grade: grade(&[
            ("aliases", "one, equal(ncanode,openssl,oncl)".to_owned()),
            (
                "serial",
                "equal(ncanode,oncl,openssl+asn1crypto)".to_owned(),
            ),
            ("ncanode-info-valid", info["valid"].to_string()),
        ]),
        ours: format!("{entry}"),
        oracle: format!("NCANode alias {alias}; OpenSSL friendlyName {friendly}"),
        detail: String::new(),
    })
}

/// A wrong password is refused by oncl, NCANode and OpenSSL alike, with no certificate.
fn wrong_password(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let signer = ctx.world.signer(Profile::Rsa);
    let p12 = signer.p12.clone();
    let alias = signer.entry.alias.clone();
    let run = ctx.oncl.run(&[
        "--json".to_owned(),
        "inspect".into(),
        "--profile".into(),
        "container".into(),
        "--input".into(),
        path_str(&p12)?.into(),
        "--alias".into(),
        alias,
        "--secret-file".into(),
        path_str(&ctx.world.private.join("wrong.secret"))?.into(),
    ])?;
    ensure!(
        !run.ok() && run.stdout.is_empty(),
        "oncl accepted a wrong password: {}",
        run.brief()
    );
    let (status, _) = ctx.nc_post(
        "/pkcs12/aliases",
        &json!({ "keys": [{ "key": b64(&std::fs::read(&p12)?), "password": "not-the-password" }] }),
    )?;
    ensure!(
        status >= 400,
        "NCANode accepted a wrong password: HTTP {status}"
    );
    let out = ctx.openssl(&[
        "pkcs12".to_owned(),
        "-legacy".into(),
        "-in".into(),
        path_str(&p12)?.into(),
        "-nokeys".into(),
        "-passin".into(),
        "pass:not-the-password".into(),
    ])?;
    ensure!(!out.ok(), "OpenSSL accepted a wrong password");
    Ok(Observed {
        grade: grade(&[
            ("oncl", "refused".to_owned()),
            ("ncanode", format!("HTTP{status}")),
            ("openssl", "refused".to_owned()),
        ]),
        ours: run.brief(),
        oracle: format!("NCANode HTTP {status}"),
        detail: String::new(),
    })
}

const RAW: &[u8] = b"raw data to sign";

/// `openssl dgst -sha256 -verify` of an RSA PKCS#1 v1.5 signature over `data`.
fn openssl_raw(ctx: &Ctx, cert_der: &Path, data: &[u8], signature: &[u8]) -> anyhow::Result<bool> {
    let pubkey = ctx.file("raw.pub");
    let out = ctx.openssl(&[
        "x509".to_owned(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        path_str(cert_der)?.into(),
        "-pubkey".into(),
        "-noout".into(),
        "-out".into(),
        path_str(&pubkey)?.into(),
    ])?;
    ensure!(out.ok(), "openssl x509: {}", out.brief());
    let d = ctx.write("raw.data", data)?;
    let s = ctx.write("raw.sig", signature)?;
    Ok(ctx
        .openssl(&[
            "dgst".to_owned(),
            "-sha256".into(),
            "-verify".into(),
            path_str(&pubkey)?.into(),
            "-signature".into(),
            path_str(&s)?.into(),
            path_str(&d)?.into(),
        ])?
        .ok())
}

fn no_gost_raw_verifier() -> anyhow::Result<()> {
    blocked(
        "no external verifier judges a raw GOST signature: NCANode's /x509/verify folds the \
         certificate chain into `valid` (false for every key here, good or altered data alike, \
         shown by x509-verify-ncanode-discrimination), oncl has no raw verify profile, and \
         OpenSSL/Python have no GOST R 34.10-2004/2015",
    )
}

/// `oncl sign --profile raw` (RSA): OpenSSL verifies the signature value, rejects altered
/// data.
fn sign_ours(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    if profile != Profile::Rsa {
        return no_gost_raw_verifier().map(|()| Observed::default());
    }
    let data = ctx.write("data.bin", RAW)?;
    let sig = ctx.file("raw.sig");
    ctx.oncl.sign(
        &ctx.world,
        "raw",
        ctx.world.signer(profile),
        &data,
        &sig,
        &[] as &[&str],
    )?;
    let bytes = std::fs::read(&sig)?;
    let cert = ctx.world.signer(profile).cert_der.clone();
    ensure!(
        openssl_raw(ctx, &cert, RAW, &bytes)?,
        "OpenSSL rejected our raw RSA signature"
    );
    let mut altered = RAW.to_vec();
    altered[0] ^= 1;
    ensure!(
        !openssl_raw(ctx, &cert, &altered, &bytes)?,
        "OpenSSL accepted altered data"
    );
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("openssl", "verified, altered data rejected".to_owned()),
            ("signature-bytes", bytes.len().to_string()),
        ]),
        ours: format!("{} signature bytes", bytes.len()),
        oracle: "OpenSSL dgst -sha256 -verify".to_owned(),
        detail: String::new(),
    })
}

/// NCANode's raw signature (`/x509/sign`, RSA): OpenSSL verifies it with the returned
/// certificate; altered data is rejected.
fn sign_ncanode(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    if profile != Profile::Rsa {
        return no_gost_raw_verifier().map(|()| Observed::default());
    }
    let key = nc_key(profile)?;
    let (status, answer) = ctx.nc_post(
        "/x509/sign",
        &json!({ "data": std::str::from_utf8(RAW)?, "signer": key.request() }),
    )?;
    ensure!(status == 200, "NCANode /x509/sign: HTTP {status} {answer}");
    let signature = unb64(answer["signature"].as_str().context("no signature")?)?;
    let cert = ctx.write(
        "nc-signer.cer",
        &unb64(answer["certificate"].as_str().context("no certificate")?)?,
    )?;
    ensure!(
        openssl_raw(ctx, &cert, RAW, &signature)?,
        "OpenSSL rejected NCANode's raw RSA signature"
    );
    let mut altered = RAW.to_vec();
    altered[0] ^= 1;
    ensure!(
        !openssl_raw(ctx, &cert, &altered, &signature)?,
        "OpenSSL accepted altered data"
    );
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("openssl", "verified, altered data rejected".to_owned()),
            ("oncl", "no raw verify profile".to_owned()),
        ]),
        ours: "oncl has no verify profile for a raw signature".to_owned(),
        oracle: "OpenSSL dgst -sha256 -verify with the certificate NCANode returned".to_owned(),
        detail: String::new(),
    })
}

/// NCANode's own `/x509/verify` cannot tell a good raw signature from an altered one.
fn discrimination(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let key = nc_key(Profile::Rsa)?;
    let (status, signed) = ctx.nc_post(
        "/x509/sign",
        &json!({ "data": std::str::from_utf8(RAW)?, "signer": key.request() }),
    )?;
    ensure!(status == 200, "NCANode /x509/sign: HTTP {status}");
    let verify = |ctx: &mut Ctx, data: &str| {
        ctx.nc_post(
            "/x509/verify",
            &json!({ "certificate": signed["certificate"], "signature": signed["signature"], "data": data }),
        )
    };
    let (s1, good) = verify(ctx, std::str::from_utf8(RAW)?)?;
    let (s2, bad) = verify(ctx, "raw data to signX")?;
    ensure!(
        s1 == 200 && s2 == 200,
        "NCANode /x509/verify: HTTP {s1} {s2}"
    );
    Ok(Observed {
        grade: grade(&[
            ("ncanode-good", format!("valid={}", good["valid"])),
            ("ncanode-altered", format!("valid={}", bad["valid"])),
        ]),
        ours: "n/a".to_owned(),
        oracle: "NCANode /x509/verify answers valid=false for the good and the altered data alike (the expired test certificate is folded into `valid`)".to_owned(),
        detail: String::new(),
    })
}
