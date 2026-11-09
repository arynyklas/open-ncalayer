//! Helpers the cases share: NCANode keys and answers, tampering, comparisons.

use anyhow::{Context, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::super::Ctx;
use super::super::world::{Profile, Signer};

/// The content of the byte-oriented cases: binary, with CRLF and NUL.
pub const CONTENT: &[u8] = b"OpenNCALayer platform interop content\r\n\x00\x01\xfe\xff end";

/// A key NCANode signs with: a test key of its repository.
pub struct NcKey {
    pub p12: Vec<u8>,
    pub password: &'static str,
}

impl NcKey {
    /// The `SignerRequest` object of NCANode's API.
    pub fn request(&self) -> Value {
        json!({ "key": STANDARD.encode(&self.p12), "password": self.password })
    }
}

/// The NCANode test keys (`cargo xtask fetch-fixtures`); `ceo_sign_revoked_2004.p12` is its
/// GOST 34.310-2004 key, `individual_valid_sign_2004.p12` an RSA-2048 key despite its name.
pub fn nc_key(profile: Profile) -> anyhow::Result<NcKey> {
    let (file, password) = match profile {
        Profile::Gost2015 => ("individual_valid_2015.p12", "Aa123456"),
        Profile::Gost2004 => ("ceo_sign_revoked_2004.p12", "Qwerty12"),
        Profile::Rsa => ("individual_valid_sign_2004.p12", "Qwerty12"),
    };
    let path = crate::fetch::ncanode_dir().join(file);
    ensure!(
        path.is_file(),
        "{} is missing: run `cargo xtask fetch-fixtures`",
        path.display()
    );
    Ok(NcKey {
        p12: std::fs::read(&path)?,
        password,
    })
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(text: &str) -> anyhow::Result<Vec<u8>> {
    STANDARD
        .decode(text.split_whitespace().collect::<String>())
        .context("not base64")
}

/// The grade string of a case: `key=value` pairs, one per judge, in a fixed order.
pub fn grade(parts: &[(&str, String)]) -> String {
    parts
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `STATUS/SUBINDICATION` of a graded signature.
pub fn grade_of(status: Option<&str>, sub: Option<&str>) -> String {
    match (status, sub) {
        (Some(s), Some(sub)) => format!("{s}/{sub}"),
        (Some(s), None) => s.to_owned(),
        _ => "none".to_owned(),
    }
}

/// NCANode's grades of the signers of a `/cms/verify` or `/pdf/verify` answer.
pub fn signer_grades(response: &Value) -> Vec<String> {
    response["signers"]
        .as_array()
        .map(|signers| {
            signers
                .iter()
                .map(|s| grade_of(s["status"].as_str(), s["subIndication"].as_str()))
                .collect()
        })
        .unwrap_or_default()
}

/// NCANode's grade of a good signature by a synthetic key: the issuer is not its NCA.
pub const NC_CHAIN_INCOMPLETE: &str = "INDETERMINATE/CHAIN_INCOMPLETE";
/// NCANode's grade of a good signature by an NCANode test key: its certificate expired.
pub const NC_EXPIRED: &str = "INDETERMINATE/OUT_OF_BOUNDS_NO_POE";
/// NCANode's grade of a bad signature value or reference digest.
pub const NC_REJECTED: &str = "INVALID/SIG_CRYPTO_FAILURE";

/// `bytes` with the first occurrence of `needle` changed in its last byte.
pub fn flip_in(bytes: &[u8], needle: &[u8]) -> anyhow::Result<Vec<u8>> {
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .context("the bytes to alter were not found")?;
    let mut altered = bytes.to_vec();
    altered[at + needle.len() - 1] ^= 0x01;
    Ok(altered)
}

/// The policy OID of the loopback TSA's requests (the NCA's GOST 2015 TSA policy).
pub const TSA_POLICY: &str = "1.2.398.3.3.2.6.2";

/// `--tsa-url`/`--tsa-policy` of the loopback TSA.
pub fn tsa_args(ctx: &Ctx) -> Vec<String> {
    vec![
        "--tsa-url".to_owned(),
        ctx.world.tsa_url(),
        "--tsa-policy".to_owned(),
        TSA_POLICY.to_owned(),
    ]
}

/// A fresh OCSP response for `cert` (issued by the matrix's root), produced one minute
/// after [`super::super::world::NOW`]: evidence of a signature made at `NOW`.
pub fn ocsp_for(ctx: &Ctx, cert: &x509_cert::Certificate) -> anyhow::Result<Vec<u8>> {
    use oncl_pki::http::{GetOptions, HttpRequest, HttpTransport};
    use oncl_pki::ocsp::{MockOcsp, request_der};
    let now = time::OffsetDateTime::from_unix_timestamp(super::super::world::NOW)?
        + time::Duration::seconds(60);
    let responder = MockOcsp::new(ctx.world.responder.clone()).with_now(now);
    let request = request_der(cert, &ctx.world.root_entry.cert);
    let reply = responder
        .send(&HttpRequest::post(
            &format!("{}/ocsp", ctx.world.origin),
            Some("application/ocsp-request"),
            &request,
            GetOptions::default(),
        ))
        .map_err(|e| anyhow::anyhow!("the mock OCSP responder: {e:?}"))?;
    Ok(reply.body)
}

/// The `--evidence-*` arguments of an LT/LTA signature or `extend` of `signer`: the root and
/// the TSA certificate, and OCSP responses for the signer and the TSA, as files in the
/// case directory.
pub fn evidence_args(ctx: &Ctx, signer: &Signer) -> anyhow::Result<Vec<String>> {
    use der::Encode as _;
    let files: [(&str, Vec<u8>, &str); 4] = [
        (
            "evidence-root.der",
            ctx.world.root_entry.cert.to_der()?,
            "--evidence-certificate",
        ),
        (
            "evidence-tsa.der",
            ctx.world.tsa.cert.to_der()?,
            "--evidence-certificate",
        ),
        (
            "evidence-signer.ocsp",
            ocsp_for(ctx, &signer.entry.cert)?,
            "--evidence-ocsp",
        ),
        (
            "evidence-tsa.ocsp",
            ocsp_for(ctx, &ctx.world.tsa.cert)?,
            "--evidence-ocsp",
        ),
    ];
    let mut args = Vec::new();
    for (name, bytes, flag) in files {
        let path = ctx.write(name, &bytes)?;
        args.push(flag.to_owned());
        args.push(path.display().to_string());
    }
    Ok(args)
}

/// The trust part of a verified signer: `signature/chain/validity`.
pub fn trust_summary(v: &super::super::oncl::Verified, index: usize) -> String {
    format!(
        "sig={}/chain={}/validity={}",
        v.check(index, "signature"),
        v.check(index, "chain"),
        v.check(index, "validity")
    )
}

/// The Kalkan JCE name of the signature algorithm of a GOST profile (hash and sign in one:
/// Streebog-512 with the 2015 curve, GOST R 34.11-94 with the 2004 curve).
pub fn kalkan_algorithm(profile: Profile) -> anyhow::Result<&'static str> {
    match profile {
        Profile::Gost2015 => Ok("ECGOST3410-2015-512"),
        Profile::Gost2004 => Ok("ECGOST34310"),
        Profile::Rsa => anyhow::bail!("Kalkan is the oracle of the GOST profiles, not of RSA"),
    }
}

/// Kalkan's verdict on `signature` (as the signer wrote it) over `data` with the public key
/// of the DER certificate `cert`.
pub fn kalkan_raw(
    ctx: &Ctx,
    profile: Profile,
    cert: &std::path::Path,
    data: &[u8],
    signature: &[u8],
) -> anyhow::Result<bool> {
    let data = ctx.write("kalkan.data", data)?;
    let signature = ctx.write("kalkan.sig", signature)?;
    let answer = ctx.java_json(&[
        "raw",
        kalkan_algorithm(profile)?,
        super::super::oncl::path_str(cert)?,
        super::super::oncl::path_str(&data)?,
        super::super::oncl::path_str(&signature)?,
    ])?;
    Ok(super::super::kalkan::verdict(&answer))
}

/// Kalkan accepts `signature` over `data` and rejects the same signature over altered
/// data: a verifier that said yes (or no) to everything fails here.
pub fn kalkan_raw_discriminates(
    ctx: &Ctx,
    profile: Profile,
    cert: &std::path::Path,
    data: &[u8],
    signature: &[u8],
    maker: &str,
) -> anyhow::Result<()> {
    ensure!(
        kalkan_raw(ctx, profile, cert, data, signature)?,
        "Kalkan ({}) rejected {maker}'s raw {} signature ({} bytes)",
        kalkan_algorithm(profile)?,
        profile.label(),
        signature.len()
    );
    let mut altered = data.to_vec();
    altered[0] ^= 1;
    ensure!(
        !kalkan_raw(ctx, profile, cert, &altered, signature)?,
        "Kalkan accepted {maker}'s signature over altered data"
    );
    Ok(())
}
