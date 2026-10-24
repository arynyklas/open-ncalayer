//! `cargo xtask interop-openssl`: signs with the synthetic `user-rsa-sign` key, attached and
//! detached, and checks that `openssl cms -verify` accepts both CMS. Files land in
//! `target/interop-openssl/`.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail, ensure};
use oncl_pki::cms::{SignOptions, sign};
use oncl_testkit::{read, synthetic};
use time::OffsetDateTime;

/// Content signed by the check.
const CONTENT: &[u8] = b"OpenNCALayer CMS interoperability check\r\n\x00\xff";

/// Runs the check; `root` is the workspace root.
///
/// # Errors
///
/// If signing fails, `openssl` cannot be run, or it does not report
/// `Verification successful` with the original content.
pub fn interop_openssl(root: &Path) -> anyhow::Result<()> {
    let key = synthetic("user-rsa-sign");
    let entry = oncl_pki::pkcs12::load(&read(&key.path), &key.password)?
        .into_iter()
        .next()
        .context("user-rsa-sign has no key")?;
    let dir = root.join("target/interop-openssl");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let content_path = dir.join("content.bin");
    fs::write(&content_path, CONTENT)?;

    for (name, encapsulate) in [("attached", true), ("detached", false)] {
        let opts = SignOptions {
            encapsulate,
            digested: false,
            signing_time: OffsetDateTime::now_utc(),
        };
        let cms_path = dir.join(format!("{name}.p7s"));
        fs::write(&cms_path, sign(&entry, CONTENT, &opts)?)?;
        let out_path = dir.join(format!("{name}.out"));

        let mut openssl = Command::new("openssl");
        openssl
            .args([
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-noverify",
                "-in",
            ])
            .arg(&cms_path)
            .arg("-out")
            .arg(&out_path);
        if !encapsulate {
            openssl.arg("-content").arg(&content_path);
        }
        let output = openssl
            .output()
            .context("running `openssl` (is it on PATH?)")?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() || !stderr.contains("Verification successful") {
            bail!(
                "openssl rejected the {name} CMS ({}): {}",
                output.status,
                stderr.trim()
            );
        }
        ensure!(
            fs::read(&out_path)? == CONTENT,
            "openssl returned other content for the {name} CMS"
        );
        println!("{name} CMS: {}", stderr.trim());
    }
    Ok(())
}
