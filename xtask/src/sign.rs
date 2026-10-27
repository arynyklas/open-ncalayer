//! `cargo xtask sign`: the minisign key of the update index and the signature of an index.
//!
//! - [`keygen`] makes the maintainer's key pair: [`SECRET_KEY_FILE`], encrypted with a
//!   password, and [`PUBLIC_KEY_FILE`], which goes into `crates/oncl-update/keys/` as
//!   `current.pub` or `next.pub`. It refuses a directory whose secret key git could commit.
//! - [`sign`] writes `<index>.minisig` beside an index, in the prehashed mode, with the
//!   trusted comment `channel=<channel>;seq=<seq>` the client checks
//!   (`oncl_update::trusted_comment`).
//!
//! Passwords are read by the CLI without echo and held in `Zeroizing`; these functions take
//! them as arguments, so tests use keys of their own in temporary directories. minisign
//! takes the password as a `String` of its own and does not wipe it, nor the decrypted key.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use minisign::{KeyPair, PublicKey, SecretKey};
use oncl_update::{Index, MAX_INDEX_LEN, trusted_comment};
use time::OffsetDateTime;

/// The secret key that [`keygen`] writes.
pub const SECRET_KEY_FILE: &str = "oncl-index.key";

/// The public key that [`keygen`] writes.
pub const PUBLIC_KEY_FILE: &str = "oncl-index.pub";

/// Where the client's trusted public keys live, from the workspace root.
pub const TRUSTED_KEYS_DIR: &str = "crates/oncl-update/keys";

/// The files of a new key pair.
#[derive(Debug)]
pub struct KeyFiles {
    /// The encrypted secret key.
    pub secret: PathBuf,
    /// The public key.
    pub public: PathBuf,
}

/// The files [`keygen`] would write into `out`, after checking that it may: neither exists
/// yet, and git would not commit the secret key (see [`refuse_committable`]).
///
/// # Errors
///
/// If a key file exists already, or the secret key would be committable.
pub fn keygen_target(out: &Path) -> anyhow::Result<KeyFiles> {
    let files = KeyFiles {
        secret: out.join(SECRET_KEY_FILE),
        public: out.join(PUBLIC_KEY_FILE),
    };
    for path in [&files.secret, &files.public] {
        if path.exists() {
            bail!(
                "{} exists already; refusing to overwrite it",
                path.display()
            );
        }
    }
    refuse_committable(&files.secret)?;
    Ok(files)
}

/// Makes a key pair in `out` (created if missing): the secret key encrypted with
/// `password`, and the public key.
///
/// # Errors
///
/// The errors of [`keygen_target`], an empty password, or a failure to write.
pub fn keygen(out: &Path, password: &str) -> anyhow::Result<KeyFiles> {
    let files = keygen_target(out)?;
    if password.is_empty() {
        bail!("the password of the secret key must not be empty");
    }
    let pair = KeyPair::generate_encrypted_keypair(Some(password.to_owned()))
        .context("generating the key pair")?;
    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let secret = pair
        .sk
        .to_box(Some("OpenNCALayer update index secret key"))
        .context("encoding the secret key")?;
    write_new(&files.secret, &secret.to_bytes(), true)?;
    let public = pair.pk.to_box().context("encoding the public key")?;
    write_new(&files.public, &public.to_bytes(), false)?;
    Ok(files)
}

/// Reads the encrypted secret key at `path`.
///
/// # Errors
///
/// If the file cannot be read, is not an encrypted minisign secret key, or `password` is
/// wrong.
pub fn load_secret_key(path: &Path, password: &str) -> anyhow::Result<SecretKey> {
    SecretKey::from_file(path, Some(password.to_owned()))
        .with_context(|| format!("reading the secret key {}", path.display()))
}

/// `<index>.minisig`, the signature beside `index`.
pub fn signature_path(index: &Path) -> PathBuf {
    let mut name = index.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

/// Signs the index at `index` with `key` into [`signature_path`]. An index whose asset URLs
/// are not the project's releases ([`crate::index::check_asset_urls`]) is not signed.
/// Before writing, the signature is verified as the client would verify it at `now`, so an
/// index that is invalid or already expired is not signed either.
///
/// # Errors
///
/// If the index cannot be read or is refused by these checks, or signing fails.
pub fn sign(index: &Path, key: &SecretKey, now: OffsetDateTime) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(index).with_context(|| format!("reading {}", index.display()))?;
    if bytes.len() as u64 > MAX_INDEX_LEN {
        bail!(
            "{} is larger than {MAX_INDEX_LEN} bytes, the client's limit",
            index.display()
        );
    }
    let parsed =
        Index::from_json(&bytes).with_context(|| format!("reading {}", index.display()))?;
    crate::index::check_asset_urls(&parsed)
        .with_context(|| format!("not signing {}", index.display()))?;
    let comment = trusted_comment(parsed.channel, parsed.seq);
    let public = PublicKey::from_secret_key(key).context("the public key of the secret key")?;
    let signature = minisign::sign(
        Some(&public),
        key,
        Cursor::new(&bytes),
        Some(&comment),
        Some(&format!("OpenNCALayer update index, {comment}")),
    )
    .context("signing")?
    .into_string();

    let trusted = oncl_update::PublicKey::decode(
        &public
            .to_box()
            .context("encoding the public key")?
            .into_string(),
    )
    .context("decoding the public key")?;
    oncl_update::verify(
        &bytes,
        signature.as_bytes(),
        &[trusted],
        parsed.channel,
        None,
        now,
    )
    .with_context(|| format!("the client would refuse {}", index.display()))?;

    let path = signature_path(index);
    fs::write(&path, signature).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Refuses `secret` if it lies in a git work tree and is not ignored there, so the secret
/// key is never committed by accident. A path outside any work tree passes.
///
/// The deepest existing directory of the path is resolved first (symlinks, junctions,
/// `..`), so a link into a work tree is caught and `../keys` beside one is not mistaken for
/// a path in it; git itself then says whether that directory is in a work tree and whether
/// the rest of the path is ignored there. A tracked file counts as not ignored.
///
/// # Errors
///
/// If the path is committable, names a directory with `..` after its last existing
/// directory, or git cannot tell.
pub fn refuse_committable(secret: &Path) -> anyhow::Result<()> {
    let absolute =
        std::path::absolute(secret).with_context(|| format!("resolving {}", secret.display()))?;
    let no_name = || format!("{}: no file name", secret.display());
    let mut rest: Vec<OsString> = vec![absolute.file_name().with_context(no_name)?.to_owned()];
    let mut existing = absolute.parent().with_context(no_name)?;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().with_context(|| {
                    format!(
                        "{}: write the directory without `..` after its last existing part",
                        secret.display()
                    )
                })?;
                rest.push(name.to_owned());
                existing = existing.parent().with_context(no_name)?;
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", existing.display())),
        }
    }
    let dir = plain(
        fs::canonicalize(existing).with_context(|| format!("resolving {}", existing.display()))?,
    );
    let relative = rest
        .iter()
        .rev()
        .map(|c| c.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");

    // `LC_ALL=C`: the message below is matched in English.
    let inside = Command::new("git")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(&dir)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .context("running git to check that the secret key would not be committed")?;
    if !inside.status.success() {
        let stderr = String::from_utf8_lossy(&inside.stderr);
        if stderr.contains("not a git repository") {
            return Ok(());
        }
        bail!(
            "git rev-parse failed in {} ({}): {}; not writing the secret key there",
            dir.display(),
            inside.status,
            stderr.trim()
        );
    }
    if String::from_utf8_lossy(&inside.stdout).trim() != "true" {
        // A `.git` directory or a bare repository: nothing there is committed.
        return Ok(());
    }
    let status = Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["check-ignore", "--quiet", "--"])
        .arg(&relative)
        .status()
        .context("running git to check that the secret key would not be committed")?;
    match status.code() {
        Some(0) => Ok(()),
        Some(1) => bail!(
            "{} is in a git work tree and not ignored: keep the secret key outside the \
             repository (or in an ignored directory)",
            secret.display(),
        ),
        _ => bail!(
            "git check-ignore failed in {} ({status}); not writing the secret key there",
            dir.display()
        ),
    }
}

/// `path` without the `\\?\` prefix `canonicalize` gives on Windows, which git may not
/// read.
fn plain(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(text) = path.to_str() {
        if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{unc}"));
        }
        if let Some(local) = text.strip_prefix(r"\\?\")
            && local.as_bytes().get(1) == Some(&b':')
        {
            return PathBuf::from(local);
        }
    }
    path
}

/// Writes a file that must not exist yet; `private` makes it readable by its owner only
/// (on Unix).
fn write_new(path: &Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))
}
