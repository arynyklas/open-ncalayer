//! `oncl-server install-file`: puts operator material (`server.toml`, key containers, password
//! and TLS files) into a private directory through the same private-file API the service reads
//! it with. On Windows nothing else can create such a file (the required ACL is a protected
//! one-entry DACL that `icacls`/`Set-Acl` cannot produce); on Unix it replaces `install -m 0600`.
use oncl_pki::private_fs::PrivateDirectory;
use std::{
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

/// Largest file accepted: a key container or certificate bundle; far above `server.toml`'s
/// own 64 KiB limit, so an oversized input is refused before anything is created.
pub const MAX_INSTALL_BYTES: usize = 16 * 1024 * 1024;

fn refused(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

/// A single plain file name: no separator, drive or stream syntax, no reserved device name.
pub fn validate_name(name: &str) -> io::Result<()> {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    // The private-file allow-list too, so a name it would refuse is refused before anything
    // (a directory) is created.
    let plain = !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if reserved || !plain || name.ends_with('.') {
        return Err(refused("invalid file name"));
    }
    Ok(())
}

/// Installs `name` into `directory` (created private if absent) from `input` or `stdin`.
/// Never overwrites; bytes are zeroized after use and never echoed; a partial file is removed.
pub fn install(
    directory: &Path,
    name: &str,
    input: Option<&Path>,
    stdin: &mut dyn Read,
) -> io::Result<usize> {
    validate_name(name)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let read = match input {
        Some(path) => std::fs::File::open(path)?
            .take(MAX_INSTALL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?,
        None => stdin
            .take(MAX_INSTALL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?,
    };
    if read > MAX_INSTALL_BYTES {
        return Err(refused("input too large"));
    }
    let created = !directory.exists();
    let private = if created {
        PrivateDirectory::create(directory)?
    } else {
        PrivateDirectory::open(directory)?
    };
    let mut file = match private.create_file(name) {
        Ok(file) => file,
        Err(error) => {
            // A directory this command made is not left behind; an existing one never is touched.
            if created {
                drop(private);
                let _ = std::fs::remove_dir(directory);
            }
            return Err(error);
        }
    };
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = private.remove_file(name);
        return Err(error);
    }
    private.sync()?;
    Ok(read)
}
