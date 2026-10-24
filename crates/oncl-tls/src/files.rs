//! TLS files in the data directory and the rustls server configuration built from them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{InconsistentKeys, ServerConfig};

use crate::{TlsError, TlsInfo, TlsMaterial};

/// The TLS directory (`<data dir>/tls`) and the names of the files in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub dir: PathBuf,
}

impl TlsFiles {
    /// Local CA certificate, PEM.
    pub fn ca_pem(&self) -> PathBuf {
        self.dir.join("OpenNCALayer-CA.crt")
    }

    /// Local CA certificate, DER (what `certutil -addstore` and the Windows UI take).
    pub fn ca_der(&self) -> PathBuf {
        self.dir.join("OpenNCALayer-CA.cer")
    }

    /// Server certificate chain, leaf first, PEM.
    pub fn chain_pem(&self) -> PathBuf {
        self.dir.join("server.crt")
    }

    /// Server private key, PEM.
    pub fn key_pem(&self) -> PathBuf {
        self.dir.join("server.key")
    }

    /// [`TlsInfo`] as JSON.
    pub fn info(&self) -> PathBuf {
        self.dir.join("tls.json")
    }
}

/// Writes `m` into `files.dir`, creating the directory.
///
/// Every file is written to a temporary sibling and renamed into place; `tls.json` goes last,
/// so [`load_info`] sees the new material only after all other files are in place. CA files
/// left over from a previously generated set are removed when `m` has no CA (imported).
///
/// `server.key` is created with mode `0600` on Unix. On Windows no ACL is changed: the file
/// inherits the ACL of the data directory (`%APPDATA%\OpenNCALayer`, which by default is
/// accessible only to the user, SYSTEM and Administrators).
pub fn save(files: &TlsFiles, m: &TlsMaterial) -> io::Result<()> {
    fs::create_dir_all(&files.dir)?;
    write_file(&files.key_pem(), m.key_pem.as_bytes(), true)?;
    write_file(&files.chain_pem(), m.chain_pem.as_bytes(), false)?;
    match (&m.ca_pem, &m.ca_der) {
        (Some(ca_pem), Some(ca_der)) => {
            write_file(&files.ca_pem(), ca_pem.as_bytes(), false)?;
            write_file(&files.ca_der(), ca_der, false)?;
        }
        _ => {
            remove_if_exists(&files.ca_pem())?;
            remove_if_exists(&files.ca_der())?;
        }
    }
    let info = serde_json::to_vec_pretty(&m.info).map_err(io::Error::other)?;
    write_file(&files.info(), &info, false)
}

/// Reads `tls.json`; `Ok(None)` when TLS has not been set up yet. A corrupt file is an
/// [`io::ErrorKind::InvalidData`] error.
pub fn load_info(files: &TlsFiles) -> io::Result<Option<TlsInfo>> {
    let bytes = match fs::read(files.info()) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// A rustls server configuration (ring provider, TLS 1.3 and 1.2, no client authentication)
/// serving `server.crt` with `server.key`.
pub fn server_config(files: &TlsFiles) -> Result<ServerConfig, TlsError> {
    let chain_path = files.chain_pem();
    let chain = CertificateDer::pem_file_iter(&chain_path)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| TlsError::Parse(format!("{}: {e}", chain_path.display())))?;
    if chain.is_empty() {
        return Err(TlsError::Parse(format!(
            "{}: no certificate",
            chain_path.display()
        )));
    }
    let key_path = files.key_pem();
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|e| TlsError::Parse(format!("{}: {e}", key_path.display())))?;

    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TlsError::Parse(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| match e {
            rustls::Error::InconsistentKeys(InconsistentKeys::KeyMismatch) => TlsError::KeyMismatch,
            e => TlsError::Parse(e.to_string()),
        })
}

fn write_file(path: &Path, contents: &[u8], private: bool) -> io::Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    remove_if_exists(&tmp)?;
    let mut file = create_new(&tmp, private)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}

#[cfg(unix)]
fn create_new(path: &Path, private: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    if private {
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(unix))]
fn create_new(path: &Path, _private: bool) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
