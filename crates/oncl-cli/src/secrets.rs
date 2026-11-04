use oncl_core::{OperationContext, OperationError};
use oncl_pki::{private_fs::PrivateDirectory, resource::ProcessingError};
use std::{
    io::{self, IsTerminal, Read},
    path::Path,
};
use zeroize::Zeroizing;

/// Reuses the SDK's pinned owner-only namespace and file ownership/link checks.
/// One optional terminal LF/CRLF is stripped; at most 4097 raw file bytes and
/// 4096 password UTF-8 bytes are admitted, without secret spool or reallocations.
pub fn read(
    path: Option<&Path>,
    interactive: bool,
    stdin_document: bool,
    ctx: &mut OperationContext,
) -> Result<Zeroizing<String>, OperationError> {
    ctx.resources().checkpoint()?;
    if let Some(path) = path {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(OperationError::InvalidKeySource)?;
        let directory = PrivateDirectory::open(parent).map_err(ProcessingError::from)?;
        let mut file = directory.open_file(name).map_err(ProcessingError::from)?;
        if file.metadata().map_err(ProcessingError::from)?.len() > 4097 {
            return Err(OperationError::SecretRequired);
        }
        let mut bytes = Zeroizing::new([0u8; 4097]);
        let mut count = 0;
        loop {
            ctx.resources().checkpoint()?;
            let mut probe = Zeroizing::new([0u8; 1]);
            let read = if count < bytes.len() {
                file.read(&mut bytes[count..])
            } else {
                file.read(&mut *probe)
            };
            ctx.resources().checkpoint()?;
            let n = match read {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result.map_err(ProcessingError::from)?,
            };
            if n == 0 {
                break;
            }
            if count == bytes.len() {
                return Err(OperationError::SecretRequired);
            }
            count = count.checked_add(n).ok_or(OperationError::SecretRequired)?;
        }
        let bytes = &bytes[..count];
        let bytes = bytes
            .strip_suffix(b"\r\n")
            .or_else(|| bytes.strip_suffix(b"\n"))
            .unwrap_or(bytes);
        if bytes.len() > 4096 {
            return Err(OperationError::SecretRequired);
        }
        return crate::terminal::finish(bytes);
    }
    if !interactive || stdin_document || !std::io::stdin().is_terminal() {
        return Err(OperationError::SecretRequired);
    }
    crate::terminal::read(ctx)
}

/// The API token of a remote session from standard input: at most 4096 bytes and one
/// trailing LF/CRLF, read into wiped fixed memory. Nothing is truncated: a longer input is
/// refused. Stdin is then not available as a document.
pub fn read_stdin(ctx: &mut OperationContext) -> Result<Zeroizing<String>, OperationError> {
    ctx.resources().checkpoint()?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(4098)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    io::stdin()
        .lock()
        .take(4098)
        .read_to_end(&mut bytes)
        .map_err(ProcessingError::from)?;
    ctx.resources().checkpoint()?;
    let token = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(&bytes);
    if token.is_empty() || token.len() > 4096 {
        return Err(OperationError::SecretRequired);
    }
    crate::terminal::finish(token)
}
