//! Allocation-free length/count checks precede every bound-certificate copy.
use super::*;
use der::Encode;
use oncl_pki::{cert::Certificate, resource::ResourceScope};
impl CapabilityAdmission {
    pub(super) fn admit_metadata(&mut self, bytes: u64) -> Result<(), OperationError> {
        let target = self
            .base
            .checked_add(bytes.max(self.host_work))
            .ok_or(ProcessingError::MetadataLimit)?;
        if target > self.metadata.bytes() {
            self.metadata.grow(target - self.metadata.bytes())?;
        }
        self.host_work = self.host_work.max(bytes);
        Ok(())
    }
}
pub(super) fn admit_bound_metadata(
    state: &mut BackendState,
    scope: &ResourceScope,
    leaf: &Certificate,
    chain: &[Certificate],
    alias: &str,
) -> Result<(), OperationError> {
    scope.checkpoint()?;
    let count = (chain.len() as u64)
        .checked_add(1)
        .ok_or(ProcessingError::MetadataLimit)?;
    let slots = count
        .checked_mul(
            (2 * std::mem::size_of::<Vec<u8>>()
                + std::mem::size_of::<(usize, &[u8])>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<&[u8]>()) as u64,
        )
        .ok_or(ProcessingError::MetadataLimit)?;
    // Admit collection slots first, before even traversing a host-controlled count.
    state
        .admission
        .as_mut()
        .ok_or(OperationError::InvalidContext)?
        .admit_metadata(slots)?;
    let mut bytes = 0u64;
    for certificate in std::iter::once(leaf).chain(chain) {
        scope.checkpoint()?;
        let len: u32 = certificate
            .encoded_len()
            .map_err(|_| ProcessingError::InvalidInput("invalid bound certificate"))?
            .into();
        bytes = bytes
            .checked_add(u64::from(len))
            .ok_or(ProcessingError::MetadataLimit)?;
    }
    // DER values, their aggregate and encoder capacity coexist. Metadata already
    // debits RAM: grow that one guard, never reserve the same RAM a second time.
    let work = bytes
        .checked_mul(3)
        .and_then(|n| n.checked_add(slots))
        .and_then(|n| n.checked_add((alias.len() as u64).checked_mul(2)?))
        .ok_or(ProcessingError::MetadataLimit)?;
    state
        .admission
        .as_mut()
        .ok_or(OperationError::InvalidContext)?
        .admit_metadata(work)
}

pub(super) fn admit_cms_output(
    admission: &mut CapabilityAdmission,
    scope: &ResourceScope,
    transfer: usize,
    import: Import,
    output: abi::CmsOutput,
    plan: oncl_pki::cms::CmsAdmission,
) -> Result<(), OperationError> {
    scope.checkpoint()?;
    admission.admit_metadata(plan.metadata_bytes)?;
    if plan.memory_bytes
        > (transfer as u64)
            .checked_mul(8)
            .ok_or(ProcessingError::MemoryLimit)?
    {
        return Err(ProcessingError::MemoryLimit.into());
    }
    if let Some(der) = plan.output_der_bytes {
        let size = match output {
            abi::CmsOutput::Der => der,
            abi::CmsOutput::Base64 | abi::CmsOutput::Pem => {
                let base64 = der
                    .checked_add(2)
                    .and_then(|n| (n / 3).checked_mul(4))
                    .ok_or(ProcessingError::OutputLimit)?;
                if output == abi::CmsOutput::Base64 {
                    base64
                } else {
                    let lines = base64.checked_add(63).ok_or(ProcessingError::OutputLimit)? / 64;
                    let newline = if cfg!(windows) { 2 } else { 1 };
                    base64
                        .checked_add(36)
                        .and_then(|n| n.checked_add(lines.checked_add(2)?.checked_mul(newline)?))
                        .ok_or(ProcessingError::OutputLimit)?
                }
            }
        };
        let header = match size {
            0..=23 => 1,
            24..=255 => 2,
            256..=65535 => 3,
            65536..=0xffff_ffff => 5,
            _ => 9,
        };
        let framing = if import == Import::KeysSignCmsEx {
            12
        } else {
            4
        };
        if size
            .checked_add(header)
            .and_then(|n| n.checked_add(framing))
            .ok_or(ProcessingError::ContainerLimit)?
            > transfer as u64
        {
            return Err(ProcessingError::ContainerLimit.into());
        }
        scope.check_output_capacity(size)?;
    }
    Ok(())
}
