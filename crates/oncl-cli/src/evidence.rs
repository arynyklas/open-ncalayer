//! Operator-supplied public validation material for CAdES/PAdES evidence levels
//! and keyless extension: certificates, complete OCSPResponse values and CRLs
//! as DER files. Nothing here is trust: the SDK rechecks every path, status,
//! freshness and signature. Files are read under the same bounded rules and the
//! same shared configuration reservation as host roots, before any document or
//! key I/O.
use crate::{args::Cli, control::Control};
use oncl_core::OperationError;
use oncl_pki::{
    cert::Certificate,
    resource::{ConfigurationReservation, ProcessingError},
};
use std::{fs::File, io::Read, path::PathBuf};

pub const MAX_ITEMS: usize = 64;
const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Default)]
pub struct Material {
    pub certificates: Vec<Certificate>,
    pub ocsp: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}
impl Material {
    pub fn ocsp_slices(&self) -> Vec<&[u8]> {
        self.ocsp.iter().map(Vec::as_slice).collect()
    }
    pub fn crl_slices(&self) -> Vec<&[u8]> {
        self.crls.iter().map(Vec::as_slice).collect()
    }
}
pub fn any(cli: &Cli) -> bool {
    !cli.evidence_certificate.is_empty()
        || !cli.evidence_ocsp.is_empty()
        || !cli.evidence_crl.is_empty()
}
fn blob(
    path: &PathBuf,
    control: &Control,
    total: &mut u64,
    reservation: &mut ConfigurationReservation,
    metadata_factor: u64,
) -> Result<Vec<u8>, OperationError> {
    control.check()?;
    let mut file = File::open(path).map_err(ProcessingError::from)?;
    let length = file.metadata().map_err(ProcessingError::from)?.len();
    let next = total
        .checked_add(length)
        .filter(|n| *n <= MAX_TOTAL_BYTES && length <= MAX_FILE_BYTES)
        .ok_or(ProcessingError::MetadataLimit)?;
    reservation.grow(
        length,
        length
            .checked_mul(metadata_factor)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    *total = next;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    let read = Read::by_ref(&mut file)
        .take(length + 1)
        .read_to_end(&mut bytes);
    control.check()?;
    read.map_err(ProcessingError::from)?;
    if bytes.len() as u64 != length {
        return Err(ProcessingError::InvalidInput("evidence file changed during intake").into());
    }
    Ok(bytes)
}
pub fn load(
    cli: &Cli,
    control: &Control,
    reservation: &mut ConfigurationReservation,
) -> Result<Material, OperationError> {
    let mut total = 0u64;
    let mut material = Material::default();
    for path in &cli.evidence_certificate {
        let bytes = blob(
            path,
            control,
            &mut total,
            reservation,
            crate::bounded::CERTIFICATE_METADATA_FACTOR,
        )?;
        material.certificates.push(
            oncl_pki::cert::parse(&bytes)
                .map_err(|_| ProcessingError::InvalidInput("invalid evidence certificate"))?,
        );
    }
    for path in &cli.evidence_ocsp {
        material
            .ocsp
            .push(blob(path, control, &mut total, reservation, 2)?);
    }
    for path in &cli.evidence_crl {
        material
            .crls
            .push(blob(path, control, &mut total, reservation, 2)?);
    }
    Ok(material)
}
