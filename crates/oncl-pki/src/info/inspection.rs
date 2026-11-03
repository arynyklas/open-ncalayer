//! Read-only public metadata with inseparable operation reservations.
use super::{CertInfo, cert_info};
use crate::{
    cert::Certificate,
    digest::{DigestValue, HashState},
    key::HashAlg,
    resource::{ProcessingError, ResourceReservation, ResourceScope},
};
use der::Encode;
/// Trusted host work profile for read-only container inspection. Reaching a
/// bound is a resource refusal, not evidence that a valid store is malformed.
#[derive(Clone, Debug)]
pub struct InspectionLimits {
    pub max_entries: usize,
    pub max_safes: usize,
    pub kdf_iterations: u32,
    pub aggregate_kdf_iterations: u64,
    pub salt_bytes: usize,
    pub password_bytes: usize,
}
impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_safes: 64,
            kdf_iterations: 10_000,
            aggregate_kdf_iterations: 100_000,
            salt_bytes: 1024,
            password_bytes: 4096,
        }
    }
}
impl InspectionLimits {
    pub fn validate(&self) -> Result<(), ProcessingError> {
        if self.max_entries == 0
            || self.max_entries > 4096
            || self.max_safes == 0
            || self.max_safes > 64
            || self.kdf_iterations == 0
            || self.kdf_iterations > crate::pkcs12::MAX_ITERATIONS
            || self.aggregate_kdf_iterations == 0
            || self.aggregate_kdf_iterations > 1_000_000_000
            || self.salt_bytes == 0
            || self.salt_bytes > 1 << 20
            || self.password_bytes == 0
            || self.password_bytes > 1 << 20
        {
            return Err(ProcessingError::InvalidLimits);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataIntegrity {
    NotApplicable,
    NotPresent,
    PasswordMacVerified,
}
#[derive(Debug)]
pub struct PublicEntry {
    alias: Option<String>,
    certificate: Option<Vec<u8>>,
    info: Option<CertInfo>,
    fingerprint: Option<DigestValue>,
}
impl PublicEntry {
    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }
    pub fn certificate_der(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }
    pub fn fingerprint(&self) -> Option<&DigestValue> {
        self.fingerprint.as_ref()
    }
    pub fn subject_cn(&self) -> Option<&str> {
        self.info.as_ref()?.subject_cn.as_deref()
    }
    pub fn serial_hex(&self) -> Option<&str> {
        self.info.as_ref().map(|info| info.serial_hex.as_str())
    }
    pub fn signature_algorithm_oid(&self) -> Option<&str> {
        self.info
            .as_ref()
            .map(|info| info.signature_alg_oid.as_str())
    }
    pub fn public_key_algorithm_oid(&self) -> Option<&str> {
        self.info.as_ref().map(|info| info.spki_alg_oid.as_str())
    }
    pub fn not_before(&self) -> Option<time::OffsetDateTime> {
        self.info.as_ref().map(|info| info.not_before)
    }
    pub fn not_after(&self) -> Option<time::OffsetDateTime> {
        self.info.as_ref().map(|info| info.not_after)
    }
}
pub struct PublicMetadata {
    entries: Vec<PublicEntry>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
    scope: ResourceScope,
    integrity: MetadataIntegrity,
}
impl std::fmt::Debug for PublicMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicMetadata")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}
impl PublicMetadata {
    pub fn check_scope(&self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        if !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "metadata belongs to another operation",
            ));
        }
        self.scope.checkpoint()?;
        scope.checkpoint()
    }
    /// Public-only projection for a host-authorized source slot. The alias is a
    /// name, not a claim that its certificate is trusted or its private key used.
    pub fn named_certificate(
        alias: &str,
        certificate: Option<&[u8]>,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        let size = alias
            .len()
            .checked_add(certificate.map_or(0, <[u8]>::len))
            .ok_or(ProcessingError::MetadataLimit)?;
        let mut result = Self::admitted(size, scope)?;
        let cert = certificate
            .map(crate::cert::parse)
            .transpose()
            .map_err(|_| ProcessingError::InvalidInput("certificate input"))?;
        result.push(Some(alias), cert.as_ref())?;
        scope.checkpoint()?;
        Ok(result)
    }
    /// Admission covers parser expansion, certificate/name objects and the public
    /// projection simultaneously. Retain the whole immutable owner after Context drop.
    pub(crate) fn admitted(bytes: usize, scope: &ResourceScope) -> Result<Self, ProcessingError> {
        let bytes = (bytes as u64)
            .checked_mul(64)
            .and_then(|n| n.checked_add(4096))
            .ok_or(ProcessingError::MetadataLimit)?;
        let memory = scope.reserve_memory(bytes)?;
        let metadata = scope.reserve_metadata(bytes)?;
        Ok(Self {
            entries: Vec::new(),
            _memory: memory,
            _metadata: metadata,
            scope: scope.retain(),
            integrity: MetadataIntegrity::NotApplicable,
        })
    }
    pub(crate) fn push(
        &mut self,
        alias: Option<&str>,
        cert: Option<&Certificate>,
    ) -> Result<(), ProcessingError> {
        if self.entries.len() >= 4096 {
            return Err(ProcessingError::MetadataLimit);
        }
        let certificate = cert
            .map(|cert| {
                cert.to_der()
                    .map_err(|_| ProcessingError::InvalidInput("certificate DER"))
            })
            .transpose()?;
        let fingerprint = certificate.as_ref().map(|der| {
            let mut hash = HashState::new(HashAlg::Sha256);
            hash.update(der);
            hash.finish()
        });
        self.entries
            .try_reserve_exact(1)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        self.entries.push(PublicEntry {
            alias: alias.map(str::to_owned),
            certificate,
            info: cert.map(cert_info),
            fingerprint,
        });
        Ok(())
    }
    pub fn certificate(input: &[u8], scope: &ResourceScope) -> Result<Self, ProcessingError> {
        let mut result = Self::admitted(input.len(), scope)?;
        scope.checkpoint()?;
        let cert = crate::cert::parse(input)
            .map_err(|_| ProcessingError::InvalidInput("certificate input"))?;
        result.push(None, Some(&cert))?;
        scope.checkpoint()?;
        Ok(result)
    }
    pub fn entries(&self) -> &[PublicEntry] {
        &self.entries
    }
    pub fn integrity(&self) -> MetadataIntegrity {
        self.integrity
    }
    pub(crate) fn set_integrity(&mut self, integrity: MetadataIntegrity) {
        self.integrity = integrity;
    }
    pub(crate) fn sort(&mut self) {
        self.entries
            .sort_by(|left, right| left.alias.cmp(&right.alias));
    }
}
