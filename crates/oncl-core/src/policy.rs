use oncl_pki::key::SigAlg;
use oncl_pki::validation::ValidationPolicy;

/// The implemented action family. New actions arrive with real implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Hash,
    /// Hash and sign the document supplied to this operation.
    Sign,
    /// Explicit use of a caller-supplied digest, not a future format-sign action.
    SignDigest,
    /// Bounded existing CMS validation and host-only PKI transport.
    Validate,
    /// Source-based CMS signature and full host-policy verification.
    Verify,
    /// Structural CMS content extraction; never a verification assertion.
    Extract,
}

/// Authority supplied by a trusted host/authorizer, intentionally not Deserialize.
#[derive(Clone, Debug)]
pub struct ExecutionGrant {
    hash: bool,
    sign: bool,
    sign_digest: bool,
    validate: bool,
    verify: bool,
    extract: bool,
    keys: Vec<crate::keys::KeyId>,
}
impl ExecutionGrant {
    pub fn new(actions: impl IntoIterator<Item = Action>) -> Self {
        let mut grant = Self {
            hash: false,
            sign: false,
            sign_digest: false,
            keys: Vec::new(),
            validate: false,
            verify: false,
            extract: false,
        };
        for action in actions {
            match action {
                Action::Hash => grant.hash = true,
                Action::Sign => grant.sign = true,
                Action::SignDigest => grant.sign_digest = true,
                Action::Validate => grant.validate = true,
                Action::Verify => grant.verify = true,
                Action::Extract => grant.extract = true,
            }
        }
        grant
    }
    pub fn allows(&self, action: Action) -> bool {
        match action {
            Action::Hash => self.hash,
            Action::Sign => self.sign,
            Action::SignDigest => self.sign_digest,
            Action::Validate => self.validate,
            Action::Verify => self.verify,
            Action::Extract => self.extract,
        }
    }
    pub fn with_keys(mut self, keys: impl IntoIterator<Item = crate::keys::KeyId>) -> Self {
        self.keys = keys.into_iter().collect();
        self
    }
    pub fn allows_key(&self, key: &crate::keys::KeyId) -> bool {
        self.keys.contains(key)
    }
    pub(crate) fn is_empty(&self) -> bool {
        !self.hash
            && !self.sign
            && !self.sign_digest
            && !self.validate
            && !self.verify
            && !self.extract
    }
}

/// Owned host policy. Signature/validation settings are vocabulary for subsequent
/// PKI operations, not fictitious validation performed by a hash operation.
#[derive(Clone, Debug)]
pub struct OperationPolicy {
    pub validation: ValidationPolicy,
    pub allowed_signature_algorithms: &'static [SigAlg],
    pub allow_prehashed: bool,
}
impl OperationPolicy {
    pub fn strict_online() -> Self {
        Self {
            validation: ValidationPolicy::StrictOnline,
            allowed_signature_algorithms: &[
                SigAlg::Gost2004,
                SigAlg::Gost2015_512,
                SigAlg::RsaSha256,
            ],
            allow_prehashed: false,
        }
    }
    pub fn offline_report() -> Self {
        Self {
            validation: ValidationPolicy::OfflineReport,
            ..Self::strict_online()
        }
    }
    pub fn ncalayer_compatibility() -> Self {
        Self {
            validation: ValidationPolicy::NcalayerCompatibility,
            allowed_signature_algorithms: &[
                SigAlg::Gost2004,
                SigAlg::Gost2015_512,
                SigAlg::RsaSha256,
                SigAlg::RsaSha1,
            ],
            allow_prehashed: false,
        }
    }
}
