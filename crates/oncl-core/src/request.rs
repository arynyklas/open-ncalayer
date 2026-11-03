//! Only profiles backed by complete operation implementations are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyProfile {
    Cms,
    #[cfg(feature = "pdf")]
    Pdf,
    #[cfg(feature = "pdf")]
    Pades(oncl_pki::evidence::AdesLevel),
    Cades(oncl_pki::evidence::AdesLevel),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyRequest {
    profile: VerifyProfile,
    limits: Option<oncl_pki::evidence::EvidenceLimits>,
}
impl VerifyRequest {
    #[cfg(feature = "pdf")]
    pub const fn pdf() -> Self {
        Self {
            profile: VerifyProfile::Pdf,
            limits: None,
        }
    }
    #[cfg(feature = "pdf")]
    pub const fn pades(
        required: oncl_pki::evidence::AdesLevel,
        limits: oncl_pki::evidence::EvidenceLimits,
    ) -> Self {
        Self {
            profile: VerifyProfile::Pades(required),
            limits: Some(limits),
        }
    }
    pub const fn cms() -> Self {
        Self {
            profile: VerifyProfile::Cms,
            limits: None,
        }
    }
    pub const fn profile(&self) -> VerifyProfile {
        self.profile
    }
    pub const fn cades(
        required: oncl_pki::evidence::AdesLevel,
        limits: oncl_pki::evidence::EvidenceLimits,
    ) -> Self {
        Self {
            profile: VerifyProfile::Cades(required),
            limits: Some(limits),
        }
    }
    pub const fn evidence_limits(&self) -> Option<oncl_pki::evidence::EvidenceLimits> {
        self.limits
    }
}

/// The complete implemented signature family; no filename inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignProfile {
    Cms,
    Raw,
    Cades(oncl_pki::evidence::AdesLevel),
    #[cfg(feature = "pdf")]
    Pdf,
    #[cfg(feature = "pdf")]
    Pades(oncl_pki::evidence::AdesLevel),
}
/// A one-shot request: detached Add sources and secrets are borrowed, not
/// cloned, serialized or included in Debug output.
pub struct SignRequest<'a> {
    pub(crate) mode: SignMode<'a>,
}
pub(crate) enum SignMode<'a> {
    RawMessage(crate::keys::KeyRequest<'a>),
    RawDigest(crate::keys::KeyRequest<'a>, oncl_pki::digest::DigestValue),
    CmsCreate(Vec<crate::keys::KeyRequest<'a>>, bool),
    CmsAdd(
        Vec<crate::keys::KeyRequest<'a>>,
        Option<oncl_pki::io::Source<'a>>,
    ),
    CadesCreate(
        Vec<crate::keys::KeyRequest<'a>>,
        bool,
        oncl_pki::evidence::AdesLevel,
        oncl_pki::cms::ades::ValidationMaterial<'a>,
        oncl_pki::evidence::EvidenceLimits,
    ),
    CadesAdd(
        Vec<crate::keys::KeyRequest<'a>>,
        Option<oncl_pki::io::Source<'a>>,
        oncl_pki::evidence::AdesLevel,
        oncl_pki::cms::ades::ValidationMaterial<'a>,
        oncl_pki::evidence::EvidenceLimits,
    ),
    #[cfg(feature = "pdf")]
    Pdf(crate::keys::KeyRequest<'a>, oncl_pdf::PdfSignProfile),
    #[cfg(feature = "pdf")]
    Pades(
        crate::keys::KeyRequest<'a>,
        oncl_pdf::PdfSignProfile,
        oncl_pki::evidence::AdesLevel,
        oncl_pki::cms::ades::ValidationMaterial<'a>,
        oncl_pki::evidence::EvidenceLimits,
    ),
}
impl<'a> SignRequest<'a> {
    /// Incrementally sign an existing PDF, validating every existing signature
    /// before Add. One explicit key application per invocation; Action::Sign.
    #[cfg(feature = "pdf")]
    pub fn pdf(key: crate::keys::KeyRequest<'a>, profile: oncl_pdf::PdfSignProfile) -> Self {
        Self {
            mode: SignMode::Pdf(key, profile),
        }
    }
    #[cfg(feature = "pdf")]
    pub fn pades(
        key: crate::keys::KeyRequest<'a>,
        profile: oncl_pdf::PdfSignProfile,
        level: oncl_pki::evidence::AdesLevel,
        material: oncl_pki::cms::ades::ValidationMaterial<'a>,
        limits: oncl_pki::evidence::EvidenceLimits,
    ) -> Self {
        Self {
            mode: SignMode::Pades(key, profile, level, material, limits),
        }
    }
    pub fn raw_message(key: crate::keys::KeyRequest<'a>) -> Self {
        Self {
            mode: SignMode::RawMessage(key),
        }
    }
    pub fn raw_digest(
        key: crate::keys::KeyRequest<'a>,
        digest: oncl_pki::digest::DigestValue,
    ) -> Self {
        Self {
            mode: SignMode::RawDigest(key, digest),
        }
    }
    pub fn cms_create(keys: Vec<crate::keys::KeyRequest<'a>>, attached: bool) -> Self {
        Self {
            mode: SignMode::CmsCreate(keys, attached),
        }
    }
    pub fn cms_add(
        keys: Vec<crate::keys::KeyRequest<'a>>,
        detached: Option<oncl_pki::io::Source<'a>>,
    ) -> Self {
        Self {
            mode: SignMode::CmsAdd(keys, detached),
        }
    }
    pub fn cades_create(
        keys: Vec<crate::keys::KeyRequest<'a>>,
        attached: bool,
        level: oncl_pki::evidence::AdesLevel,
        material: oncl_pki::cms::ades::ValidationMaterial<'a>,
        reader_limits: oncl_pki::evidence::EvidenceLimits,
    ) -> Self {
        Self {
            mode: SignMode::CadesCreate(keys, attached, level, material, reader_limits),
        }
    }
    pub fn cades_add(
        keys: Vec<crate::keys::KeyRequest<'a>>,
        detached: Option<oncl_pki::io::Source<'a>>,
        level: oncl_pki::evidence::AdesLevel,
        material: oncl_pki::cms::ades::ValidationMaterial<'a>,
        reader_limits: oncl_pki::evidence::EvidenceLimits,
    ) -> Self {
        Self {
            mode: SignMode::CadesAdd(keys, detached, level, material, reader_limits),
        }
    }
    pub fn profile(&self) -> SignProfile {
        match self.mode {
            SignMode::RawMessage(_) | SignMode::RawDigest(..) => SignProfile::Raw,
            SignMode::CmsCreate(..) | SignMode::CmsAdd(..) => SignProfile::Cms,
            SignMode::CadesCreate(_, _, level, _, _) | SignMode::CadesAdd(_, _, level, _, _) => {
                SignProfile::Cades(level)
            }
            #[cfg(feature = "pdf")]
            SignMode::Pdf(..) => SignProfile::Pdf,
            #[cfg(feature = "pdf")]
            SignMode::Pades(_, _, level, _, _) => SignProfile::Pades(level),
        }
    }
}
