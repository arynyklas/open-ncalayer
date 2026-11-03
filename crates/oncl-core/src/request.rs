//! Only profiles backed by complete operation implementations are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyProfile {
    Cms,
    #[cfg(feature = "pdf")]
    Pdf,
    #[cfg(feature = "pdf")]
    Pades(oncl_pki::evidence::AdesLevel),
    Cades(oncl_pki::evidence::AdesLevel),
    #[cfg(feature = "xml")]
    Xml,
    #[cfg(feature = "xml")]
    XmlKalkan,
    #[cfg(feature = "xml")]
    Xades(oncl_pki::evidence::AdesLevel),
    #[cfg(feature = "xml")]
    Wsse,
}

#[derive(Clone, Debug)]
pub struct VerifyRequest {
    profile: VerifyProfile,
    limits: Option<oncl_pki::evidence::EvidenceLimits>,
    #[cfg(feature = "xml")]
    pub(crate) wsse: Option<oncl_xml::wsse::WsseVerifyProfile>,
}
impl VerifyRequest {
    #[cfg(feature = "xml")]
    pub fn wsse(profile: oncl_xml::wsse::WsseVerifyProfile) -> Self {
        Self {
            profile: VerifyProfile::Wsse,
            limits: None,
            wsse: Some(profile),
        }
    }
    #[cfg(feature = "xml")]
    pub const fn xades(required: oncl_pki::evidence::AdesLevel) -> Self {
        Self {
            profile: VerifyProfile::Xades(required),
            limits: None,
            #[cfg(feature = "xml")]
            wsse: None,
        }
    }
    #[cfg(feature = "xml")]
    pub const fn xml() -> Self {
        Self {
            profile: VerifyProfile::Xml,
            limits: None,
            wsse: None,
        }
    }
    #[cfg(feature = "xml")]
    pub const fn xml_kalkan() -> Self {
        Self {
            profile: VerifyProfile::XmlKalkan,
            limits: None,
            wsse: None,
        }
    }
    #[cfg(feature = "pdf")]
    pub const fn pdf() -> Self {
        Self {
            profile: VerifyProfile::Pdf,
            limits: None,
            #[cfg(feature = "xml")]
            wsse: None,
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
            #[cfg(feature = "xml")]
            wsse: None,
        }
    }
    pub const fn cms() -> Self {
        Self {
            profile: VerifyProfile::Cms,
            limits: None,
            #[cfg(feature = "xml")]
            wsse: None,
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
            #[cfg(feature = "xml")]
            wsse: None,
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
    #[cfg(feature = "xml")]
    Xml,
    #[cfg(feature = "xml")]
    Xades(oncl_pki::evidence::AdesLevel),
    #[cfg(feature = "xml")]
    Wsse,
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
    #[cfg(feature = "xml")]
    Xml(
        crate::keys::KeyRequest<'a>,
        oncl_xml::XmlSignProfile<'a>,
        Option<oncl_pki::evidence::AdesLevel>,
    ),
    #[cfg(feature = "xml")]
    XmlLegacy(crate::keys::KeyRequest<'a>, oncl_xml::XmlSignSpec<'a>),
    #[cfg(feature = "xml")]
    XadesLegacy(crate::keys::KeyRequest<'a>, oncl_xml::xades::XadesSpec<'a>),
    #[cfg(feature = "xml")]
    Wsse(
        crate::keys::KeyRequest<'a>,
        oncl_xml::wsse::SourceWsseSignProfile,
    ),
}
impl<'a> SignRequest<'a> {
    #[cfg(feature = "xml")]
    pub fn wsse(
        key: crate::keys::KeyRequest<'a>,
        profile: oncl_xml::wsse::SourceWsseSignProfile,
    ) -> Self {
        Self {
            mode: SignMode::Wsse(key, profile),
        }
    }
    /// Bounded compatibility signing with the original selector, placement and
    /// wire-layout contract, through the same authorized key and canonical writer.
    #[cfg(feature = "xml")]
    pub fn xml_legacy(key: crate::keys::KeyRequest<'a>, spec: oncl_xml::XmlSignSpec<'a>) -> Self {
        Self {
            mode: SignMode::XmlLegacy(key, spec),
        }
    }
    #[cfg(feature = "xml")]
    pub fn xades_legacy(
        key: crate::keys::KeyRequest<'a>,
        spec: oncl_xml::xades::XadesSpec<'a>,
    ) -> Self {
        Self {
            mode: SignMode::XadesLegacy(key, spec),
        }
    }
    #[cfg(feature = "xml")]
    pub fn xml(key: crate::keys::KeyRequest<'a>, profile: oncl_xml::XmlSignProfile<'a>) -> Self {
        Self {
            mode: SignMode::Xml(key, profile, None),
        }
    }
    #[cfg(feature = "xml")]
    pub fn xades(
        key: crate::keys::KeyRequest<'a>,
        profile: oncl_xml::XmlSignProfile<'a>,
        level: oncl_pki::evidence::AdesLevel,
    ) -> Self {
        Self {
            mode: SignMode::Xml(key, profile, Some(level)),
        }
    }
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
            #[cfg(feature = "xml")]
            SignMode::Xml(_, _, None) | SignMode::XmlLegacy(..) => SignProfile::Xml,
            #[cfg(feature = "xml")]
            SignMode::Xml(_, _, Some(level)) => SignProfile::Xades(level),
            #[cfg(feature = "xml")]
            SignMode::Wsse(..) => SignProfile::Wsse,
            #[cfg(feature = "xml")]
            SignMode::XadesLegacy(_, ref spec) => SignProfile::Xades(match spec.level {
                oncl_xml::xades::XadesLevel::B => oncl_pki::evidence::AdesLevel::B,
                oncl_xml::xades::XadesLevel::T => oncl_pki::evidence::AdesLevel::T,
                oncl_xml::xades::XadesLevel::Lt => oncl_pki::evidence::AdesLevel::Lt,
            }),
        }
    }
}
