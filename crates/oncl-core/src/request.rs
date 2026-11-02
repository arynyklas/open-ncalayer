//! Only profiles backed by complete operation implementations are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyProfile {
    Cms,
    #[cfg(feature = "pdf")]
    Pdf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyRequest {
    profile: VerifyProfile,
}
impl VerifyRequest {
    #[cfg(feature = "pdf")]
    pub const fn pdf() -> Self {
        Self {
            profile: VerifyProfile::Pdf,
        }
    }
    pub const fn cms() -> Self {
        Self {
            profile: VerifyProfile::Cms,
        }
    }
    pub const fn profile(&self) -> VerifyProfile {
        self.profile
    }
}

/// The complete implemented signature family; no filename inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignProfile {
    Cms,
    Raw,
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
}
impl<'a> SignRequest<'a> {
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
    pub fn profile(&self) -> SignProfile {
        match self.mode {
            SignMode::RawMessage(_) | SignMode::RawDigest(..) => SignProfile::Raw,
            SignMode::CmsCreate(..) | SignMode::CmsAdd(..) => SignProfile::Cms,
        }
    }
}
