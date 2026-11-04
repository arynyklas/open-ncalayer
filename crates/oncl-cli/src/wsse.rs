//! Host-selected WS-Security profile fields; each maps to an accepted SDK field.
use clap::{Args, ValueEnum};
use oncl_xml::wsse::{
    SoapVersion, SourceWsseSignProfile, TokenReference, WsseTimestamp, WsseVerifyProfile,
};

#[derive(Clone, Copy, ValueEnum)]
pub enum Soap {
    Soap11,
    Soap12,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Token {
    NcanodeX509KeyIdentifier,
    BinarySecurityToken,
}
#[derive(Args, Default)]
pub struct WsseOptions {
    #[arg(long, value_enum)]
    pub soap_version: Option<Soap>,
    #[arg(long)]
    pub wsse_role: Option<String>,
    /// Full unique WSU identity of a direct application header that must be signed.
    #[arg(long)]
    pub wsse_required_header: Vec<String>,
    #[arg(long)]
    pub wsse_timestamp_required: bool,
    #[arg(long)]
    pub wsse_timestamp_max_lifetime: Option<u64>,
    #[arg(long, value_enum)]
    pub wsse_token_reference: Option<Token>,
    #[arg(long)]
    pub wsse_token_id: Option<String>,
    #[arg(long)]
    pub wsse_body_id: Option<String>,
    #[arg(long)]
    pub wsse_timestamp_id: Option<String>,
    #[arg(long)]
    pub wsse_timestamp_created: Option<i64>,
    #[arg(long)]
    pub wsse_timestamp_expires: Option<i64>,
}
impl WsseOptions {
    pub fn any(&self) -> bool {
        self.soap_version.is_some()
            || self.wsse_role.is_some()
            || !self.wsse_required_header.is_empty()
            || self.wsse_timestamp_required
            || self.wsse_timestamp_max_lifetime.is_some()
            || self.wsse_token_reference.is_some()
            || self.wsse_token_id.is_some()
            || self.wsse_body_id.is_some()
            || self.wsse_timestamp_id.is_some()
            || self.wsse_timestamp_created.is_some()
            || self.wsse_timestamp_expires.is_some()
    }
    /// Verification-only options cannot silently configure signing.
    fn sign_only(&self) -> bool {
        self.wsse_token_reference.is_some()
            || self.wsse_token_id.is_some()
            || self.wsse_body_id.is_some()
            || self.wsse_timestamp_id.is_some()
            || self.wsse_timestamp_created.is_some()
            || self.wsse_timestamp_expires.is_some()
    }
    pub fn preflight(&self, signing: bool) -> Result<(), &'static str> {
        if !signing && self.sign_only() {
            return Err("InvalidCombination");
        }
        if self.wsse_timestamp_created.is_some() != self.wsse_timestamp_expires.is_some()
            || (self.wsse_timestamp_id.is_some() && self.wsse_timestamp_created.is_none())
        {
            return Err("InvalidCombination");
        }
        if let (Some(created), Some(expires)) =
            (self.wsse_timestamp_created, self.wsse_timestamp_expires)
        {
            let valid = time::OffsetDateTime::from_unix_timestamp(created).is_ok()
                && time::OffsetDateTime::from_unix_timestamp(expires).is_ok()
                && expires > created;
            if !valid {
                return Err("InvalidCombination");
            }
        }
        for text in [
            &self.wsse_token_id,
            &self.wsse_body_id,
            &self.wsse_timestamp_id,
        ]
        .into_iter()
        .flatten()
        .chain(self.wsse_role.iter())
        .chain(self.wsse_required_header.iter())
        {
            if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
                return Err("InvalidCombination");
            }
        }
        if self.wsse_required_header.len() > 64 {
            return Err("ConfigurationLimit");
        }
        Ok(())
    }
    pub fn verify_profile(&self) -> WsseVerifyProfile {
        let mut profile = WsseVerifyProfile::default();
        profile.soap = match self.soap_version {
            Some(Soap::Soap12) => SoapVersion::Soap12,
            _ => SoapVersion::Soap11,
        };
        profile.role = self.wsse_role.clone();
        profile.required_headers = self.wsse_required_header.clone();
        profile.timestamp.required = self.wsse_timestamp_required;
        if let Some(seconds) = self.wsse_timestamp_max_lifetime {
            profile.timestamp.max_lifetime_seconds = seconds;
        }
        profile
    }
    pub fn sign_profile(&self, add: bool) -> SourceWsseSignProfile {
        let mut profile = SourceWsseSignProfile {
            verification: self.verify_profile(),
            mode: if add {
                oncl_xml::XmlSignMode::Add
            } else {
                oncl_xml::XmlSignMode::Create
            },
            ..Default::default()
        };
        profile.token_reference = match self.wsse_token_reference {
            Some(Token::BinarySecurityToken) => TokenReference::BinarySecurityToken,
            _ => TokenReference::NcanodeX509KeyIdentifier,
        };
        if let Some(id) = &self.wsse_token_id {
            profile.token_id = id.clone();
        }
        if let Some(id) = &self.wsse_body_id {
            profile.body_id = id.clone();
        }
        if let (Some(created), Some(expires)) =
            (self.wsse_timestamp_created, self.wsse_timestamp_expires)
        {
            profile.timestamp = Some(WsseTimestamp {
                id: self
                    .wsse_timestamp_id
                    .clone()
                    .unwrap_or_else(|| "oncl-timestamp".into()),
                created: time::OffsetDateTime::from_unix_timestamp(created).unwrap(),
                expires: time::OffsetDateTime::from_unix_timestamp(expires).unwrap(),
            });
        }
        profile
    }
}
