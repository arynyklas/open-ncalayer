//! Service-owned aliases and secret mounts. No desktop state or request paths.
use crate::{
    audit::AuditLabel,
    config::{KeyConfig, invalid},
};
use oncl_core::{
    Action, OperationContext, OperationError,
    keys::{KeyId, KeyLease, KeyProvider, KeyRequest, KeySelector, KeySources},
};
use oncl_token::{
    TokenKind, Tokens,
    execution::{TokenDeviceId, TokenGateRegistry},
};
use std::{collections::HashMap, io, path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

pub struct KeyBinding {
    id: KeyId,
    selector: KeySelector,
    secret: Zeroizing<String>,
    label: AuditLabel,
}
impl KeyBinding {
    fn new(
        name: &str,
        selector: KeySelector,
        secret: Zeroizing<String>,
    ) -> Result<Self, OperationError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(OperationError::InvalidKeySource);
        }
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"oncl-audit-key-v1\0");
        hash.update(name.as_bytes());
        let digest = hash.finish();
        Ok(Self {
            id: KeyId::new(name)?,
            selector,
            secret,
            label: AuditLabel::new(digest.as_ref()[..16].try_into().expect("digest length")),
        })
    }
    pub fn file(
        name: &str,
        path: PathBuf,
        alias: Option<String>,
        secret: String,
    ) -> Result<Self, OperationError> {
        let secret = Zeroizing::new(secret);
        Self::new(name, KeySelector::file(path, alias)?, secret)
    }
    pub fn token(
        name: &str,
        reader: String,
        kind: TokenKind,
        alias: String,
        secret: String,
    ) -> Result<Self, OperationError> {
        let secret = Zeroizing::new(secret);
        Self::new(
            name,
            KeySelector::token(
                TokenDeviceId::new(reader).map_err(|_| OperationError::InvalidKeySource)?,
                kind,
                alias,
            ),
            secret,
        )
    }
    pub fn from_config(config: &KeyConfig) -> io::Result<Self> {
        let binding = match config {
            KeyConfig::File {
                name,
                path,
                alias,
                secret,
            } => Self::file(
                name,
                path.clone(),
                alias.clone(),
                std::mem::take(&mut *secret.text()?),
            ),
            KeyConfig::Token {
                name,
                reader,
                kind,
                alias,
                secret,
            } => Self::token(
                name,
                reader.clone(),
                TokenKind::from_storage_name(kind).ok_or_else(invalid)?,
                alias.clone(),
                std::mem::take(&mut *secret.text()?),
            ),
        };
        binding.map_err(|_| invalid())
    }
}
type TokenServices = (Arc<Tokens>, Arc<TokenGateRegistry>);
pub struct OperatorKeys {
    sources: KeySources,
    bindings: HashMap<KeyId, (Zeroizing<String>, AuditLabel)>,
    inline: bool,
}
impl OperatorKeys {
    pub fn new(
        bindings: Vec<KeyBinding>,
        tokens: Option<TokenServices>,
        inline: bool,
    ) -> Result<Self, OperationError> {
        if bindings.len() > 64 {
            return Err(OperationError::InvalidKeySource);
        }
        let mut sources = KeySources::new();
        if let Some((tokens, gates)) = tokens {
            sources = sources.with_tokens(tokens, gates);
        }
        let mut names = HashMap::new();
        for binding in bindings {
            sources = sources.with_named(binding.id.clone(), binding.selector)?;
            if names
                .insert(binding.id, (binding.secret, binding.label))
                .is_some()
            {
                return Err(OperationError::InvalidKeySource);
            }
        }
        Ok(Self {
            sources,
            bindings: names,
            inline,
        })
    }
    pub fn labels(&self) -> impl Iterator<Item = (KeyId, AuditLabel)> + '_ {
        self.bindings
            .iter()
            .map(|(id, (_, label))| (id.clone(), *label))
    }
}
impl KeyProvider for OperatorKeys {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        let id = request.selector().key_id();
        if !ctx.grant().allows_key(&id)
            || !(ctx.grant().allows(Action::Sign) || ctx.grant().allows(Action::SignDigest))
        {
            return Err(OperationError::PermissionDenied);
        }
        if let Some((secret, _)) = self.bindings.get(&id) {
            return self
                .sources
                .open(&KeyRequest::new(request.selector(), Some(secret)), ctx);
        }
        // The host must additionally have granted this exact source identity.
        // S02 exposes no inline transport; no request can mint that authority.
        if self.inline && request.selector().is_inline() && request.secret().is_some() {
            return self.sources.open(request, ctx);
        }
        Err(OperationError::PermissionDenied)
    }
}

/// Audit label for an exact immutable inline source identity. Derived from the
/// host-computed InlineID, never from a client-asserted name or fingerprint.
pub fn inline_label(id: &KeyId) -> AuditLabel {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"oncl-audit-inline-v1\0");
    hash.update(format!("{id:?}").as_bytes());
    let digest = hash.finish();
    AuditLabel::new(digest.as_ref()[..16].try_into().expect("digest length"))
}
