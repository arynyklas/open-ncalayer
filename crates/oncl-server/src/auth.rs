//! Host-only authority. Wire data never deserializes a grant or principal.
use crate::audit::AuditLabel;
use oncl_core::keys::KeyId;
use oncl_core::{Action, ExecutionGrant};
use ring::hmac;
use std::{
    collections::HashMap,
    fmt, io,
    sync::{Arc, RwLock},
};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"OpenNCALayer API token verifier v1\0";
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "access denied")
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid authority configuration",
    )
}
pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}
pub(crate) fn decode<const N: usize>(text: &str) -> io::Result<[u8; N]> {
    if text.len() != N * 2 {
        return Err(invalid());
    }
    let mut out = [0; N];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        fn digit(b: u8) -> io::Result<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(invalid()),
            }
        }
        out[i] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(out)
}
/// Fixed verifier, safe to persist; its Debug never discloses authentication data.
#[derive(Clone, Copy)]
pub struct TokenVerifier([u8; 32]);
impl TokenVerifier {
    pub fn parse(text: &str) -> io::Result<Self> {
        Ok(Self(decode(text)?))
    }
    pub fn encoded(&self) -> String {
        encode(&self.0)
    }
    fn accepts(&self, secret: &[u8; 32], key: &hmac::Key) -> bool {
        hmac::verify(key, secret, &self.0).is_ok()
    }
}
impl fmt::Debug for TokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenVerifier([REDACTED])")
    }
}
/// 256 bits from the OS CSPRNG, held zeroizing and never accepted as argv.
pub struct TokenSecret(Zeroizing<[u8; 32]>);
impl TokenSecret {
    pub fn generate() -> io::Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|_| io::Error::other("token randomness unavailable"))?;
        Ok(Self(bytes))
    }
    pub fn parse(text: &str) -> io::Result<Self> {
        Ok(Self(Zeroizing::new(decode(text)?)))
    }
    pub fn verifier(&self) -> TokenVerifier {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, DOMAIN), self.0.as_ref());
        TokenVerifier(tag.as_ref().try_into().expect("SHA256 length"))
    }
    pub fn bearer(&self) -> Zeroizing<String> {
        Zeroizing::new(encode(self.0.as_ref()))
    }
}
fn canonical(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub struct TokenRecord {
    id: String,
    verifier: TokenVerifier,
    actions: Vec<Action>,
    keys: Vec<String>,
    label: AuditLabel,
    inline_pkcs12: bool,
    metadata_aliases: Vec<String>,
}
impl TokenRecord {
    pub fn new(
        id: &str,
        verifier: TokenVerifier,
        actions: Vec<Action>,
        keys: Vec<String>,
    ) -> io::Result<Self> {
        if !canonical(id)
            || actions.is_empty()
            || keys.len() > 64
            || keys.iter().any(|k| !canonical(k))
        {
            return Err(invalid());
        }
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"oncl-audit-principal-v1\0");
        hash.update(id.as_bytes());
        let hash = hash.finish();
        Ok(Self {
            id: id.into(),
            verifier,
            actions,
            keys,
            label: AuditLabel::new(hash.as_ref()[..16].try_into().expect("digest length")),
            inline_pkcs12: false,
            metadata_aliases: Vec::new(),
        })
    }
    pub fn with_metadata_aliases(mut self, aliases: Vec<String>) -> Self {
        self.metadata_aliases = aliases;
        self
    }
    pub fn with_inline_pkcs12(mut self, allowed: bool) -> Self {
        self.inline_pkcs12 = allowed;
        self
    }
}
struct PolicyState {
    generation: u64,
    records: HashMap<String, TokenRecord>,
}
pub struct AccessPolicy {
    state: RwLock<PolicyState>,
    verifier_key: hmac::Key,
    identity: Arc<()>,
}
/// Opaque, operation-independent authenticated identity; stale identities cannot
/// mint grants after a host policy update. Existing grants are immutable.
pub struct Principal {
    id: String,
    generation: u64,
    label: AuditLabel,
    owner: Arc<()>,
}
impl Principal {
    /// The authenticated token id (host-assigned, not a request field).
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn audit_label(&self) -> AuditLabel {
        self.label
    }
}
fn records_map(records: Vec<TokenRecord>) -> io::Result<HashMap<String, TokenRecord>> {
    if records.len() > 256 {
        return Err(invalid());
    }
    let mut map = HashMap::new();
    let mut verifiers = std::collections::HashSet::new();
    for record in records {
        if !verifiers.insert(record.verifier.0) || map.insert(record.id.clone(), record).is_some() {
            return Err(invalid());
        }
    }
    Ok(map)
}
impl AccessPolicy {
    pub fn new(records: Vec<TokenRecord>) -> io::Result<Self> {
        let map = records_map(records)?;
        Ok(Self {
            state: RwLock::new(PolicyState {
                generation: 0,
                records: map,
            }),
            verifier_key: hmac::Key::new(hmac::HMAC_SHA256, DOMAIN),
            identity: Arc::new(()),
        })
    }
    pub fn authenticate(&self, bearer: &[u8]) -> io::Result<Principal> {
        let text = std::str::from_utf8(bearer).map_err(|_| denied())?;
        let raw = Zeroizing::new(decode::<32>(text).map_err(|_| denied())?);
        let state = self.state.read().map_err(|_| denied())?;
        // Run a constant-time fixed-size MAC comparison for every configured token;
        // do not early-return on a matching record or compare encoded verifier text.
        let mut matched = None;
        for record in state.records.values() {
            if record.verifier.accepts(&raw, &self.verifier_key) {
                matched = Some(record);
            }
        }
        let record = matched.ok_or_else(denied)?;
        Ok(Principal {
            id: record.id.clone(),
            generation: state.generation,
            label: record.label,
            owner: self.identity.clone(),
        })
    }
    pub fn authorize(
        &self,
        principal: &Principal,
        action: Action,
        key: Option<&str>,
        nested: Option<(Action, Option<&str>)>,
    ) -> io::Result<ExecutionGrant> {
        if nested.is_some_and(|n| n != (action, key))
            || key.is_some_and(|k| !canonical(k))
            || (action == Action::Hash && key.is_some())
        {
            return Err(denied());
        }
        let state = self.state.read().map_err(|_| denied())?;
        if !Arc::ptr_eq(&principal.owner, &self.identity)
            || principal.generation != state.generation
        {
            return Err(denied());
        }
        let record = state.records.get(&principal.id).ok_or_else(denied)?;
        if !record.actions.contains(&action)
            || key.is_some_and(|k| !record.keys.iter().any(|allowed| allowed == k))
        {
            return Err(denied());
        }
        if matches!(action, Action::Sign | Action::SignDigest) && key.is_none() {
            return Err(denied());
        }
        let keys = key.map(KeyId::new).transpose().map_err(|_| denied())?;
        Ok(ExecutionGrant::new([action]).with_keys(keys))
    }
    /// Host-only source-specific authority for already bounded SDK inputs. S02
    /// deliberately has no inline HTTP body/secret endpoint (that belongs to S03).
    pub fn authorize_inline(
        &self,
        principal: &Principal,
        action: Action,
        selector: &oncl_core::keys::KeySelector,
        enabled: bool,
    ) -> io::Result<ExecutionGrant> {
        if !enabled || !selector.is_inline() || !matches!(action, Action::Sign | Action::SignDigest)
        {
            return Err(denied());
        }
        let state = self.state.read().map_err(|_| denied())?;
        if !Arc::ptr_eq(&principal.owner, &self.identity)
            || principal.generation != state.generation
        {
            return Err(denied());
        }
        let record = state.records.get(&principal.id).ok_or_else(denied)?;
        if !record.inline_pkcs12 || !record.actions.contains(&action) {
            return Err(denied());
        }
        Ok(ExecutionGrant::new([action]).with_keys([selector.key_id()]))
    }
    /// The principal is still the live, current-generation token of this policy.
    /// Needed by items that carry no action right (plugins authorized only by an
    /// operator grant), so a revoked token cannot proceed through a key-less plugin.
    pub fn ensure_live(&self, principal: &Principal) -> io::Result<()> {
        let state = self.state.read().map_err(|_| denied())?;
        if !Arc::ptr_eq(&principal.owner, &self.identity)
            || principal.generation != state.generation
            || !state.records.contains_key(&principal.id)
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Source-independent inline right check, made BEFORE any secret byte is
    /// read. The exact immutable InlineID is still authorized after intake.
    pub fn precheck_inline(
        &self,
        principal: &Principal,
        action: Action,
        enabled: bool,
    ) -> io::Result<()> {
        if !enabled || !matches!(action, Action::Sign | Action::SignDigest) {
            return Err(denied());
        }
        let state = self.state.read().map_err(|_| denied())?;
        if !Arc::ptr_eq(&principal.owner, &self.identity)
            || principal.generation != state.generation
        {
            return Err(denied());
        }
        let record = state.records.get(&principal.id).ok_or_else(denied)?;
        if !record.inline_pkcs12 || !record.actions.contains(&action) {
            return Err(denied());
        }
        Ok(())
    }
    /// Exact container aliases the host granted to this principal's inspection.
    pub fn metadata_aliases(&self, principal: &Principal) -> io::Result<Vec<String>> {
        let state = self.state.read().map_err(|_| denied())?;
        if !Arc::ptr_eq(&principal.owner, &self.identity)
            || principal.generation != state.generation
        {
            return Err(denied());
        }
        let record = state.records.get(&principal.id).ok_or_else(denied)?;
        Ok(record.metadata_aliases.clone())
    }
    /// Atomic trusted-host ACL replacement; no request DTO can call this method.
    /// Validation completes before publication; every old Principal becomes stale.
    pub fn replace(&self, records: Vec<TokenRecord>) -> io::Result<()> {
        let records = records_map(records)?;
        let mut state = self.state.write().map_err(|_| denied())?;
        let generation = state.generation.checked_add(1).ok_or_else(denied)?;
        state.records = records;
        state.generation = generation;
        Ok(())
    }
    pub fn revoke(&self, id: &str) -> io::Result<()> {
        let mut state = self.state.write().map_err(|_| denied())?;
        let generation = state.generation.checked_add(1).ok_or_else(denied)?;
        state.records.remove(id);
        state.generation = generation;
        Ok(())
    }
}
