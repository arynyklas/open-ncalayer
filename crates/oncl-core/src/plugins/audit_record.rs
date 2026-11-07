//! What the audit of a plugin key use names (`docs/design/manual-plugins.md` §5): trusted
//! facts only, never the nonce itself, document bytes, parameters or secrets.
use super::{CallerContext, PackageHash, PluginUse};
use sha2::{Digest, Sha256};

/// Who the caller of the use is, without the caller's name or origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginCallerKind {
    Browser,
    LocalOperator,
    ServiceClient,
}
impl PluginCallerKind {
    /// Stable text for logs and journals.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::LocalOperator => "local-operator",
            Self::ServiceClient => "service-client",
        }
    }
}

/// The facts of one plugin key use that the durable audit journal and the trace record.
/// Built by Core from the ticket the guard decided on; the plugin supplies none of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginAuditRecord {
    pub plugin_id: String,
    /// The tagged package hash: `1` file, `2` loose ([`PackageHash::canonical`]).
    pub package_kind: u8,
    pub package_sha256: [u8; 32],
    pub version: String,
    pub operation: String,
    /// [`PluginUse::digest`]: names every field of the ticket without carrying bytes.
    pub ticket_digest: [u8; 32],
    /// SHA-256 of the approval's nonce (manual window); `None` when no user approved it (a
    /// server or CLI grant). The nonce itself is never recorded.
    pub approval_nonce_sha256: Option<[u8; 32]>,
    pub content_sha256: [u8; 32],
    pub content_len: u64,
    /// The content is a caller-supplied digest (CMS `Digest`), not document bytes.
    pub prehashed: bool,
    pub options_sha256: [u8; 32],
    pub caller: PluginCallerKind,
    /// The operation is declared in the manifest (always `true` for a ticketed use; the
    /// undeclared grants of plugins without declarations carry no ticket and are `false`
    /// in the journals that record them).
    pub declared: bool,
    /// The operator grant that covered the use (server and CLI), when there is one.
    pub grant_id: Option<String>,
}
impl PluginAuditRecord {
    /// The facts of `ticket`; `nonce` is the approval's nonce when a user approved it, hashed
    /// here so no caller can pass the nonce on.
    pub fn from_ticket(
        ticket: &PluginUse,
        nonce: Option<&[u8; 16]>,
        grant_id: Option<String>,
    ) -> Self {
        let identity = ticket.identity();
        let canonical = identity.package.canonical();
        debug_assert!(matches!(
            identity.package,
            PackageHash::File(_) | PackageHash::Loose(_)
        ));
        let mut package_sha256 = [0; 32];
        package_sha256.copy_from_slice(&canonical[1..]);
        Self {
            plugin_id: identity.id.clone(),
            package_kind: canonical[0],
            package_sha256,
            version: identity.version.clone(),
            operation: ticket.operation().to_owned(),
            ticket_digest: ticket.digest(),
            approval_nonce_sha256: nonce.map(|n| {
                let mut h = Sha256::new();
                h.update(b"ONCLNONCE1\0");
                h.update(n);
                h.finalize().into()
            }),
            content_sha256: ticket.content().sha256,
            content_len: ticket.content().len,
            prehashed: ticket.content().prehashed,
            options_sha256: *ticket.options_sha256(),
            caller: match ticket.caller() {
                CallerContext::Browser { .. } => PluginCallerKind::Browser,
                CallerContext::LocalOperator(_) => PluginCallerKind::LocalOperator,
                CallerContext::ServiceClient(_) => PluginCallerKind::ServiceClient,
            },
            declared: true,
            grant_id,
        }
    }
}
