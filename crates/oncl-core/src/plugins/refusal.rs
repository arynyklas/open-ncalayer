//! Stable subcodes of plugin refusals (`docs/design/manual-plugins.md` §4.8).
//!
//! The public [`ErrorCode`] contract stays as it is: a refusal is still `PermissionDenied`,
//! `InvalidInput`, `InputLimit`... A [`PluginRefusalCode`] is a field *next to* the code, for
//! the host, the audit journal and the HTTP/CLI contracts. The plugin never sees it: a
//! plugin whose key use is refused gets `PermissionDenied` and nothing else.
//!
//! Every subcode has a stable kebab-case id ([`PluginRefusalCode::id`]). An id is never
//! reused or renumbered; a retired reason keeps its id forever. `ALL` and the tests that pin
//! the whole list make every change deliberate.
use super::{
    ApprovalIssueError, ApprovalRejected, PluginPrepareError, PluginRequestError, TicketRefusal,
};
use crate::ErrorCode;

/// Why a plugin operation was refused, in a form that does not depend on message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PluginRefusalCode {
    // Ticket (the guard at the key use, or the fast check before the module runs).
    /// The key use carries no ticket (not a plugin key use of a declared operation).
    TicketMissing,
    /// No approval was granted to the guard (or it was revoked).
    ApprovalMissing,
    /// The ticket allows other than one use.
    TicketUses,
    /// The approval's deadline passed.
    ApprovalExpired,
    /// Another invocation than the approved one.
    OperationIdMismatch,
    /// Another plugin, package or version than the approved one.
    PackageChanged,
    /// Another declared operation than the approved one.
    OperationMismatch,
    /// Another caller than the approved one.
    CallerMismatch,
    /// Another key or handle than the approved one.
    KeyMismatch,
    /// The key action does not fit the content (document vs prehashed).
    ActionMismatch,
    /// Another signature kind than the approved one.
    KindMismatch,
    /// Other content bytes than the approved ones.
    ContentMismatch,
    /// Other signature options than the approved ones.
    OptionsMismatch,
    /// The approved use is spent.
    KeyUseSpent,
    /// The operation is not declared by the plugin (or it declares none and a ticket was
    /// asked for).
    NotDeclared,
    /// The certificate of the key that signs is not the approved one.
    CertificateChanged,
    /// The engine has no consent guard for plugin key uses.
    NoConsentGuard,
    /// Another approved call of this engine is running.
    Busy,
    /// The approval's nonce was granted before.
    ApprovalReplayed,
    /// No operator grant covers the ticket (a server or CLI key use without a `plugin_bytes`
    /// grant for the plugin, operation and key).
    NotGranted,
    // Request (before any key is opened).
    UnknownPlugin,
    /// Declared, but not for the manual window.
    NotManual,
    /// `derived` content is not run in this release.
    DerivedUnsupported,
    /// `network = [urls]` is not runnable in the manual window in this release.
    NetworkUnsupported,
    /// Endpoints were given to an operation whose declared network is `none`.
    NetworkNotDeclared,
    UnknownParam,
    DuplicateParam,
    MissingParam,
    ParamWrongKind,
    ParamTooLarge,
    ParamInvalidValue,
    InvalidEndpoint,
    RequestTooLarge,
    InvalidTemplate,
    // Prepare.
    InvalidContext,
    CallerNotManual,
    NoKeyUse,
    KeyMetadataMissing,
    UnsupportedKey,
    /// A profile parameter has no valid text.
    OptionsInvalid,
    KeyUnavailable,
    /// The binding's certificate is not the one the key store holds.
    CertificateMismatch,
    // Approval issue.
    ConfirmationMismatch,
    ApprovalTtlInvalid,
    ApprovalRandomUnavailable,
    // Appended later.
    /// A fact of the use (a version or grant id) is too long to be audited, so the use
    /// does not run.
    AuditFactTooLong,
    /// The CLI cannot compute the expected content of a digest-form bound key use before the
    /// key is opened, so it refuses to grant it.
    ContentBindingUnavailable,
    /// The engine's memory and metadata budgets cannot hold the call over this document
    /// (`manual_call_budget`), so it is refused before the user is asked and before a key is
    /// opened.
    ResourceBudget,
    /// The operation signs XML and the engine has no temporary store to spool it through.
    NoTemporaryStore,
}

impl PluginRefusalCode {
    /// Every subcode, in a fixed order. New subcodes are appended, never inserted.
    pub const ALL: [Self; 49] = [
        Self::TicketMissing,
        Self::ApprovalMissing,
        Self::TicketUses,
        Self::ApprovalExpired,
        Self::OperationIdMismatch,
        Self::PackageChanged,
        Self::OperationMismatch,
        Self::CallerMismatch,
        Self::KeyMismatch,
        Self::ActionMismatch,
        Self::KindMismatch,
        Self::ContentMismatch,
        Self::OptionsMismatch,
        Self::KeyUseSpent,
        Self::NotDeclared,
        Self::CertificateChanged,
        Self::NoConsentGuard,
        Self::Busy,
        Self::ApprovalReplayed,
        Self::NotGranted,
        Self::UnknownPlugin,
        Self::NotManual,
        Self::DerivedUnsupported,
        Self::NetworkUnsupported,
        Self::NetworkNotDeclared,
        Self::UnknownParam,
        Self::DuplicateParam,
        Self::MissingParam,
        Self::ParamWrongKind,
        Self::ParamTooLarge,
        Self::ParamInvalidValue,
        Self::InvalidEndpoint,
        Self::RequestTooLarge,
        Self::InvalidTemplate,
        Self::InvalidContext,
        Self::CallerNotManual,
        Self::NoKeyUse,
        Self::KeyMetadataMissing,
        Self::UnsupportedKey,
        Self::OptionsInvalid,
        Self::KeyUnavailable,
        Self::CertificateMismatch,
        Self::ConfirmationMismatch,
        Self::ApprovalTtlInvalid,
        Self::ApprovalRandomUnavailable,
        Self::AuditFactTooLong,
        Self::ContentBindingUnavailable,
        Self::ResourceBudget,
        Self::NoTemporaryStore,
    ];
}

impl PluginRefusalCode {
    /// The stable kebab-case id: never reused, never renumbered.
    pub const fn id(self) -> &'static str {
        match self {
            Self::TicketMissing => "ticket-missing",
            Self::ApprovalMissing => "approval-missing",
            Self::TicketUses => "ticket-uses",
            Self::ApprovalExpired => "approval-expired",
            Self::OperationIdMismatch => "operation-id-mismatch",
            Self::PackageChanged => "package-changed",
            Self::OperationMismatch => "operation-mismatch",
            Self::CallerMismatch => "caller-mismatch",
            Self::KeyMismatch => "key-mismatch",
            Self::ActionMismatch => "action-mismatch",
            Self::KindMismatch => "kind-mismatch",
            Self::ContentMismatch => "content-mismatch",
            Self::OptionsMismatch => "options-mismatch",
            Self::KeyUseSpent => "key-use-spent",
            Self::NotDeclared => "not-declared",
            Self::CertificateChanged => "certificate-changed",
            Self::NoConsentGuard => "no-consent-guard",
            Self::Busy => "busy",
            Self::ApprovalReplayed => "approval-replayed",
            Self::NotGranted => "not-granted",
            Self::UnknownPlugin => "unknown-plugin",
            Self::NotManual => "not-manual",
            Self::DerivedUnsupported => "derived-unsupported",
            Self::NetworkUnsupported => "network-unsupported",
            Self::NetworkNotDeclared => "network-not-declared",
            Self::UnknownParam => "unknown-param",
            Self::DuplicateParam => "duplicate-param",
            Self::MissingParam => "missing-param",
            Self::ParamWrongKind => "param-wrong-kind",
            Self::ParamTooLarge => "param-too-large",
            Self::ParamInvalidValue => "param-invalid-value",
            Self::InvalidEndpoint => "invalid-endpoint",
            Self::RequestTooLarge => "request-too-large",
            Self::InvalidTemplate => "invalid-template",
            Self::InvalidContext => "invalid-context",
            Self::CallerNotManual => "caller-not-manual",
            Self::NoKeyUse => "no-key-use",
            Self::KeyMetadataMissing => "key-metadata-missing",
            Self::UnsupportedKey => "unsupported-key",
            Self::OptionsInvalid => "options-invalid",
            Self::KeyUnavailable => "key-unavailable",
            Self::CertificateMismatch => "certificate-mismatch",
            Self::ConfirmationMismatch => "confirmation-mismatch",
            Self::ApprovalTtlInvalid => "approval-ttl-invalid",
            Self::ApprovalRandomUnavailable => "approval-random-unavailable",
            Self::AuditFactTooLong => "audit-fact-too-long",
            Self::ContentBindingUnavailable => "content-binding-unavailable",
            Self::ResourceBudget => "resource-budget",
            Self::NoTemporaryStore => "no-temporary-store",
        }
    }
    /// The subcode of an id, if it is one.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.id() == id)
    }
    /// The [`ErrorCode`] the refusal is reported with (docs/design/manual-plugins.md §4.8):
    /// the same one [`crate::OperationError::code`] gives for it.
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::UnknownParam
            | Self::DuplicateParam
            | Self::MissingParam
            | Self::ParamWrongKind
            | Self::ParamInvalidValue
            | Self::InvalidEndpoint
            | Self::InvalidTemplate
            | Self::InvalidContext
            | Self::OptionsInvalid
            | Self::ApprovalTtlInvalid => ErrorCode::InvalidInput,
            Self::ParamTooLarge | Self::RequestTooLarge => ErrorCode::InputLimit,
            Self::UnsupportedKey => ErrorCode::UnsupportedAlgorithm,
            Self::KeyUnavailable => ErrorCode::MissingKeyProvider,
            Self::ApprovalRandomUnavailable => ErrorCode::Io,
            Self::ResourceBudget => ErrorCode::MemoryLimit,
            Self::NoTemporaryStore => ErrorCode::MissingTemporaryStore,
            Self::TicketMissing
            | Self::ApprovalMissing
            | Self::TicketUses
            | Self::ApprovalExpired
            | Self::OperationIdMismatch
            | Self::PackageChanged
            | Self::OperationMismatch
            | Self::CallerMismatch
            | Self::KeyMismatch
            | Self::ActionMismatch
            | Self::KindMismatch
            | Self::ContentMismatch
            | Self::OptionsMismatch
            | Self::KeyUseSpent
            | Self::NotDeclared
            | Self::CertificateChanged
            | Self::NoConsentGuard
            | Self::Busy
            | Self::ApprovalReplayed
            | Self::NotGranted
            | Self::AuditFactTooLong
            | Self::ContentBindingUnavailable
            | Self::UnknownPlugin
            | Self::NotManual
            | Self::DerivedUnsupported
            | Self::NetworkUnsupported
            | Self::NetworkNotDeclared
            | Self::CallerNotManual
            | Self::NoKeyUse
            | Self::KeyMetadataMissing
            | Self::CertificateMismatch
            | Self::ConfirmationMismatch => ErrorCode::PermissionDenied,
        }
    }
}
impl std::fmt::Display for PluginRefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}
impl From<TicketRefusal> for PluginRefusalCode {
    fn from(reason: TicketRefusal) -> Self {
        match reason {
            TicketRefusal::NoTicket => Self::TicketMissing,
            TicketRefusal::NoApproval => Self::ApprovalMissing,
            TicketRefusal::Uses => Self::TicketUses,
            TicketRefusal::Expired => Self::ApprovalExpired,
            TicketRefusal::OperationId => Self::OperationIdMismatch,
            TicketRefusal::Identity => Self::PackageChanged,
            TicketRefusal::Operation => Self::OperationMismatch,
            TicketRefusal::Caller => Self::CallerMismatch,
            TicketRefusal::Key => Self::KeyMismatch,
            TicketRefusal::Action => Self::ActionMismatch,
            TicketRefusal::Kind => Self::KindMismatch,
            TicketRefusal::Content => Self::ContentMismatch,
            TicketRefusal::Options => Self::OptionsMismatch,
            TicketRefusal::AlreadyUsed => Self::KeyUseSpent,
            TicketRefusal::UndeclaredOperation => Self::NotDeclared,
            TicketRefusal::CertificateChanged => Self::CertificateChanged,
            TicketRefusal::NoGuard => Self::NoConsentGuard,
            TicketRefusal::Busy => Self::Busy,
            TicketRefusal::Replayed => Self::ApprovalReplayed,
            TicketRefusal::NotGranted => Self::NotGranted,
            TicketRefusal::AuditFactTooLong => Self::AuditFactTooLong,
        }
    }
}
impl From<&PluginRequestError> for PluginRefusalCode {
    fn from(error: &PluginRequestError) -> Self {
        match error {
            PluginRequestError::UnknownPlugin => Self::UnknownPlugin,
            PluginRequestError::UndeclaredOperation => Self::NotDeclared,
            PluginRequestError::NotManual => Self::NotManual,
            PluginRequestError::DerivedUnsupported => Self::DerivedUnsupported,
            PluginRequestError::NetworkUnsupported => Self::NetworkUnsupported,
            PluginRequestError::NetworkNotDeclared => Self::NetworkNotDeclared,
            PluginRequestError::UnknownParam(_) => Self::UnknownParam,
            PluginRequestError::DuplicateParam(_) => Self::DuplicateParam,
            PluginRequestError::MissingParam(_) => Self::MissingParam,
            PluginRequestError::WrongKind(_) => Self::ParamWrongKind,
            PluginRequestError::TooLarge(_) => Self::ParamTooLarge,
            PluginRequestError::InvalidValue(_) => Self::ParamInvalidValue,
            PluginRequestError::InvalidEndpoint => Self::InvalidEndpoint,
            PluginRequestError::RequestTooLarge => Self::RequestTooLarge,
            PluginRequestError::InvalidTemplate => Self::InvalidTemplate,
        }
    }
}
impl From<&PluginPrepareError> for PluginRefusalCode {
    fn from(error: &PluginPrepareError) -> Self {
        match error {
            PluginPrepareError::Request(e) => e.into(),
            PluginPrepareError::InvalidContext => Self::InvalidContext,
            PluginPrepareError::CallerNotManual => Self::CallerNotManual,
            PluginPrepareError::NoKeyUse => Self::NoKeyUse,
            PluginPrepareError::KeyMetadataMissing => Self::KeyMetadataMissing,
            PluginPrepareError::UnsupportedKey => Self::UnsupportedKey,
            PluginPrepareError::Options => Self::OptionsInvalid,
            PluginPrepareError::KeyUnavailable => Self::KeyUnavailable,
            PluginPrepareError::CertificateMismatch => Self::CertificateMismatch,
            PluginPrepareError::ResourceBudget => Self::ResourceBudget,
            PluginPrepareError::NoTemporaryStore => Self::NoTemporaryStore,
        }
    }
}
impl From<ApprovalIssueError> for PluginRefusalCode {
    fn from(error: ApprovalIssueError) -> Self {
        match error {
            ApprovalIssueError::ConfirmationMismatch => Self::ConfirmationMismatch,
            ApprovalIssueError::Ttl => Self::ApprovalTtlInvalid,
            ApprovalIssueError::Random => Self::ApprovalRandomUnavailable,
        }
    }
}
impl From<ApprovalRejected> for PluginRefusalCode {
    fn from(error: ApprovalRejected) -> Self {
        match error {
            ApprovalRejected::Replayed => Self::ApprovalReplayed,
            ApprovalRejected::Uses => Self::TicketUses,
        }
    }
}
impl TicketRefusal {
    /// The stable subcode of this reason.
    pub fn subcode(self) -> PluginRefusalCode {
        self.into()
    }
}
impl PluginRequestError {
    pub fn subcode(&self) -> PluginRefusalCode {
        self.into()
    }
}
impl PluginPrepareError {
    pub fn subcode(&self) -> PluginRefusalCode {
        self.into()
    }
}
impl ApprovalIssueError {
    pub fn subcode(self) -> PluginRefusalCode {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationError;

    /// The whole list of ids. Adding a subcode means appending here on purpose; an id is
    /// never edited, removed or reordered (clients and journals keep the strings).
    const PINNED: [&str; 49] = [
        "ticket-missing",
        "approval-missing",
        "ticket-uses",
        "approval-expired",
        "operation-id-mismatch",
        "package-changed",
        "operation-mismatch",
        "caller-mismatch",
        "key-mismatch",
        "action-mismatch",
        "kind-mismatch",
        "content-mismatch",
        "options-mismatch",
        "key-use-spent",
        "not-declared",
        "certificate-changed",
        "no-consent-guard",
        "busy",
        "approval-replayed",
        "not-granted",
        "unknown-plugin",
        "not-manual",
        "derived-unsupported",
        "network-unsupported",
        "network-not-declared",
        "unknown-param",
        "duplicate-param",
        "missing-param",
        "param-wrong-kind",
        "param-too-large",
        "param-invalid-value",
        "invalid-endpoint",
        "request-too-large",
        "invalid-template",
        "invalid-context",
        "caller-not-manual",
        "no-key-use",
        "key-metadata-missing",
        "unsupported-key",
        "options-invalid",
        "key-unavailable",
        "certificate-mismatch",
        "confirmation-mismatch",
        "approval-ttl-invalid",
        "approval-random-unavailable",
        "audit-fact-too-long",
        "content-binding-unavailable",
        "resource-budget",
        "no-temporary-store",
    ];

    #[test]
    fn ids_are_pinned_unique_kebab_and_round_trip() {
        let ids: Vec<_> = PluginRefusalCode::ALL.iter().map(|c| c.id()).collect();
        assert_eq!(ids, PINNED);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "ids are unique");
        for code in PluginRefusalCode::ALL {
            let id = code.id();
            assert!(
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                    && !id.starts_with('-')
                    && !id.ends_with('-'),
                "{id}"
            );
            assert_eq!(PluginRefusalCode::from_id(id), Some(code));
            assert_eq!(code.to_string(), id);
        }
        assert_eq!(PluginRefusalCode::from_id("nope"), None);
    }

    fn requests() -> Vec<PluginRequestError> {
        let p = || "p".to_owned();
        vec![
            PluginRequestError::UnknownPlugin,
            PluginRequestError::UndeclaredOperation,
            PluginRequestError::NotManual,
            PluginRequestError::DerivedUnsupported,
            PluginRequestError::NetworkUnsupported,
            PluginRequestError::NetworkNotDeclared,
            PluginRequestError::UnknownParam(p()),
            PluginRequestError::DuplicateParam(p()),
            PluginRequestError::MissingParam(p()),
            PluginRequestError::WrongKind(p()),
            PluginRequestError::TooLarge(p()),
            PluginRequestError::InvalidValue(p()),
            PluginRequestError::InvalidEndpoint,
            PluginRequestError::RequestTooLarge,
            PluginRequestError::InvalidTemplate,
        ]
    }
    fn prepares() -> Vec<PluginPrepareError> {
        let mut all: Vec<_> = requests()
            .into_iter()
            .map(PluginPrepareError::Request)
            .collect();
        all.extend([
            PluginPrepareError::InvalidContext,
            PluginPrepareError::CallerNotManual,
            PluginPrepareError::NoKeyUse,
            PluginPrepareError::KeyMetadataMissing,
            PluginPrepareError::UnsupportedKey,
            PluginPrepareError::Options,
            PluginPrepareError::KeyUnavailable,
            PluginPrepareError::CertificateMismatch,
            PluginPrepareError::ResourceBudget,
            PluginPrepareError::NoTemporaryStore,
        ]);
        all
    }
    const TICKETS: [TicketRefusal; 21] = [
        TicketRefusal::NoTicket,
        TicketRefusal::NoApproval,
        TicketRefusal::Uses,
        TicketRefusal::Expired,
        TicketRefusal::OperationId,
        TicketRefusal::Identity,
        TicketRefusal::Operation,
        TicketRefusal::Caller,
        TicketRefusal::Key,
        TicketRefusal::Action,
        TicketRefusal::Kind,
        TicketRefusal::Content,
        TicketRefusal::Options,
        TicketRefusal::AlreadyUsed,
        TicketRefusal::UndeclaredOperation,
        TicketRefusal::CertificateChanged,
        TicketRefusal::NoGuard,
        TicketRefusal::Busy,
        TicketRefusal::Replayed,
        TicketRefusal::NotGranted,
        TicketRefusal::AuditFactTooLong,
    ];

    /// Every reason of every source enum has a subcode, and together they cover ALL.
    #[test]
    fn every_reason_maps_and_the_union_is_all() {
        let mut seen = std::collections::BTreeSet::new();
        seen.extend(TICKETS.iter().map(|t| t.subcode()));
        seen.extend(prepares().iter().map(|e| e.subcode()));
        for e in [
            ApprovalIssueError::ConfirmationMismatch,
            ApprovalIssueError::Ttl,
            ApprovalIssueError::Random,
        ] {
            seen.insert(e.subcode());
        }
        for r in [ApprovalRejected::Replayed, ApprovalRejected::Uses] {
            seen.insert(r.into());
        }
        // Raised by the CLI's operator grant, not by a Core reason enum.
        seen.insert(PluginRefusalCode::ContentBindingUnavailable);
        let all: std::collections::BTreeSet<_> = PluginRefusalCode::ALL.into_iter().collect();
        assert_eq!(
            seen, all,
            "a subcode no source reason maps to, or the reverse"
        );
    }

    /// The ErrorCode of a subcode is the one the caller of the call actually gets, and a
    /// guard refusal reaches the plugin as plain PermissionDenied.
    #[test]
    fn error_codes_agree_with_the_operation_error() {
        for e in requests() {
            assert_eq!(
                e.subcode().error_code(),
                OperationError::from(e.clone()).code(),
                "{e}"
            );
        }
        for e in prepares() {
            assert_eq!(
                e.subcode().error_code(),
                OperationError::from(e.clone()).code(),
                "{e}"
            );
        }
        for t in TICKETS {
            assert_eq!(
                t.subcode().error_code(),
                ErrorCode::PermissionDenied,
                "{t:?}"
            );
        }
        assert_eq!(
            ApprovalIssueError::Ttl.subcode().error_code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            ApprovalIssueError::Random.subcode().error_code(),
            ErrorCode::Io
        );
        assert_eq!(
            ApprovalIssueError::ConfirmationMismatch
                .subcode()
                .error_code(),
            ErrorCode::PermissionDenied
        );
    }
}
