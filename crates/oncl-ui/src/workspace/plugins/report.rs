//! The result of a plugin run, said honestly: what [`oncl_core::plugins::ApprovedCall`] reported,
//! turned into words without deciding it again.
//!
//! * No result is styled as success: the signature in the plugin's reply is never checked
//!   here. A call that Core reports as `Applied`, with no refusal and no error, is a caution
//!   worded "key applied; signature not checked". A key applied and a failure after it, a
//!   key use that did not report (`Unknown`), a refusal, a cancel: none is "done".
//! * The plugin's reply is the plugin's own text: it appears only in [`ReplyView`], which the
//!   page draws in the plugin's frame, cleaned of control and bidirectional characters and cut
//!   at [`MAX_REPLY_CHARS`]. It is never in the headline or the rows.
//! * Why Core refused a key use is said through [`RefusalWords`], a seam: the local mapping
//!   [`TicketWords`] words each `TicketRefusal` of Core; when Core's refusal subcodes land the
//!   page swaps this one implementation and nothing else.
//! * The host saves nothing by itself. The reply of an applied call (the caution condition
//!   above) can be saved, whole and as received, to a `.json` file the user places
//!   (`save.rs`): the manifest declares no file output for the manual window and Core's call
//!   has no output binding, so the reply is the only thing there is to save, and the host
//!   never extracts a signature from it.

use oncl_core::ErrorCode;
use oncl_core::plugins::{
    PluginPrepareError, PluginRefusalCode, PluginRequestError, TicketRefusal,
};
use oncl_flows::Locale;
use oncl_pki::key::AppliedState;

use super::save::SaveOffer;
use super::texts::Texts;
use crate::reports::{Row, controller::Tone};
use crate::workspace::{JobError, Texts as WorkspaceTexts, error_text};

/// The most characters of a plugin's reply the page shows; the rest is only counted. A reply
/// is not a document: a signature or a short status.
pub(super) const MAX_REPLY_CHARS: usize = 2000;

/// What Core said of a call, as plain data (the engine's own objects stay on the worker).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::workspace) struct CallReport {
    pub(super) applied: AppliedState,
    /// Core's typed refusals of this invocation, oldest first.
    pub(super) refusals: Vec<TicketRefusal>,
    /// Core's stable reason for the refusal, if it gave one.
    pub(super) subcode: Option<PluginRefusalCode>,
    /// The module's reply, if it replied.
    pub(super) response: Option<String>,
    /// How the call failed, if it did.
    pub(super) error: Option<ErrorCode>,
}

/// Who ran: the operation and the plugin, from the host's own data.
pub(super) struct RunFacts<'a> {
    pub(super) operation: &'a str,
    pub(super) plugin_id: &'a str,
    pub(super) plugin_version: &'a str,
}

/// How the refusals of Core are put into words.
pub(super) trait RefusalWords {
    fn words(&self, refusal: &TicketRefusal, l: Locale) -> String;
    /// The words for a stable subcode of Core.
    fn code(&self, code: PluginRefusalCode, l: Locale) -> String;
}

/// The subcodes that have words of their own; every other one gets the generic text and its id
/// as a technical row. A new code of Core is in neither list until it is classified, and
/// `every_subcode_is_classified` fails until then.
pub(super) fn code_words(code: PluginRefusalCode, l: Locale) -> Option<&'static str> {
    use PluginRefusalCode as C;
    let t = Texts::of(l);
    Some(match code {
        C::TicketMissing => t.f_no_ticket,
        C::ApprovalMissing => t.f_no_approval,
        C::TicketUses => t.f_uses,
        C::ApprovalExpired => t.f_expired,
        C::OperationIdMismatch => t.f_operation_id,
        C::PackageChanged => t.f_identity,
        C::OperationMismatch => t.f_operation,
        C::CallerMismatch => t.f_caller,
        C::KeyMismatch => t.f_key,
        C::ActionMismatch => t.f_action,
        C::KindMismatch => t.f_kind,
        C::ContentMismatch => t.f_content,
        C::OptionsMismatch => t.f_options,
        C::KeyUseSpent => t.f_already_used,
        C::NotDeclared => t.f_undeclared,
        C::CertificateChanged => t.f_certificate_changed,
        C::NoConsentGuard => t.f_no_guard,
        C::Busy => t.f_busy,
        C::ApprovalReplayed => t.f_replayed,
        C::UnknownPlugin
        | C::NotManual
        | C::DerivedUnsupported
        | C::NetworkUnsupported
        | C::NetworkNotDeclared => t.p_not_runnable,
        C::ParamTooLarge | C::RequestTooLarge => t.p_too_large,
        C::UnknownParam
        | C::DuplicateParam
        | C::MissingParam
        | C::ParamWrongKind
        | C::ParamInvalidValue => t.p_value,
        C::KeyUnavailable => t.p_key_unavailable,
        C::CertificateMismatch => t.p_cert_mismatch,
        C::UnsupportedKey => t.p_unsupported_key,
        C::NoKeyUse => t.p_no_key_use,
        C::OptionsInvalid => t.p_options,
        C::ResourceBudget => t.p_budget,
        C::NoTemporaryStore => t.p_no_store,
        _ => return None,
    })
}

/// The subcodes worded only generically (with their id shown).
#[cfg(test)]
pub(super) const GENERIC_ONLY: [PluginRefusalCode; 11] = [
    PluginRefusalCode::NotGranted,
    PluginRefusalCode::InvalidEndpoint,
    PluginRefusalCode::InvalidTemplate,
    PluginRefusalCode::InvalidContext,
    PluginRefusalCode::CallerNotManual,
    PluginRefusalCode::KeyMetadataMissing,
    PluginRefusalCode::ConfirmationMismatch,
    PluginRefusalCode::ApprovalTtlInvalid,
    PluginRefusalCode::ApprovalRandomUnavailable,
    PluginRefusalCode::AuditFactTooLong,
    PluginRefusalCode::ContentBindingUnavailable,
];

/// The local mapping of the variants of [`TicketRefusal`] (which is `non_exhaustive`: a variant
/// this build does not know is worded as «refused»).
pub(super) struct TicketWords;

impl RefusalWords for TicketWords {
    fn words(&self, refusal: &TicketRefusal, l: Locale) -> String {
        let t = Texts::of(l);
        match refusal {
            TicketRefusal::NoTicket => t.f_no_ticket,
            TicketRefusal::NoApproval => t.f_no_approval,
            TicketRefusal::Uses => t.f_uses,
            TicketRefusal::Expired => t.f_expired,
            TicketRefusal::OperationId => t.f_operation_id,
            TicketRefusal::Identity => t.f_identity,
            TicketRefusal::Operation => t.f_operation,
            TicketRefusal::Caller => t.f_caller,
            TicketRefusal::Key => t.f_key,
            TicketRefusal::Action => t.f_action,
            TicketRefusal::Kind => t.f_kind,
            TicketRefusal::Content => t.f_content,
            TicketRefusal::Options => t.f_options,
            TicketRefusal::AlreadyUsed => t.f_already_used,
            TicketRefusal::UndeclaredOperation => t.f_undeclared,
            TicketRefusal::CertificateChanged => t.f_certificate_changed,
            TicketRefusal::NoGuard => t.f_no_guard,
            TicketRefusal::Busy => t.f_busy,
            TicketRefusal::Replayed => t.f_replayed,
            _ => t.f_other,
        }
        .to_owned()
    }
    fn code(&self, code: PluginRefusalCode, l: Locale) -> String {
        code_words(code, l)
            .unwrap_or(Texts::of(l).f_other)
            .to_owned()
    }
}

/// The plugin's reply as the frame draws it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReplyView {
    pub(super) caption: String,
    pub(super) text: String,
    /// «… N more characters are not shown.», or empty.
    pub(super) cut_note: String,
}

/// The result page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResultView {
    pub(super) tone: Tone,
    pub(super) headline: String,
    /// Facts the host knows: the key use, the operation, the plugin.
    pub(super) rows: Vec<Row>,
    pub(super) reply: Option<ReplyView>,
    pub(super) note: String,
    /// The whole reply and the name the host suggests, only for a call that was verified
    /// applied (the same condition as the "key applied; signature not checked" caution).
    pub(super) save: Option<SaveOffer>,
}

/// A reply as the frame draws it: line breaks and tabs become spaces, other control characters
/// and bidirectional controls are gone, at most [`MAX_REPLY_CHARS`] characters; and how many
/// more there were.
pub(super) fn clean_reply(raw: &str) -> (String, usize) {
    let mut shown = String::new();
    let (mut kept, mut cut) = (0usize, 0usize);
    for c in raw.chars() {
        let c = match c {
            '\n' | '\r' | '\t' => ' ',
            c if crate::view::is_invisible(c) => continue,
            c => c,
        };
        if kept < MAX_REPLY_CHARS {
            shown.push(c);
            kept += 1;
        } else {
            cut += 1;
        }
    }
    (shown, cut)
}

/// The words for why a confirmation could not be prepared.
pub(super) fn prepare_error_text(l: Locale, e: &PluginPrepareError) -> &'static str {
    let t = Texts::of(l);
    match e {
        PluginPrepareError::Request(r) => match r {
            PluginRequestError::TooLarge(_) | PluginRequestError::RequestTooLarge => t.p_too_large,
            PluginRequestError::MissingParam(_)
            | PluginRequestError::UnknownParam(_)
            | PluginRequestError::DuplicateParam(_)
            | PluginRequestError::WrongKind(_)
            | PluginRequestError::InvalidValue(_) => t.p_value,
            _ => t.p_not_runnable,
        },
        // The cause of a failed open (a wrong password, a cancel, a deadline) is not kept by
        // Core: one sentence for all of them.
        PluginPrepareError::KeyUnavailable => t.p_key_unavailable,
        PluginPrepareError::CertificateMismatch => t.p_cert_mismatch,
        PluginPrepareError::UnsupportedKey => t.p_unsupported_key,
        PluginPrepareError::NoKeyUse => t.p_no_key_use,
        PluginPrepareError::Options => t.p_options,
        PluginPrepareError::InvalidContext
        | PluginPrepareError::CallerNotManual
        | PluginPrepareError::KeyMetadataMissing => t.p_other,
        _ => t.p_other,
    }
}

fn plain_rows(facts: &RunFacts<'_>, l: Locale, key: &str) -> Vec<Row> {
    let t = Texts::of(l);
    let row = |text: String| Row {
        depth: 0,
        tone: Tone::Neutral,
        text,
        detail: String::new(),
    };
    vec![
        row(key.to_owned()),
        row(t.row_operation.replace("{0}", facts.operation)),
        row(t
            .row_plugin
            .replace("{0}", facts.plugin_id)
            .replace("{1}", facts.plugin_version)),
    ]
}

/// The result page of `report`.
pub(super) fn render(
    report: &CallReport,
    facts: &RunFacts<'_>,
    l: Locale,
    words: &dyn RefusalWords,
) -> ResultView {
    let t = Texts::of(l);
    let key_row = match report.applied {
        AppliedState::Applied => t.row_key_applied,
        AppliedState::NotApplied => t.row_key_not_applied,
        AppliedState::Unknown => t.row_key_unknown,
    };
    let mut rows = plain_rows(facts, l, key_row);
    // Why, as far as Core says it: its typed refusals first, then the error's code.
    let reason = {
        let mut parts: Vec<String> = match report.subcode {
            Some(code) => vec![words.code(code, l)],
            None => report.refusals.iter().map(|r| words.words(r, l)).collect(),
        };
        if let (true, Some(code)) = (parts.is_empty(), report.error) {
            parts.push(error_text(WorkspaceTexts::of(l), &JobError::Operation(code), 0).to_owned());
        }
        if parts.is_empty() {
            t.no_reason.to_owned()
        } else {
            parts.join("; ")
        }
    };
    let reason_known =
        !report.refusals.is_empty() || report.subcode.is_some() || report.error.is_some();
    // The key was applied and a reply came back; the reply's signature is NOT checked here,
    // so this is never styled as success (the green of a verified signature).
    let applied_ok = report.applied == AppliedState::Applied
        && report.refusals.is_empty()
        && report.error.is_none()
        && report.response.is_some();
    let (tone, headline) = match (report.applied, &report.error) {
        _ if applied_ok => (Tone::Caution, t.r_ok.to_owned()),
        (AppliedState::Applied, None) if !reason_known => {
            (Tone::Failure, t.r_applied_no_reply.to_owned())
        }
        (AppliedState::Applied, _) => (Tone::Failure, t.r_applied_failed.replace("{0}", &reason)),
        (AppliedState::Unknown, _) => (Tone::Caution, t.r_unknown.to_owned()),
        (AppliedState::NotApplied, Some(ErrorCode::Cancelled)) if report.refusals.is_empty() => {
            (Tone::Neutral, t.r_cancelled_before.to_owned())
        }
        // The module answered but the key was never applied: a reply that claims a signature
        // is not believed, and the page does not call it done.
        (AppliedState::NotApplied, None) => {
            (Tone::Caution, t.r_not_applied.replace("{0}", &reason))
        }
        (AppliedState::NotApplied, Some(_)) => {
            (Tone::Failure, t.r_not_applied.replace("{0}", &reason))
        }
    };
    if applied_ok {
        rows.push(Row {
            depth: 0,
            tone: Tone::Caution,
            text: t.row_not_verified.to_owned(),
            detail: String::new(),
        });
    }
    if let Some(code) = report.subcode {
        rows.push(Row {
            depth: 0,
            tone: Tone::Neutral,
            text: t.row_code.replace("{0}", code.id()),
            detail: String::new(),
        });
    }
    if reason_known && !applied_ok {
        rows.push(Row {
            depth: 0,
            tone: Tone::Neutral,
            text: t.row_reason.replace("{0}", &reason),
            detail: String::new(),
        });
    }
    let reply = report.response.as_ref().map(|raw| {
        let (text, cut) = clean_reply(raw);
        ReplyView {
            caption: t.reply_caption.replace("{0}", &MAX_REPLY_CHARS.to_string()),
            text,
            cut_note: if cut == 0 {
                String::new()
            } else {
                t.reply_cut.replace("{0}", &cut.to_string())
            },
        }
    });
    let save = report
        .response
        .as_deref()
        .filter(|raw| applied_ok && !raw.is_empty())
        .map(|raw| SaveOffer::new(raw, facts.operation, facts.plugin_id));
    ResultView {
        tone,
        headline,
        rows,
        reply,
        note: if save.is_some() {
            t.save_note_offered
        } else if report.response.is_some() {
            t.save_note_none
        } else {
            ""
        }
        .to_owned(),
        save,
    }
}

/// The result of a run that ended with no call: the worker was lost after the confirmation.
pub(super) fn render_lost(facts: &RunFacts<'_>, l: Locale) -> ResultView {
    let t = Texts::of(l);
    ResultView {
        tone: Tone::Caution,
        headline: t.r_lost.to_owned(),
        rows: plain_rows(facts, l, t.row_key_unknown),
        reply: None,
        note: String::new(),
        save: None,
    }
}

/// The result of a run that was cancelled before the key could be used.
pub(super) fn render_cancelled(facts: &RunFacts<'_>, l: Locale) -> ResultView {
    let t = Texts::of(l);
    ResultView {
        tone: Tone::Neutral,
        headline: t.r_cancelled_before.to_owned(),
        rows: plain_rows(facts, l, t.row_key_not_applied),
        reply: None,
        note: String::new(),
        save: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Locale; 3] = [Locale::Ru, Locale::Kk, Locale::En];

    fn facts() -> RunFacts<'static> {
        RunFacts {
            operation: "sign-xml",
            plugin_id: "test.ui",
            plugin_version: "1.2.3",
        }
    }

    fn report(
        applied: AppliedState,
        refusals: Vec<TicketRefusal>,
        response: Option<&str>,
        error: Option<ErrorCode>,
    ) -> CallReport {
        CallReport {
            applied,
            refusals,
            subcode: None,
            response: response.map(str::to_owned),
            error,
        }
    }

    fn all_text(v: &ResultView) -> String {
        let mut text = vec![v.headline.clone(), v.note.clone()];
        for row in &v.rows {
            text.push(row.text.clone());
            text.push(row.detail.clone());
        }
        text.join("\n")
    }

    /// Core's refusals, one of each variant this build knows.
    fn every_refusal() -> Vec<TicketRefusal> {
        use TicketRefusal::*;
        vec![
            NoTicket,
            NoApproval,
            Uses,
            Expired,
            OperationId,
            Identity,
            Operation,
            Caller,
            Key,
            Action,
            Kind,
            Content,
            Options,
            AlreadyUsed,
            UndeclaredOperation,
            CertificateChanged,
            NoGuard,
            Busy,
            Replayed,
        ]
    }

    #[test]
    fn no_plugin_result_is_styled_success_and_an_applied_reply_is_a_caution() {
        use AppliedState::*;
        let states = [Applied, NotApplied, Unknown];
        let refusal_sets = [Vec::new(), vec![TicketRefusal::Content]];
        let replies = [None, Some("reply")];
        let errors = [
            None,
            Some(ErrorCode::PermissionDenied),
            Some(ErrorCode::Cancelled),
        ];
        for applied in states {
            for refusals in &refusal_sets {
                for reply in replies {
                    for error in errors {
                        let r = report(applied, refusals.clone(), reply, error);
                        let v = render(&r, &facts(), Locale::En, &TicketWords);
                        let success = applied == Applied
                            && refusals.is_empty()
                            && error.is_none()
                            && reply.is_some();
                        // The reply's signature is never checked here: nothing is green.
                        assert_ne!(
                            v.tone,
                            Tone::Success,
                            "{applied:?} {refusals:?} {reply:?} {error:?} was styled {:?}",
                            v.tone
                        );
                        if success {
                            assert_eq!(v.tone, Tone::Caution);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_key_use_is_worded_as_the_engine_reported_it() {
        for l in ALL {
            let t = Texts::of(l);
            let applied = render(
                &report(AppliedState::Applied, vec![], Some("r"), None),
                &facts(),
                l,
                &TicketWords,
            );
            assert!(
                applied.rows.iter().any(|r| r.text == t.row_key_applied),
                "{l:?}"
            );
            assert_eq!(applied.headline, t.r_ok);
            // The signature in the reply is said not to have been checked here.
            assert!(applied.rows.iter().any(|r| r.text == t.row_not_verified));

            let after = render(
                &report(
                    AppliedState::Applied,
                    vec![],
                    None,
                    Some(ErrorCode::DeadlineExceeded),
                ),
                &facts(),
                l,
                &TicketWords,
            );
            assert!(after.rows.iter().any(|r| r.text == t.row_key_applied));
            assert!(
                after
                    .headline
                    .starts_with(t.r_applied_failed.split('{').next().unwrap()),
                "{l:?}: {}",
                after.headline
            );
            assert_eq!(after.tone, Tone::Failure);

            let unknown = render(
                &report(
                    AppliedState::Unknown,
                    vec![],
                    None,
                    Some(ErrorCode::InvalidInput),
                ),
                &facts(),
                l,
                &TicketWords,
            );
            assert_eq!(unknown.headline, t.r_unknown);
            assert_eq!(unknown.tone, Tone::Caution);
            assert!(unknown.rows.iter().any(|r| r.text == t.row_key_unknown));

            let not = render(
                &report(
                    AppliedState::NotApplied,
                    vec![TicketRefusal::Content],
                    None,
                    Some(ErrorCode::PermissionDenied),
                ),
                &facts(),
                l,
                &TicketWords,
            );
            assert!(not.rows.iter().any(|r| r.text == t.row_key_not_applied));
            assert!(
                not.headline.contains(t.f_content),
                "{l:?}: {}",
                not.headline
            );
            assert_eq!(not.tone, Tone::Failure);
        }
    }

    #[test]
    fn the_replies_text_is_only_in_the_reply_and_is_cut() {
        let long = format!("{}{}", "r".repeat(MAX_REPLY_CHARS), "x".repeat(37));
        for l in ALL {
            let v = render(
                &report(AppliedState::Applied, vec![], Some(&long), None),
                &facts(),
                l,
                &TicketWords,
            );
            let reply = v.reply.as_ref().expect("the reply is shown");
            assert_eq!(reply.text.chars().count(), MAX_REPLY_CHARS);
            assert!(!reply.text.contains('x'));
            assert!(reply.cut_note.contains("37"), "{l:?}: {}", reply.cut_note);
            // The reply text is not in anything the host says.
            assert!(!all_text(&v).contains("rrrrr"), "{l:?}");
        }
        let (text, cut) = clean_reply("a\u{202E}b\nc\td\u{7}e");
        assert_eq!((text.as_str(), cut), ("ab c de", 0));
    }

    #[test]
    fn every_refusal_of_core_is_worded_in_every_language() {
        let refusals = every_refusal();
        for l in ALL {
            let words: Vec<String> = refusals.iter().map(|r| TicketWords.words(r, l)).collect();
            assert!(words.iter().all(|w| !w.is_empty()), "{l:?}");
            let mut distinct = words.clone();
            distinct.sort();
            distinct.dedup();
            assert_eq!(
                distinct.len(),
                words.len(),
                "{l:?}: two refusals share words"
            );
        }
    }

    #[test]
    fn every_subcode_is_classified_and_worded_in_every_language() {
        for code in PluginRefusalCode::ALL {
            let generic = GENERIC_ONLY.contains(&code);
            for l in ALL {
                assert_eq!(
                    code_words(code, l).is_none(),
                    generic,
                    "{} must be either worded or in GENERIC_ONLY",
                    code.id()
                );
                let words = TicketWords.code(code, l);
                assert!(!words.is_empty());
            }
        }
        // A generic one still shows its stable id as a technical row.
        let r = CallReport {
            applied: AppliedState::NotApplied,
            refusals: vec![],
            subcode: Some(PluginRefusalCode::NotGranted),
            response: None,
            error: Some(ErrorCode::PermissionDenied),
        };
        let v = render(&r, &facts(), Locale::En, &TicketWords);
        assert!(v.rows.iter().any(|row| row.text.contains("not-granted")));
        // A worded one is worded by its own text.
        let r = CallReport {
            subcode: Some(PluginRefusalCode::ContentMismatch),
            ..r
        };
        let v = render(&r, &facts(), Locale::En, &TicketWords);
        assert!(v.headline.contains(Texts::of(Locale::En).f_content));
    }

    #[test]
    fn an_applied_call_with_no_reason_does_not_end_on_an_empty_reason() {
        for l in ALL {
            let r = report(AppliedState::Applied, vec![], None, None);
            let v = render(&r, &facts(), l, &TicketWords);
            assert!(
                v.headline == Texts::of(l).r_applied_no_reply,
                "{}",
                v.headline
            );
            assert!(!v.headline.trim_end().ends_with(':'));
            assert_eq!(v.tone, Tone::Failure);
        }
    }

    #[test]
    fn the_reply_and_names_lose_invisible_and_direction_characters() {
        let (text, _) = clean_reply("a\u{200E}b\u{200F}c\u{061C}d\u{200B}e\u{2066}f\u{FEFF}g");
        assert_eq!(text, "abcdefg");
        assert_eq!(
            crate::view::display_text("x\u{200E}y\u{200D}z\u{202E}"),
            "xyz"
        );
        // Hangul fillers are drawn as blanks: Core's set, one source.
        let (text, _) = clean_reply("a\u{115F}b\u{1160}c\u{3164}d\u{FFA0}e");
        assert_eq!(text, "abcde");
    }

    #[test]
    fn the_refusal_words_are_a_seam() {
        struct Subcodes;
        impl RefusalWords for Subcodes {
            fn words(&self, refusal: &TicketRefusal, _: Locale) -> String {
                format!("SEAM-{refusal:?}")
            }
            fn code(&self, code: PluginRefusalCode, _: Locale) -> String {
                format!("SEAM-{}", code.id())
            }
        }
        let r = report(
            AppliedState::NotApplied,
            vec![TicketRefusal::Expired],
            None,
            Some(ErrorCode::PermissionDenied),
        );
        let v = render(&r, &facts(), Locale::En, &Subcodes);
        assert!(v.headline.contains("SEAM-Expired"), "{}", v.headline);
    }

    #[test]
    fn an_expired_approval_says_to_confirm_again_and_that_nothing_was_signed() {
        for l in ALL {
            let t = Texts::of(l);
            let v = render(
                &report(
                    AppliedState::NotApplied,
                    vec![TicketRefusal::Expired],
                    None,
                    Some(ErrorCode::PermissionDenied),
                ),
                &facts(),
                l,
                &TicketWords,
            );
            assert!(v.headline.contains(t.f_expired), "{l:?}");
            assert!(v.rows.iter().any(|r| r.text == t.row_key_not_applied));
            assert_ne!(v.tone, Tone::Success);
        }
    }

    #[test]
    fn a_cancel_and_a_lost_worker_are_not_success() {
        for l in ALL {
            let t = Texts::of(l);
            let cancelled = render_cancelled(&facts(), l);
            assert_eq!(cancelled.headline, t.r_cancelled_before);
            assert_eq!(cancelled.tone, Tone::Neutral);
            let lost = render_lost(&facts(), l);
            assert_eq!(lost.headline, t.r_lost);
            assert_eq!(lost.tone, Tone::Caution);
            assert!(lost.rows.iter().any(|r| r.text == t.row_key_unknown));
        }
    }

    #[test]
    fn prepare_errors_are_worded_and_name_no_cause_of_the_key_open() {
        for l in ALL {
            let t = Texts::of(l);
            assert_eq!(
                prepare_error_text(l, &PluginPrepareError::KeyUnavailable),
                t.p_key_unavailable
            );
            assert_eq!(
                prepare_error_text(l, &PluginPrepareError::CertificateMismatch),
                t.p_cert_mismatch
            );
            assert_eq!(
                prepare_error_text(
                    l,
                    &PluginPrepareError::Request(PluginRequestError::TooLarge("file".into()))
                ),
                t.p_too_large
            );
            assert_eq!(
                prepare_error_text(l, &PluginPrepareError::NoKeyUse),
                t.p_no_key_use
            );
        }
        let _ = (JobError::Cancelled, WorkspaceTexts::of(Locale::En));
        let _ = error_text;
    }

    /// The reply of a verified-applied call is offered whole (not the 2000 characters shown),
    /// under a name built from the host's own facts; no other call offers anything.
    #[test]
    fn only_a_verified_applied_call_offers_the_whole_reply_under_a_host_made_name() {
        let long = format!("{{\"x\":\"{}\"}}\n\u{202e}", "A".repeat(5000));
        for l in ALL {
            let ok = render(
                &report(AppliedState::Applied, vec![], Some(&long), None),
                &facts(),
                l,
                &TicketWords,
            );
            let offer = ok.save.expect("verified applied: offered");
            assert_eq!(offer.reply.bytes(), long.as_bytes());
            assert!(ok.reply.unwrap().text.chars().count() <= MAX_REPLY_CHARS);
            assert_eq!(offer.name, "sign-xml-test.ui.json");
            let t = Texts::of(l);
            assert_eq!(ok.note, t.save_note_offered);
            let cases = [
                report(AppliedState::NotApplied, vec![], Some(&long), None),
                report(AppliedState::Unknown, vec![], Some(&long), None),
                report(AppliedState::Applied, vec![], None, None),
                report(
                    AppliedState::Applied,
                    vec![],
                    Some(&long),
                    Some(ErrorCode::Cancelled),
                ),
                report(
                    AppliedState::Applied,
                    vec![TicketRefusal::Expired],
                    Some(&long),
                    None,
                ),
            ];
            for case in cases {
                let view = render(&case, &facts(), l, &TicketWords);
                assert!(view.save.is_none(), "{case:?}");
            }
        }
        // A reply that tries to name the file changes nothing about the name.
        let hostile = "{\"file\":\"../../evil.exe\"}";
        let view = render(
            &report(AppliedState::Applied, vec![], Some(hostile), None),
            &facts(),
            Locale::En,
            &TicketWords,
        );
        assert_eq!(view.save.unwrap().name, "sign-xml-test.ui.json");
    }
}
