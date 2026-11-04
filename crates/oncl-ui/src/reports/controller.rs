//! What the SDK reported, as the page may say it: owned views of the structured reports and
//! the few transformations in which a careless word would mislead. No Slint, no SDK calls and
//! no cryptography: the views hold what the engine already decided, and nothing here decides
//! it again.
//!
//! The transformations that must stay honest, each with its tests:
//!
//! * an `Indeterminate` verdict is never success: only `Valid` is styled as success, at every
//!   level (the document, the signer, the check);
//! * a partial batch is never «everything done»: that headline needs every item completed,
//!   no stop, and every item success;
//! * a signature that was made but not written is not success;
//! * extraction is not verification: its result is never styled as a verified one;
//! * whether a key was used is told as the engine tells it: `NotApplied`, `Applied` or
//!   `Unknown`, and a worker lost after the consent never means «not used».
//!
//! Encrypt and decrypt are not here: G01/G02 (the Kazakhstani GOST encryption backend) are
//! externally blocked and no RSA-only substitute is offered, so there is no envelope report
//! and no decrypt result to mis-name «verified sender».

use std::path::PathBuf;

use oncl_core::ErrorCode;
use oncl_pki::evidence::AdesLevel;
use oncl_pki::key::{AppliedState, HashAlg};
use oncl_pki::tsp::DocumentImprint;
use oncl_pki::validation::{CheckStatus, TimeBasis, ValidationPolicy, ValidationReason, Verdict};
use time::OffsetDateTime;

/// How a result is styled. Only `Success` looks like success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Success,
    /// Not proven either way: the check could not be completed, or the work is partial.
    Caution,
    Failure,
    /// Neither good nor bad: a plain fact (an extraction, nothing to do).
    Neutral,
}

/// The tone a verdict is styled with. `Indeterminate` is a caution, never success.
pub fn verdict_tone(verdict: Verdict) -> Tone {
    match verdict {
        Verdict::Valid => Tone::Success,
        Verdict::Invalid => Tone::Failure,
        Verdict::Indeterminate => Tone::Caution,
    }
}

/// The tone one check is styled with: a check that could not be run is a caution, not a pass.
pub fn check_tone(status: CheckStatus) -> Tone {
    match status {
        CheckStatus::Passed => Tone::Success,
        CheckStatus::Failed => Tone::Failure,
        CheckStatus::Unavailable => Tone::Caution,
        CheckStatus::NotApplicable => Tone::Neutral,
    }
}

/// The checks of one signer, in the order the page shows them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Signature,
    Chain,
    Validity,
    Revocation,
    Timestamp,
    KeyUsage,
}

/// One signer as the SDK checked it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerView {
    /// The SDK's own verdict of the signer ([`SignerValidation::verdict`]
    /// (oncl_pki::validation::SignerValidation::verdict)).
    pub verdict: Verdict,
    pub checks: Vec<(Check, CheckStatus)>,
    pub reasons: Vec<ValidationReason>,
    /// The level the format was actually checked to, if a standard adapter checked one.
    pub level: Option<AdesLevel>,
    pub claimed_signing_time: Option<OffsetDateTime>,
    pub basis: TimeBasis,
    /// The signature algorithm, when the format names it (JOSE, XML).
    pub algorithm: Option<String>,
    /// SHA-256 of the signer's certificate, when the format's report has it.
    pub certificate_sha256: Option<[u8; 32]>,
}

/// A fact of the document's own format, apart from the signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    /// An XML signature's reference: whether its digest matches what it points at.
    XmlReference {
        signature: usize,
        reference: usize,
        resolved: bool,
        digest_matches: bool,
    },
    /// A PDF signature's revision, and whether the file was changed after it.
    PdfRevision {
        revision: usize,
        later_changes: bool,
        signers: usize,
    },
    /// The size of the PDF the signatures were found in.
    PdfExtent(u64),
}

/// The claims of a JWT, apart from its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimsView {
    pub verdict: Verdict,
    pub failures: Vec<oncl_core::jose::ClaimsFailure>,
}

/// A verification as the SDK reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationView {
    pub verdict: Verdict,
    pub policy: ValidationPolicy,
    pub checked_at: OffsetDateTime,
    /// The minimum level actually verified, for the formats that have levels.
    pub level: Option<AdesLevel>,
    pub signers: Vec<SignerView>,
    pub notes: Vec<Note>,
    pub claims: Option<ClaimsView>,
}

/// The checks of a timestamp token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StampCheck {
    Signature,
    TsaUsage,
    Chain,
    Validity,
    Revocation,
    Expectations,
}

/// A timestamp as the SDK reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StampView {
    pub verdict: Verdict,
    pub policy: ValidationPolicy,
    pub checked_at: OffsetDateTime,
    pub gen_time: OffsetDateTime,
    pub checks: Vec<(StampCheck, CheckStatus)>,
    /// Whether the token is of the data given: absent data is `NotProvided`, never `Matched`.
    pub imprint: DocumentImprint,
    pub algorithm: Option<HashAlg>,
    pub tsa_policy: String,
}

/// What one completed item holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detail {
    Hash {
        digest: String,
        bytes: u64,
    },
    /// A signature or an extension that was made. `check` is what the SDK found when it
    /// checked the result it made (an extension re-verifies what it extends).
    Written {
        profile: String,
        signers: usize,
        bytes_out: u64,
        check: Option<VerificationView>,
    },
    Verified(VerificationView),
    /// Content taken out of a signature container: a structural extraction, the signature was
    /// not checked.
    Extracted {
        bytes: u64,
    },
    /// A timestamp that was acquired and checked.
    Stamped(StampView),
    /// A timestamp token that was checked.
    StampChecked(StampView),
}

/// How one item ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed(Detail),
    Failed(ErrorCode),
    NotRun,
}

/// One document of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemView {
    pub name: String,
    pub outcome: Outcome,
    /// Whether a private key was applied for this item, as the engine says.
    pub applied: AppliedState,
    /// The file that was published, if the item wrote one and it is there.
    pub output: Option<PathBuf>,
}

/// Why a batch stopped before its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Cancelled,
    Deadline,
    /// A failure that ends the batch (a quota, the audit, the control).
    Failed(ErrorCode),
}

/// What the operation was, which decides whether key use is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Sign,
    Verify,
    Extend,
    Extract,
    Stamp,
    StampCheck,
}

impl Family {
    /// Whether this family applies a private key.
    pub fn uses_key(self) -> bool {
        matches!(self, Family::Sign)
    }
}

/// A batch as the SDK reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchView {
    pub family: Family,
    pub items: Vec<ItemView>,
    pub stop: Option<Stop>,
    /// Whether the operation reaches a network service (a time stamp service, revocation
    /// status): a failure to read or write is then more likely the network's than a file's.
    pub network: bool,
}

impl Detail {
    /// `published`: the file this item was to write is there. A result whose file is not
    /// there is not a success, whatever the engine made.
    fn tone(&self, published: bool) -> Tone {
        match self {
            Detail::Hash { .. } => Tone::Success,
            Detail::Written { check, .. } => {
                if published {
                    check
                        .as_ref()
                        .map_or(Tone::Success, |check| verdict_tone(check.verdict))
                } else {
                    Tone::Failure
                }
            }
            Detail::Verified(view) => verdict_tone(view.verdict),
            Detail::Extracted { .. } => {
                if published {
                    Tone::Neutral
                } else {
                    Tone::Failure
                }
            }
            Detail::Stamped(view) => {
                if published {
                    verdict_tone(view.verdict)
                } else {
                    Tone::Failure
                }
            }
            Detail::StampChecked(view) => verdict_tone(view.verdict),
        }
    }
}

impl ItemView {
    /// How the item is styled. Success only when the engine said so: a valid verdict, or a
    /// signature that was made and written.
    pub fn tone(&self) -> Tone {
        match &self.outcome {
            Outcome::Completed(detail) => detail.tone(self.output.is_some()),
            Outcome::Failed(ErrorCode::Cancelled) | Outcome::NotRun => Tone::Caution,
            Outcome::Failed(_) => Tone::Failure,
        }
    }

    /// Whether a key was applied for this item.
    pub fn key_use(&self) -> KeyUse {
        key_use(self.applied)
    }
}

/// Whether a private key was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUse {
    NotUsed,
    Used,
    Unknown,
}

/// What the engine's applied state says, and nothing more: «not used» only for `NotApplied`.
pub fn key_use(applied: AppliedState) -> KeyUse {
    match applied {
        AppliedState::NotApplied => KeyUse::NotUsed,
        AppliedState::Applied => KeyUse::Used,
        AppliedState::Unknown => KeyUse::Unknown,
    }
}

/// A worker that was lost (it broke off, or its answer never came) after the consent that lets
/// the key be applied: the key may have been applied, and nobody can say. Never «not used».
pub fn key_use_after_loss(consented: bool) -> KeyUse {
    if consented {
        KeyUse::Unknown
    } else {
        KeyUse::NotUsed
    }
}

/// The verdict of several reports of one item: the worst of them. A `Valid` never covers an
/// `Indeterminate` or an `Invalid` one, and no report at all is not `Valid`.
pub fn combine_verdicts(verdicts: impl IntoIterator<Item = Verdict>) -> Verdict {
    let mut worst = None;
    for verdict in verdicts {
        worst = Some(match (worst, verdict) {
            (Some(Verdict::Invalid), _) | (_, Verdict::Invalid) => Verdict::Invalid,
            (Some(Verdict::Indeterminate), _) | (_, Verdict::Indeterminate) => {
                Verdict::Indeterminate
            }
            _ => Verdict::Valid,
        });
    }
    worst.unwrap_or(Verdict::Indeterminate)
}

/// How many items ended each way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub total: usize,
    pub completed: usize,
    pub succeeded: usize,
    pub invalid: usize,
    pub indeterminate: usize,
    pub unchecked: usize,
    pub failed: usize,
    pub not_run: usize,
}

/// What the page says first about a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Headline {
    Nothing,
    /// Every item completed, and each of them is a success.
    AllSucceeded {
        total: usize,
    },
    /// Every item completed, and some found something: an invalid or indeterminate verdict, or
    /// a result that is not a verification (an extraction).
    AllCompleted {
        total: usize,
        invalid: usize,
        indeterminate: usize,
        unchecked: usize,
    },
    /// Some items did not complete.
    Partial {
        completed: usize,
        total: usize,
    },
    Cancelled {
        completed: usize,
        total: usize,
    },
    Stopped {
        completed: usize,
        total: usize,
    },
}

impl BatchView {
    pub fn counts(&self) -> Counts {
        let mut counts = Counts {
            total: self.items.len(),
            ..Counts::default()
        };
        for item in &self.items {
            match &item.outcome {
                Outcome::Completed(_) => {
                    counts.completed += 1;
                    match item.tone() {
                        Tone::Success => counts.succeeded += 1,
                        Tone::Failure => counts.invalid += 1,
                        Tone::Caution => counts.indeterminate += 1,
                        Tone::Neutral => counts.unchecked += 1,
                    }
                }
                Outcome::Failed(_) => counts.failed += 1,
                Outcome::NotRun => counts.not_run += 1,
            }
        }
        counts
    }

    pub fn headline(&self) -> Headline {
        let c = self.counts();
        if c.total == 0 {
            return Headline::Nothing;
        }
        // A stop keeps «everything succeeded» away, even when every item completed before it.
        match self.stop {
            Some(Stop::Cancelled) => {
                return Headline::Cancelled {
                    completed: c.completed,
                    total: c.total,
                };
            }
            Some(Stop::Deadline | Stop::Failed(_)) => {
                return Headline::Stopped {
                    completed: c.completed,
                    total: c.total,
                };
            }
            None => {}
        }
        if c.completed < c.total {
            return Headline::Partial {
                completed: c.completed,
                total: c.total,
            };
        }
        if c.succeeded == c.total {
            Headline::AllSucceeded { total: c.total }
        } else {
            Headline::AllCompleted {
                total: c.total,
                invalid: c.invalid,
                indeterminate: c.indeterminate,
                unchecked: c.unchecked,
            }
        }
    }

    /// How the headline is styled: success only for «everything succeeded».
    pub fn tone(&self) -> Tone {
        match self.headline() {
            Headline::Nothing => Tone::Neutral,
            Headline::AllSucceeded { .. } => Tone::Success,
            Headline::AllCompleted { invalid, .. } if invalid > 0 => Tone::Failure,
            Headline::AllCompleted { indeterminate, .. } if indeterminate > 0 => Tone::Caution,
            Headline::AllCompleted { .. } => Tone::Neutral,
            Headline::Partial { completed: 0, .. } | Headline::Stopped { .. } => Tone::Failure,
            Headline::Partial { .. } | Headline::Cancelled { .. } => Tone::Caution,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn signer(verdict: Verdict) -> SignerView {
        let status = match verdict {
            Verdict::Valid => CheckStatus::Passed,
            Verdict::Invalid => CheckStatus::Failed,
            Verdict::Indeterminate => CheckStatus::Unavailable,
        };
        SignerView {
            verdict,
            checks: vec![
                (Check::Signature, CheckStatus::Passed),
                (Check::Revocation, status),
            ],
            reasons: Vec::new(),
            level: None,
            claimed_signing_time: None,
            basis: TimeBasis::Current(NOW),
            algorithm: None,
            certificate_sha256: None,
        }
    }

    fn verification(verdict: Verdict) -> VerificationView {
        VerificationView {
            verdict,
            policy: ValidationPolicy::StrictOnline,
            checked_at: NOW,
            level: None,
            signers: vec![signer(verdict)],
            notes: Vec::new(),
            claims: None,
        }
    }

    fn verified(name: &str, verdict: Verdict) -> ItemView {
        ItemView {
            name: name.into(),
            outcome: Outcome::Completed(Detail::Verified(verification(verdict))),
            applied: AppliedState::NotApplied,
            output: None,
        }
    }

    fn signed(name: &str, output: Option<&str>) -> ItemView {
        ItemView {
            name: name.into(),
            outcome: Outcome::Completed(Detail::Written {
                profile: "CMS".into(),
                signers: 1,
                bytes_out: 10,
                check: None,
            }),
            applied: AppliedState::Applied,
            output: output.map(PathBuf::from),
        }
    }

    fn failed(name: &str, code: ErrorCode, applied: AppliedState) -> ItemView {
        ItemView {
            name: name.into(),
            outcome: Outcome::Failed(code),
            applied,
            output: None,
        }
    }

    fn not_run(name: &str) -> ItemView {
        ItemView {
            name: name.into(),
            outcome: Outcome::NotRun,
            applied: AppliedState::NotApplied,
            output: None,
        }
    }

    fn batch(family: Family, items: Vec<ItemView>, stop: Option<Stop>) -> BatchView {
        BatchView {
            family,
            items,
            stop,
            network: false,
        }
    }

    /// An `Indeterminate` verdict is never success: not for the verdict, not for the signer,
    /// not for the check that could not be run, and not for the headline of the batch that
    /// holds it.
    #[test]
    fn an_indeterminate_verdict_is_never_success() {
        assert_eq!(verdict_tone(Verdict::Valid), Tone::Success);
        assert_eq!(verdict_tone(Verdict::Invalid), Tone::Failure);
        assert_eq!(verdict_tone(Verdict::Indeterminate), Tone::Caution);
        assert_eq!(check_tone(CheckStatus::Passed), Tone::Success);
        assert_eq!(check_tone(CheckStatus::Failed), Tone::Failure);
        assert_eq!(check_tone(CheckStatus::Unavailable), Tone::Caution);
        assert_eq!(check_tone(CheckStatus::NotApplicable), Tone::Neutral);
        let b = batch(
            Family::Verify,
            vec![verified("a", Verdict::Indeterminate)],
            None,
        );
        assert_eq!(b.items[0].tone(), Tone::Caution);
        assert_ne!(b.tone(), Tone::Success);
        assert!(!matches!(b.headline(), Headline::AllSucceeded { .. }));
        // One indeterminate among valid ones keeps the whole batch from success too.
        let b = batch(
            Family::Verify,
            vec![
                verified("a", Verdict::Valid),
                verified("b", Verdict::Indeterminate),
                verified("c", Verdict::Valid),
            ],
            None,
        );
        assert_ne!(b.tone(), Tone::Success);
        assert_eq!(
            b.headline(),
            Headline::AllCompleted {
                total: 3,
                invalid: 0,
                indeterminate: 1,
                unchecked: 0
            }
        );
        assert_eq!(b.tone(), Tone::Caution);
    }

    /// A verdict from a verification is styled as success only when it is `Valid`, however many
    /// items say so; an invalid one is a failure and wins over an indeterminate one.
    #[test]
    fn a_verification_is_success_only_when_valid() {
        let all_valid = batch(
            Family::Verify,
            vec![verified("a", Verdict::Valid), verified("b", Verdict::Valid)],
            None,
        );
        assert_eq!(all_valid.headline(), Headline::AllSucceeded { total: 2 });
        assert_eq!(all_valid.tone(), Tone::Success);
        let mixed = batch(
            Family::Verify,
            vec![
                verified("a", Verdict::Valid),
                verified("b", Verdict::Invalid),
                verified("c", Verdict::Indeterminate),
            ],
            None,
        );
        assert_eq!(
            mixed.headline(),
            Headline::AllCompleted {
                total: 3,
                invalid: 1,
                indeterminate: 1,
                unchecked: 0
            }
        );
        assert_eq!(mixed.tone(), Tone::Failure, "an invalid one is a failure");
    }

    /// A partial batch is never «everything done»: failed, not run, cancelled and stopped
    /// items all keep the headline from success, whatever the items that did complete say.
    #[test]
    fn a_partial_batch_is_never_completed_all() {
        let one_failed = batch(
            Family::Sign,
            vec![
                signed("a", Some("a.p7s")),
                failed("b", ErrorCode::InvalidInput, AppliedState::NotApplied),
                signed("c", Some("c.p7s")),
            ],
            None,
        );
        assert_eq!(
            one_failed.headline(),
            Headline::Partial {
                completed: 2,
                total: 3
            }
        );
        assert_ne!(one_failed.tone(), Tone::Success);
        let cancelled = batch(
            Family::Sign,
            vec![signed("a", Some("a.p7s")), not_run("b"), not_run("c")],
            Some(Stop::Cancelled),
        );
        assert_eq!(
            cancelled.headline(),
            Headline::Cancelled {
                completed: 1,
                total: 3
            }
        );
        assert_ne!(cancelled.tone(), Tone::Success);
        // Not run, without a stop: still not everything.
        let not_run_only = batch(
            Family::Verify,
            vec![verified("a", Verdict::Valid), not_run("b")],
            None,
        );
        assert_eq!(
            not_run_only.headline(),
            Headline::Partial {
                completed: 1,
                total: 2
            }
        );
        // A stop keeps «all succeeded» away even when every item completed.
        let stopped = batch(
            Family::Verify,
            vec![verified("a", Verdict::Valid)],
            Some(Stop::Failed(ErrorCode::AuditFailed)),
        );
        assert_eq!(
            stopped.headline(),
            Headline::Stopped {
                completed: 1,
                total: 1
            }
        );
        assert_eq!(stopped.tone(), Tone::Failure);
        // Nothing completed is a failure, not a quiet success.
        let none = batch(
            Family::Sign,
            vec![failed("a", ErrorCode::Io, AppliedState::NotApplied)],
            None,
        );
        assert_eq!(
            none.headline(),
            Headline::Partial {
                completed: 0,
                total: 1
            }
        );
        assert_eq!(none.tone(), Tone::Failure);
        assert_eq!(
            batch(Family::Verify, Vec::new(), None).headline(),
            Headline::Nothing
        );
    }

    /// Whether a key was used is told as the engine tells it. «Not used» comes only from
    /// `NotApplied`; `Unknown` stays unknown; a worker lost after the consent is unknown too.
    #[test]
    fn key_use_is_told_as_the_engine_tells_it() {
        assert_eq!(key_use(AppliedState::NotApplied), KeyUse::NotUsed);
        assert_eq!(key_use(AppliedState::Applied), KeyUse::Used);
        assert_eq!(key_use(AppliedState::Unknown), KeyUse::Unknown);
        assert_eq!(key_use_after_loss(true), KeyUse::Unknown);
        assert_eq!(key_use_after_loss(false), KeyUse::NotUsed);
        // A failure after the key was applied is not «not used»; one the engine could not
        // place is not either.
        for (applied, expected) in [
            (AppliedState::Applied, KeyUse::Used),
            (AppliedState::Unknown, KeyUse::Unknown),
            (AppliedState::NotApplied, KeyUse::NotUsed),
        ] {
            assert_eq!(
                failed("a", ErrorCode::Io, applied).key_use(),
                expected,
                "{applied:?}"
            );
        }
    }

    /// A signature that was made but is not where the page says it is, and a content that was
    /// only extracted, are not success.
    #[test]
    fn made_but_not_written_and_extracted_are_not_success() {
        assert_eq!(signed("a", Some("a.p7s")).tone(), Tone::Success);
        assert_eq!(signed("a", None).tone(), Tone::Failure);
        let extracted = ItemView {
            name: "a.p7s".into(),
            outcome: Outcome::Completed(Detail::Extracted { bytes: 3 }),
            applied: AppliedState::NotApplied,
            output: Some(PathBuf::from("a")),
        };
        assert_eq!(extracted.tone(), Tone::Neutral);
        let b = batch(Family::Extract, vec![extracted], None);
        assert_ne!(b.tone(), Tone::Success);
        assert_eq!(
            b.headline(),
            Headline::AllCompleted {
                total: 1,
                invalid: 0,
                indeterminate: 0,
                unchecked: 1
            }
        );
        assert_eq!(b.tone(), Tone::Neutral);
    }

    /// A timestamp token without the document it is of is not a proof of that document, and a
    /// stamp is judged by its verdict like any other verification.
    #[test]
    fn a_stamp_is_judged_by_its_verdict() {
        let stamp = |verdict| StampView {
            verdict,
            policy: ValidationPolicy::StrictOnline,
            checked_at: NOW,
            gen_time: NOW,
            checks: vec![(StampCheck::Signature, CheckStatus::Passed)],
            imprint: DocumentImprint::NotProvided,
            algorithm: None,
            tsa_policy: "1.2.3".into(),
        };
        for (verdict, tone) in [
            (Verdict::Valid, Tone::Success),
            (Verdict::Indeterminate, Tone::Caution),
            (Verdict::Invalid, Tone::Failure),
        ] {
            let item = ItemView {
                name: "t".into(),
                outcome: Outcome::Completed(Detail::StampChecked(stamp(verdict))),
                applied: AppliedState::NotApplied,
                output: None,
            };
            assert_eq!(item.tone(), tone, "{verdict:?}");
        }
    }

    /// A failure is a failure unless it is a cancel, which is not one but not success either.
    #[test]
    fn failures_and_cancels_are_not_success() {
        assert_eq!(
            failed("a", ErrorCode::InvalidInput, AppliedState::NotApplied).tone(),
            Tone::Failure
        );
        assert_eq!(
            failed("a", ErrorCode::Cancelled, AppliedState::NotApplied).tone(),
            Tone::Caution
        );
        assert_eq!(not_run("a").tone(), Tone::Caution);
    }

    /// Several reports of one item (an extension re-verifies each signer) are one verdict, and
    /// it is the worst: `Invalid` over `Indeterminate` over `Valid`; no reports prove nothing.
    #[test]
    fn a_combined_verdict_is_the_worst() {
        use Verdict::{Indeterminate as I, Invalid as X, Valid as V};
        assert_eq!(combine_verdicts([V, V]), V);
        assert_eq!(combine_verdicts([V, I, V]), I);
        assert_eq!(combine_verdicts([I, X, V]), X);
        assert_eq!(combine_verdicts([X, I]), X);
        assert_eq!(combine_verdicts([]), I, "nothing checked is not valid");
    }
}
