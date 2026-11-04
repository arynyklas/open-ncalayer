//! Reports of the manual tools: what the SDK found, said without deciding it again.
//! [`controller`] holds the owned views of the SDK's structured reports and the transformations
//! in which a careless word would mislead (an indeterminate verdict called success, a partial
//! batch called finished, a key called unused); this module turns them into the rows the page
//! shows, in the window's language: a headline, then per document, per signer and per check.

pub(crate) mod controller;

use oncl_core::ErrorCode;
use oncl_core::jose::ClaimsFailure;
use oncl_flows::Locale;
use oncl_pki::cms::Problem;
use oncl_pki::tsp::DocumentImprint;
use oncl_pki::validation::{CheckStatus, TimeBasis, ValidationPolicy, ValidationReason, Verdict};
use time::OffsetDateTime;

use self::controller::{
    BatchView, Check, Detail, Family, Headline, ItemView, KeyUse, Note, Outcome, SignerView,
    StampCheck, StampView, Tone, VerificationView, check_tone, verdict_tone,
};

/// One line of a report. `depth` indents it under its document or signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) depth: i32,
    pub(crate) tone: Tone,
    pub(crate) text: String,
    /// A second, quieter line: the facts behind the text.
    pub(crate) detail: String,
}

/// A report as the page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rendered {
    pub(crate) tone: Tone,
    pub(crate) headline: String,
    pub(crate) rows: Vec<Row>,
}

/// A tone as the page's property: 0 success, 1 caution, 2 failure, 3 neutral.
pub(crate) fn tone_number(tone: Tone) -> i32 {
    match tone {
        Tone::Success => 0,
        Tone::Caution => 1,
        Tone::Failure => 2,
        Tone::Neutral => 3,
    }
}

/// The report of `view`, in `locale`.
pub(crate) fn render(locale: Locale, view: &BatchView) -> Rendered {
    let t = Texts::of(locale);
    let mut rows = Vec::new();
    for item in &view.items {
        item_rows(t, view.family, item, &mut rows);
    }
    let mut headline = headline_text(t, view);
    if view.family.uses_key() {
        headline.push(' ');
        headline.push_str(&key_line(t, view));
    }
    Rendered {
        tone: view.tone(),
        headline,
        rows,
    }
}

fn family_index(family: Family) -> usize {
    match family {
        Family::Sign => 0,
        Family::Verify => 1,
        Family::Extend => 2,
        Family::Extract => 3,
        Family::Stamp => 4,
        Family::StampCheck => 5,
    }
}

fn headline_text(t: &Texts, view: &BatchView) -> String {
    match view.headline() {
        Headline::Nothing => t.nothing.to_owned(),
        Headline::AllSucceeded { total } => {
            t.all_succeeded[family_index(view.family)].replace("{0}", &total.to_string())
        }
        Headline::AllCompleted {
            total,
            invalid,
            indeterminate,
            unchecked,
        } => {
            let mut parts = Vec::new();
            if invalid > 0 {
                parts.push(t.found_invalid.replace("{0}", &invalid.to_string()));
            }
            if indeterminate > 0 {
                parts.push(
                    t.found_indeterminate
                        .replace("{0}", &indeterminate.to_string()),
                );
            }
            if unchecked > 0 {
                parts.push(t.found_unchecked.replace("{0}", &unchecked.to_string()));
            }
            t.all_completed
                .replace("{0}", &total.to_string())
                .replace("{1}", &parts.join("; "))
        }
        Headline::Partial { completed, total } => t
            .partial
            .replace("{0}", &completed.to_string())
            .replace("{1}", &total.to_string()),
        Headline::Cancelled { completed, total } => t
            .cancelled
            .replace("{0}", &completed.to_string())
            .replace("{1}", &total.to_string()),
        Headline::Stopped { completed, total } => t
            .stopped
            .replace("{0}", &completed.to_string())
            .replace("{1}", &total.to_string()),
    }
}

/// Whether the key was used, for the batch: said as the engine says it, never more.
fn key_line(t: &Texts, view: &BatchView) -> String {
    let count = |wanted: KeyUse| view.items.iter().filter(|i| i.key_use() == wanted).count();
    let (used, unknown) = (count(KeyUse::Used), count(KeyUse::Unknown));
    if unknown > 0 {
        t.key_unknown_n.replace("{0}", &unknown.to_string())
    } else if used > 0 {
        t.key_used_n.replace("{0}", &used.to_string())
    } else {
        t.key_none.to_owned()
    }
}

fn key_clause(t: &Texts, item: &ItemView) -> &'static str {
    match item.key_use() {
        KeyUse::NotUsed => t.key_not_used,
        KeyUse::Used => t.key_used,
        KeyUse::Unknown => t.key_unknown,
    }
}

fn verdict_word(t: &Texts, verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Valid => t.verdict_valid,
        Verdict::Invalid => t.verdict_invalid,
        Verdict::Indeterminate => t.verdict_indeterminate,
    }
}

fn item_rows(t: &Texts, family: Family, item: &ItemView, rows: &mut Vec<Row>) {
    let tone = item.tone();
    let output = item
        .output
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    match &item.outcome {
        Outcome::Completed(detail) => match detail {
            Detail::Hash { digest, bytes } => rows.push(Row {
                depth: 0,
                tone,
                text: format!("{}: {digest}", item.name),
                detail: t.bytes.replace("{0}", &bytes.to_string()),
            }),
            Detail::Written {
                profile,
                signers,
                bytes_out,
                check,
            } => {
                let text = if item.output.is_some() {
                    t.written
                        .replace("{0}", &item.name)
                        .replace("{1}", profile)
                        .replace("{2}", &output)
                } else {
                    t.written_missing
                        .replace("{0}", &item.name)
                        .replace("{1}", profile)
                };
                rows.push(Row {
                    depth: 0,
                    tone,
                    text,
                    detail: format!(
                        "{} · {}",
                        t.signers_n.replace("{0}", &signers.to_string()),
                        t.bytes.replace("{0}", &bytes_out.to_string())
                    ),
                });
                if let Some(check) = check {
                    verification_rows(t, check, rows);
                }
            }
            Detail::Verified(v) => {
                // A token whose signature is good but whose claims fail is not «a bad
                // signature»: it says which of the two it is.
                let claims_only = v.verdict == Verdict::Invalid
                    && v.claims
                        .as_ref()
                        .is_some_and(|c| c.verdict != Verdict::Valid)
                    && !v.signers.is_empty()
                    && v.signers.iter().all(|s| s.verdict == Verdict::Valid);
                rows.push(Row {
                    depth: 0,
                    tone,
                    text: if claims_only {
                        t.token_claims_failed.replace("{0}", &item.name)
                    } else {
                        format!("{}: {}", item.name, verdict_word(t, v.verdict))
                    },
                    detail: policy_line(t, v.policy, v.checked_at, v.level),
                });
                verification_rows(t, v, rows);
            }
            Detail::Extracted { bytes } => rows.push(Row {
                depth: 0,
                tone,
                text: if item.output.is_some() {
                    t.extracted
                        .replace("{0}", &item.name)
                        .replace("{1}", &output)
                } else {
                    t.extracted_missing.replace("{0}", &item.name)
                },
                detail: t.bytes.replace("{0}", &bytes.to_string()),
            }),
            Detail::Stamped(s) | Detail::StampChecked(s) => {
                let acquired = matches!(detail, Detail::Stamped(_));
                let text = if acquired && item.output.is_some() {
                    t.stamp_acquired
                        .replace("{0}", &item.name)
                        .replace("{1}", verdict_word(t, s.verdict))
                        .replace("{2}", &output)
                } else if acquired {
                    t.stamp_not_written.replace("{0}", &item.name)
                } else {
                    format!("{}: {}", item.name, verdict_word(t, s.verdict))
                };
                rows.push(Row {
                    depth: 0,
                    tone,
                    text,
                    detail: policy_line(t, s.policy, s.checked_at, None),
                });
                stamp_rows(t, s, rows);
            }
        },
        Outcome::Failed(code) => {
            let mut text = t
                .failed
                .replace("{0}", &item.name)
                .replace("{1}", code_text(t, *code));
            if family.uses_key() {
                text.push_str(" (");
                text.push_str(key_clause(t, item));
                text.push(')');
            }
            rows.push(Row {
                depth: 0,
                tone,
                text,
                detail: String::new(),
            });
        }
        Outcome::NotRun => rows.push(Row {
            depth: 0,
            tone,
            text: t.not_run.replace("{0}", &item.name),
            detail: String::new(),
        }),
    }
}

fn policy_line(
    t: &Texts,
    policy: ValidationPolicy,
    checked_at: OffsetDateTime,
    level: Option<oncl_pki::evidence::AdesLevel>,
) -> String {
    let mut line = format!(
        "{} · {}",
        match policy {
            ValidationPolicy::StrictOnline => t.policy_strict,
            ValidationPolicy::OfflineReport => t.policy_offline,
            ValidationPolicy::NcalayerCompatibility => t.policy_compat,
        },
        t.checked_at.replace("{0}", &when(checked_at))
    );
    if let Some(level) = level {
        line.push_str(" · ");
        line.push_str(&t.level.replace("{0}", level_name(level)));
    }
    line
}

fn level_name(level: oncl_pki::evidence::AdesLevel) -> &'static str {
    use oncl_pki::evidence::AdesLevel as L;
    match level {
        L::B => "B",
        L::T => "T",
        L::Lt => "LT",
        L::Lta => "LTA",
    }
}

fn verification_rows(t: &Texts, v: &VerificationView, rows: &mut Vec<Row>) {
    for (i, signer) in v.signers.iter().enumerate() {
        signer_rows(t, i, signer, rows);
    }
    for note in &v.notes {
        rows.push(Row {
            depth: 1,
            tone: note_tone(note),
            text: note_text(t, note),
            detail: String::new(),
        });
    }
    if let Some(claims) = &v.claims {
        rows.push(Row {
            depth: 1,
            tone: verdict_tone(claims.verdict),
            text: t.claims.replace("{0}", claims_word(t, claims.verdict)),
            detail: String::new(),
        });
        for failure in &claims.failures {
            rows.push(Row {
                depth: 2,
                tone: Tone::Failure,
                text: claims_failure(t, *failure).to_owned(),
                detail: String::new(),
            });
        }
    }
}

fn signer_rows(t: &Texts, index: usize, s: &SignerView, rows: &mut Vec<Row>) {
    let mut detail = Vec::new();
    if let Some(algorithm) = &s.algorithm {
        detail.push(t.algorithm.replace("{0}", algorithm));
    }
    if let Some(level) = s.level {
        detail.push(t.level.replace("{0}", level_name(level)));
    }
    if let Some(sha) = &s.certificate_sha256 {
        detail.push(format!(
            "SHA-256 {}",
            sha.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
    }
    rows.push(Row {
        depth: 1,
        tone: verdict_tone(s.verdict),
        text: t
            .signer
            .replace("{0}", &(index + 1).to_string())
            .replace("{1}", verdict_word(t, s.verdict)),
        detail: detail.join(" · "),
    });
    for (check, status) in &s.checks {
        rows.push(Row {
            depth: 2,
            tone: check_tone(*status),
            text: format!("{}: {}", check_name(t, *check), status_word(t, *status)),
            detail: String::new(),
        });
    }
    for reason in &s.reasons {
        rows.push(Row {
            depth: 2,
            tone: reason_tone(reason),
            text: reason_text(t, reason),
            detail: String::new(),
        });
    }
    rows.push(Row {
        depth: 2,
        tone: Tone::Neutral,
        text: basis_text(t, s),
        detail: String::new(),
    });
}

fn basis_text(t: &Texts, s: &SignerView) -> String {
    let basis = match s.basis {
        TimeBasis::Current(at) => t.basis_current.replace("{0}", &when(at)),
        TimeBasis::VerifiedTimestamp(at) => t.basis_timestamp.replace("{0}", &when(at)),
        TimeBasis::ClaimedSigningTime(at) => t.basis_claimed.replace("{0}", &when(at)),
    };
    match s.claimed_signing_time {
        Some(at) if !matches!(s.basis, TimeBasis::ClaimedSigningTime(_)) => {
            format!("{basis}; {}", t.claimed_time.replace("{0}", &when(at)))
        }
        _ => basis,
    }
}

fn stamp_rows(t: &Texts, s: &StampView, rows: &mut Vec<Row>) {
    rows.push(Row {
        depth: 1,
        tone: Tone::Neutral,
        text: t.stamp_time.replace("{0}", &when(s.gen_time)),
        detail: t.stamp_policy.replace("{0}", &s.tsa_policy),
    });
    let (tone, text) = match s.imprint {
        DocumentImprint::Matched => (Tone::Success, t.imprint_matched),
        DocumentImprint::Mismatched => (Tone::Failure, t.imprint_mismatched),
        DocumentImprint::NotProvided => (Tone::Caution, t.imprint_not_provided),
    };
    rows.push(Row {
        depth: 1,
        tone,
        text: text.to_owned(),
        detail: String::new(),
    });
    for (check, status) in &s.checks {
        rows.push(Row {
            depth: 2,
            tone: check_tone(*status),
            text: format!(
                "{}: {}",
                stamp_check_name(t, *check),
                status_word(t, *status)
            ),
            detail: String::new(),
        });
    }
}

fn note_tone(note: &Note) -> Tone {
    match note {
        Note::XmlReference {
            resolved,
            digest_matches,
            ..
        } => {
            if *resolved && *digest_matches {
                Tone::Success
            } else {
                Tone::Failure
            }
        }
        Note::PdfRevision { later_changes, .. } => {
            if *later_changes {
                Tone::Caution
            } else {
                Tone::Neutral
            }
        }
        Note::PdfExtent(_) => Tone::Neutral,
    }
}

fn note_text(t: &Texts, note: &Note) -> String {
    match note {
        Note::XmlReference {
            signature,
            reference,
            resolved,
            digest_matches,
        } => t
            .xml_reference
            .replace("{0}", &(signature + 1).to_string())
            .replace("{1}", &(reference + 1).to_string())
            .replace(
                "{2}",
                if !resolved {
                    t.reference_missing
                } else if *digest_matches {
                    t.reference_matches
                } else {
                    t.reference_differs
                },
            ),
        Note::PdfRevision {
            revision,
            later_changes,
            signers,
        } => t
            .pdf_revision
            .replace("{0}", &revision.to_string())
            .replace("{1}", &signers.to_string())
            .replace(
                "{2}",
                if *later_changes {
                    t.pdf_changed_after
                } else {
                    t.pdf_unchanged_after
                },
            ),
        Note::PdfExtent(bytes) => t.pdf_extent.replace("{0}", &bytes.to_string()),
    }
}

fn claims_word(t: &Texts, verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Valid => t.claims_ok,
        Verdict::Invalid => t.claims_bad,
        Verdict::Indeterminate => t.claims_unsure,
    }
}

fn claims_failure(t: &Texts, failure: ClaimsFailure) -> &'static str {
    match failure {
        ClaimsFailure::MissingExpiration => t.claim_no_exp,
        ClaimsFailure::InvalidNumericDate => t.claim_bad_date,
        ClaimsFailure::Expired => t.claim_expired,
        ClaimsFailure::NotYetValid => t.claim_not_yet,
        ClaimsFailure::Issuer => t.claim_issuer,
        ClaimsFailure::Audience => t.claim_audience,
    }
}

fn reason_tone(reason: &ValidationReason) -> Tone {
    match reason {
        ValidationReason::RevocationUnavailable
        | ValidationReason::TimestampRevocationUnavailable => Tone::Caution,
        _ => Tone::Failure,
    }
}

fn reason_text(t: &Texts, reason: &ValidationReason) -> String {
    match reason {
        ValidationReason::Signature(problem) => match problem {
            Problem::Malformed => t.p_malformed,
            Problem::NoContent => t.p_no_content,
            Problem::NoSignerCert => t.p_no_cert,
            Problem::BadSignature => t.p_bad_signature,
            Problem::DigestMismatch => t.p_digest,
            Problem::EssCertIdMismatch => t.p_ess,
            Problem::TspInvalid => t.p_tsp,
            Problem::TspImprintMismatch => t.p_tsp_imprint,
        }
        .to_owned(),
        ValidationReason::Format(f) => match f {
            oncl_pki::validation::FormatFailure::ReferenceDigestMismatch => t.p_ref_digest,
            oncl_pki::validation::FormatFailure::ReferenceTargetMissing => t.p_ref_missing,
        }
        .to_owned(),
        ValidationReason::CertificateValidity => t.r_validity.to_owned(),
        ValidationReason::UntrustedChain => t.r_chain.to_owned(),
        ValidationReason::KeyUsage => t.r_key_usage.to_owned(),
        ValidationReason::Timestamp => t.r_timestamp.to_owned(),
        ValidationReason::RevocationUnavailable => t.r_revocation_unavailable.to_owned(),
        ValidationReason::Revoked { at } => t.r_revoked.replace("{0}", &when(*at)),
        ValidationReason::RevokedAfterProvenTime { at } => {
            t.r_revoked_after.replace("{0}", &when(*at))
        }
        ValidationReason::TimestampRevocationUnavailable => {
            t.r_tsa_revocation_unavailable.to_owned()
        }
        ValidationReason::TimestampRevoked { at } => t.r_tsa_revoked.replace("{0}", &when(*at)),
        ValidationReason::TimestampRevokedAfterProof { at } => {
            t.r_tsa_revoked_after.replace("{0}", &when(*at))
        }
    }
}

fn when(t: OffsetDateTime) -> String {
    format!(
        "{:02}.{:02}.{:04} {:02}:{:02}:{:02} UTC",
        t.day(),
        u8::from(t.month()),
        t.year(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn status_word(t: &Texts, status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Passed => t.s_passed,
        CheckStatus::Failed => t.s_failed,
        CheckStatus::Unavailable => t.s_unavailable,
        CheckStatus::NotApplicable => t.s_not_applicable,
    }
}

fn check_name(t: &Texts, check: Check) -> &'static str {
    match check {
        Check::Signature => t.c_signature,
        Check::Chain => t.c_chain,
        Check::Validity => t.c_validity,
        Check::Revocation => t.c_revocation,
        Check::Timestamp => t.c_timestamp,
        Check::KeyUsage => t.c_key_usage,
    }
}

fn stamp_check_name(t: &Texts, check: StampCheck) -> &'static str {
    match check {
        StampCheck::Signature => t.c_signature,
        StampCheck::TsaUsage => t.c_tsa_usage,
        StampCheck::Chain => t.c_chain,
        StampCheck::Validity => t.c_validity,
        StampCheck::Revocation => t.c_revocation,
        StampCheck::Expectations => t.c_expectations,
    }
}

/// Why an item failed, in words that do not claim more than the engine's code.
fn code_text(t: &Texts, code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Cancelled => t.e_cancelled,
        ErrorCode::PermissionDenied => t.e_denied,
        ErrorCode::ValidationRequired | ErrorCode::MissingValidationServices => t.e_validation,
        ErrorCode::KeyFailure | ErrorCode::KeyNotFound | ErrorCode::SecretRequired => t.e_key,
        ErrorCode::Io => t.e_io,
        ErrorCode::InvalidInput | ErrorCode::UnsupportedAlgorithm => t.e_invalid,
        ErrorCode::InputLimit
        | ErrorCode::ContainerLimit
        | ErrorCode::FramingLimit
        | ErrorCode::OutputLimit
        | ErrorCode::MemoryLimit
        | ErrorCode::TempLimit
        | ErrorCode::MetadataLimit
        | ErrorCode::CapacityExceeded => t.e_limit,
        ErrorCode::DeadlineExceeded => t.e_deadline,
        ErrorCode::MissingCadesConfiguration => t.e_no_tsa,
        ErrorCode::AuditFailed => t.e_audit,
        _ => t.e_other,
    }
}

struct Texts {
    nothing: &'static str,
    /// Per family: sign, verify, extend, extract, stamp, stamp check. `{0}` count.
    all_succeeded: [&'static str; 6],
    /// `{0}` count, `{1}` what was found.
    all_completed: &'static str,
    found_invalid: &'static str,
    found_indeterminate: &'static str,
    found_unchecked: &'static str,
    /// `{0}` completed, `{1}` total.
    partial: &'static str,
    cancelled: &'static str,
    stopped: &'static str,
    key_none: &'static str,
    key_used_n: &'static str,
    key_unknown_n: &'static str,
    key_not_used: &'static str,
    key_used: &'static str,
    key_unknown: &'static str,
    verdict_valid: &'static str,
    verdict_invalid: &'static str,
    verdict_indeterminate: &'static str,
    bytes: &'static str,
    /// `{0}` name, `{1}` format, `{2}` file.
    written: &'static str,
    written_missing: &'static str,
    signers_n: &'static str,
    extracted: &'static str,
    extracted_missing: &'static str,
    stamp_acquired: &'static str,
    stamp_not_written: &'static str,
    failed: &'static str,
    not_run: &'static str,
    policy_strict: &'static str,
    policy_offline: &'static str,
    policy_compat: &'static str,
    checked_at: &'static str,
    level: &'static str,
    algorithm: &'static str,
    signer: &'static str,
    claims: &'static str,
    claims_ok: &'static str,
    claims_bad: &'static str,
    claims_unsure: &'static str,
    token_claims_failed: &'static str,
    basis_current: &'static str,
    basis_timestamp: &'static str,
    basis_claimed: &'static str,
    claimed_time: &'static str,
    stamp_time: &'static str,
    stamp_policy: &'static str,
    imprint_matched: &'static str,
    imprint_mismatched: &'static str,
    imprint_not_provided: &'static str,
    xml_reference: &'static str,
    reference_missing: &'static str,
    reference_matches: &'static str,
    reference_differs: &'static str,
    pdf_revision: &'static str,
    pdf_changed_after: &'static str,
    pdf_unchanged_after: &'static str,
    pdf_extent: &'static str,
    claim_no_exp: &'static str,
    claim_bad_date: &'static str,
    claim_expired: &'static str,
    claim_not_yet: &'static str,
    claim_issuer: &'static str,
    claim_audience: &'static str,
    p_malformed: &'static str,
    p_no_content: &'static str,
    p_no_cert: &'static str,
    p_bad_signature: &'static str,
    p_digest: &'static str,
    p_ess: &'static str,
    p_tsp: &'static str,
    p_tsp_imprint: &'static str,
    p_ref_digest: &'static str,
    p_ref_missing: &'static str,
    r_validity: &'static str,
    r_chain: &'static str,
    r_key_usage: &'static str,
    r_timestamp: &'static str,
    r_revocation_unavailable: &'static str,
    r_revoked: &'static str,
    r_revoked_after: &'static str,
    r_tsa_revocation_unavailable: &'static str,
    r_tsa_revoked: &'static str,
    r_tsa_revoked_after: &'static str,
    s_passed: &'static str,
    s_failed: &'static str,
    s_unavailable: &'static str,
    s_not_applicable: &'static str,
    c_signature: &'static str,
    c_chain: &'static str,
    c_validity: &'static str,
    c_revocation: &'static str,
    c_timestamp: &'static str,
    c_key_usage: &'static str,
    c_tsa_usage: &'static str,
    c_expectations: &'static str,
    e_cancelled: &'static str,
    e_denied: &'static str,
    e_validation: &'static str,
    e_key: &'static str,
    e_io: &'static str,
    e_invalid: &'static str,
    e_limit: &'static str,
    e_deadline: &'static str,
    e_no_tsa: &'static str,
    e_audit: &'static str,
    e_other: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Ru => &RU,
            Locale::Kk => &KK,
            Locale::En => &EN,
        }
    }
}

static RU: Texts = Texts {
    nothing: "Нечего показать.",
    all_succeeded: [
        "Подписано документов: {0}.",
        "Проверено документов: {0}; все подписи действительны.",
        "Продлено документов: {0}.",
        "Извлечено документов: {0}.",
        "Получено меток времени: {0}.",
        "Проверено меток времени: {0}; все действительны.",
    ],
    all_completed: "Выполнено для всех документов ({0}), но: {1}.",
    found_invalid: "недействительных: {0}",
    found_indeterminate: "не удалось полностью проверить: {0}",
    found_unchecked: "только извлечено, подпись не проверялась: {0}",
    partial: "Выполнено только для {0} из {1}. Остальные не выполнены.",
    cancelled: "Остановлено: выполнено {0} из {1}. Остальные не выполнялись.",
    stopped: "Пакет остановлен ошибкой: выполнено {0} из {1}.",
    key_none: "Ключ не применялся.",
    key_used_n: "Ключ применён для документов: {0}.",
    key_unknown_n: "Для документов ({0}) неизвестно, применялся ли ключ: проверьте результат.",
    key_not_used: "ключ не применялся",
    key_used: "ключ был применён",
    key_unknown: "применён ли ключ, неизвестно",
    verdict_valid: "подпись действительна",
    verdict_invalid: "подпись недействительна",
    verdict_indeterminate: "не удалось полностью проверить: это не подтверждение действительности",
    bytes: "{0} байт",
    written: "{0}: создано ({1}) → {2}",
    written_missing: "{0}: подпись ({1}) создана, но файл не записан",
    signers_n: "подписантов: {0}",
    extracted: "{0}: содержимое извлечено → {1}. Подпись не проверялась.",
    extracted_missing: "{0}: содержимое не записано",
    stamp_acquired: "{0}: метка времени получена ({1}) → {2}",
    stamp_not_written: "{0}: метка времени получена, но файл не записан",
    failed: "{0}: не выполнено — {1}",
    not_run: "{0}: не выполнялось",
    policy_strict: "строгая проверка с сетью",
    policy_offline: "без сети: отзыв не запрашивался",
    policy_compat: "режим совместимости с NCALayer",
    checked_at: "проверено {0}",
    level: "уровень {0}",
    algorithm: "алгоритм {0}",
    signer: "Подписант {0}: {1}",
    claims: "Утверждения JWT: {0}",
    claims_ok: "выполняются",
    claims_bad: "не выполняются",
    claims_unsure: "не удалось полностью проверить",
    token_claims_failed: "{0}: подпись действительна, но утверждения токена не выполняются",
    basis_current: "время проверки: сейчас ({0})",
    basis_timestamp: "время: по подтверждённой метке ({0})",
    basis_claimed: "время: только заявленное подписантом ({0}), не доказано",
    claimed_time: "заявленное время подписи {0}",
    stamp_time: "Время метки: {0}",
    stamp_policy: "политика TSA {0}",
    imprint_matched: "Метка относится к этим данным.",
    imprint_mismatched: "Метка относится к другим данным.",
    imprint_not_provided: "Данные не заданы: связь метки с документом не проверена.",
    xml_reference: "Подпись {0}, ссылка {1}: {2}",
    reference_missing: "цель ссылки не найдена",
    reference_matches: "дайджест совпадает",
    reference_differs: "дайджест не совпадает",
    pdf_revision: "Редакция {0} ({1} подп.): {2}",
    pdf_changed_after: "после подписи файл изменялся",
    pdf_unchanged_after: "после подписи файл не изменялся",
    pdf_extent: "Размер PDF: {0} байт",
    claim_no_exp: "нет срока действия (exp)",
    claim_bad_date: "дата в утверждениях неверна",
    claim_expired: "срок токена истёк",
    claim_not_yet: "токен ещё не действует",
    claim_issuer: "издатель не тот, что ожидался",
    claim_audience: "адресат не тот, что ожидался",
    p_malformed: "подписант или атрибут нечитаем",
    p_no_content: "нет данных, к которым относится подпись (откреплённая подпись без файла)",
    p_no_cert: "в подписи нет сертификата подписанта",
    p_bad_signature: "подпись не совпадает с данными",
    p_digest: "дайджест данных не совпадает с подписанным",
    p_ess: "сертификат не тот, что указан в подписи",
    p_tsp: "метка времени не проходит проверку",
    p_tsp_imprint: "метка времени относится к другой подписи",
    p_ref_digest: "ссылка: дайджест не совпадает",
    p_ref_missing: "ссылка: цель не найдена",
    r_validity: "срок действия сертификата не позволяет принять подпись",
    r_chain: "сертификат не связан с доверенным корнем",
    r_key_usage: "сертификат не предназначен для подписи",
    r_timestamp: "метка времени не принята",
    r_revocation_unavailable: "статус отзыва сертификата получить не удалось",
    r_revoked: "сертификат отозван {0}",
    r_revoked_after: "сертификат отозван {0}, уже после доказанного времени подписи",
    r_tsa_revocation_unavailable: "статус отзыва сертификата службы времени получить не удалось",
    r_tsa_revoked: "сертификат службы времени отозван {0}",
    r_tsa_revoked_after: "сертификат службы времени отозван {0}, уже после метки",
    s_passed: "пройдена",
    s_failed: "не пройдена",
    s_unavailable: "не удалось проверить",
    s_not_applicable: "не применимо",
    c_signature: "Подпись",
    c_chain: "Цепочка сертификатов",
    c_validity: "Срок действия",
    c_revocation: "Отзыв",
    c_timestamp: "Метка времени",
    c_key_usage: "Назначение ключа",
    c_tsa_usage: "Назначение службы времени",
    c_expectations: "Ожидания (алгоритм, политика, возраст)",
    e_cancelled: "отменено",
    e_denied: "действие не разрешено",
    e_validation: "сертификат не прошёл проверку (цепочка, срок или отзыв)",
    e_key: "ключ недоступен",
    e_io: "файл не удалось прочитать или записать",
    e_invalid: "файл не распознан или не подходит для этого действия",
    e_limit: "превышены допустимые пределы",
    e_deadline: "время операции истекло",
    e_no_tsa: "уровни T, LT и LTA недоступны: служба меток времени не настроена",
    e_audit: "запись аудита не удалась",
    e_other: "выполнить не удалось",
};

static KK: Texts = Texts {
    nothing: "Көрсетерлік ештеңе жоқ.",
    all_succeeded: [
        "Қол қойылған құжаттар: {0}.",
        "Тексерілген құжаттар: {0}; барлық қолтаңбалар жарамды.",
        "Ұзартылған құжаттар: {0}.",
        "Шығарылған құжаттар: {0}.",
        "Алынған уақыт белгілері: {0}.",
        "Тексерілген уақыт белгілері: {0}; барлығы жарамды.",
    ],
    all_completed: "Барлық құжат ({0}) үшін орындалды, бірақ: {1}.",
    found_invalid: "жарамсыз: {0}",
    found_indeterminate: "толық тексеру мүмкін болмады: {0}",
    found_unchecked: "тек шығарылды, қолтаңба тексерілмеді: {0}",
    partial: "Тек {1} ішінен {0} үшін орындалды. Қалғандары орындалмады.",
    cancelled: "Тоқтатылды: {1} ішінен {0} орындалды. Қалғандары орындалмады.",
    stopped: "Пакет қатемен тоқтатылды: {1} ішінен {0} орындалды.",
    key_none: "Кілт қолданылмады.",
    key_used_n: "Кілт құжаттарға қолданылды: {0}.",
    key_unknown_n: "Құжаттар ({0}) үшін кілттің қолданылғаны белгісіз: нәтижені тексеріңіз.",
    key_not_used: "кілт қолданылмады",
    key_used: "кілт қолданылды",
    key_unknown: "кілттің қолданылғаны белгісіз",
    verdict_valid: "қолтаңба жарамды",
    verdict_invalid: "қолтаңба жарамсыз",
    verdict_indeterminate: "толық тексеру мүмкін болмады: бұл жарамдылықтың расталуы емес",
    bytes: "{0} байт",
    written: "{0}: жасалды ({1}) → {2}",
    written_missing: "{0}: қолтаңба ({1}) жасалды, бірақ файл жазылмады",
    signers_n: "қол қоюшылар: {0}",
    extracted: "{0}: мазмұны шығарылды → {1}. Қолтаңба тексерілмеді.",
    extracted_missing: "{0}: мазмұны жазылмады",
    stamp_acquired: "{0}: уақыт белгісі алынды ({1}) → {2}",
    stamp_not_written: "{0}: уақыт белгісі алынды, бірақ файл жазылмады",
    failed: "{0}: орындалмады — {1}",
    not_run: "{0}: орындалмады",
    policy_strict: "желімен қатаң тексеру",
    policy_offline: "желісіз: күшін жою сұралмады",
    policy_compat: "NCALayer үйлесімділік режимі",
    checked_at: "тексерілді {0}",
    level: "деңгей {0}",
    algorithm: "алгоритм {0}",
    signer: "Қол қоюшы {0}: {1}",
    claims: "JWT мәлімдемелері: {0}",
    claims_ok: "орындалады",
    claims_bad: "орындалмайды",
    claims_unsure: "толық тексеру мүмкін болмады",
    token_claims_failed: "{0}: қолтаңба жарамды, бірақ токен мәлімдемелері орындалмайды",
    basis_current: "тексеру уақыты: қазір ({0})",
    basis_timestamp: "уақыты: расталған белгі бойынша ({0})",
    basis_claimed: "уақыты: тек қол қоюшы мәлімдеген ({0}), дәлелденбеген",
    claimed_time: "мәлімделген қол қою уақыты {0}",
    stamp_time: "Белгі уақыты: {0}",
    stamp_policy: "TSA саясаты {0}",
    imprint_matched: "Белгі осы деректерге қатысты.",
    imprint_mismatched: "Белгі басқа деректерге қатысты.",
    imprint_not_provided: "Деректер берілмеген: белгінің құжатпен байланысы тексерілмеді.",
    xml_reference: "Қолтаңба {0}, сілтеме {1}: {2}",
    reference_missing: "сілтеме нысаны табылмады",
    reference_matches: "дайджест сәйкес",
    reference_differs: "дайджест сәйкес емес",
    pdf_revision: "Түзету {0} ({1} қолт.): {2}",
    pdf_changed_after: "қол қойылғаннан кейін файл өзгерген",
    pdf_unchanged_after: "қол қойылғаннан кейін файл өзгермеген",
    pdf_extent: "PDF өлшемі: {0} байт",
    claim_no_exp: "жарамдылық мерзімі (exp) жоқ",
    claim_bad_date: "мәлімдемелердегі күн қате",
    claim_expired: "токен мерзімі өткен",
    claim_not_yet: "токен әлі жарамды емес",
    claim_issuer: "шығарушы күткендей емес",
    claim_audience: "алушы күткендей емес",
    p_malformed: "қол қоюшы немесе атрибут оқылмайды",
    p_no_content: "қолтаңба қатысты деректер жоқ (файлсыз бөлек қолтаңба)",
    p_no_cert: "қолтаңбада қол қоюшы сертификаты жоқ",
    p_bad_signature: "қолтаңба деректерге сәйкес емес",
    p_digest: "деректер дайджесті қол қойылғанмен сәйкес емес",
    p_ess: "сертификат қолтаңбада көрсетілгенмен бірдей емес",
    p_tsp: "уақыт белгісі тексеруден өтпейді",
    p_tsp_imprint: "уақыт белгісі басқа қолтаңбаға қатысты",
    p_ref_digest: "сілтеме: дайджест сәйкес емес",
    p_ref_missing: "сілтеме: нысан табылмады",
    r_validity: "сертификат мерзімі қолтаңбаны қабылдауға мүмкіндік бермейді",
    r_chain: "сертификат сенімді түбірмен байланыспаған",
    r_key_usage: "сертификат қол қоюға арналмаған",
    r_timestamp: "уақыт белгісі қабылданбады",
    r_revocation_unavailable: "сертификаттың күшін жою күйін алу мүмкін болмады",
    r_revoked: "сертификаттың күші жойылған {0}",
    r_revoked_after: "сертификаттың күші {0} жойылған, дәлелденген қол қою уақытынан кейін",
    r_tsa_revocation_unavailable: "уақыт қызметі сертификатының күшін жою күйін алу мүмкін болмады",
    r_tsa_revoked: "уақыт қызметі сертификатының күші жойылған {0}",
    r_tsa_revoked_after: "уақыт қызметі сертификатының күші {0} жойылған, белгіден кейін",
    s_passed: "өтті",
    s_failed: "өтпеді",
    s_unavailable: "тексеру мүмкін болмады",
    s_not_applicable: "қолданылмайды",
    c_signature: "Қолтаңба",
    c_chain: "Сертификат тізбегі",
    c_validity: "Жарамдылық мерзімі",
    c_revocation: "Күшін жою",
    c_timestamp: "Уақыт белгісі",
    c_key_usage: "Кілт мақсаты",
    c_tsa_usage: "Уақыт қызметінің мақсаты",
    c_expectations: "Күтулер (алгоритм, саясат, жас)",
    e_cancelled: "тоқтатылды",
    e_denied: "әрекетке рұқсат жоқ",
    e_validation: "сертификат тексеруден өтпеді (тізбек, мерзім немесе күшін жою)",
    e_key: "кілт қолжетімсіз",
    e_io: "файлды оқу немесе жазу мүмкін болмады",
    e_invalid: "файл танылмады немесе бұл әрекетке жарамсыз",
    e_limit: "рұқсат етілген шектен асты",
    e_deadline: "операция уақыты аяқталды",
    e_no_tsa: "T, LT және LTA деңгейлері қолжетімсіз: уақыт белгісі қызметі бапталмаған",
    e_audit: "аудит жазбасы жасалмады",
    e_other: "орындау мүмкін болмады",
};

static EN: Texts = Texts {
    nothing: "Nothing to show.",
    all_succeeded: [
        "Signed documents: {0}.",
        "Checked documents: {0}; every signature is valid.",
        "Extended documents: {0}.",
        "Extracted documents: {0}.",
        "Timestamps obtained: {0}.",
        "Timestamps checked: {0}; all are valid.",
    ],
    all_completed: "Done for every document ({0}), but: {1}.",
    found_invalid: "invalid: {0}",
    found_indeterminate: "could not be fully checked: {0}",
    found_unchecked: "only extracted, the signature was not checked: {0}",
    partial: "Done for only {0} of {1}. The rest were not done.",
    cancelled: "Stopped: {0} of {1} done. The rest were not run.",
    stopped: "The batch was stopped by an error: {0} of {1} done.",
    key_none: "No key was used.",
    key_used_n: "The key was applied for {0} document(s).",
    key_unknown_n: "For {0} document(s) it is not known whether the key was applied: check the results.",
    key_not_used: "the key was not used",
    key_used: "the key was applied",
    key_unknown: "whether the key was applied is unknown",
    verdict_valid: "the signature is valid",
    verdict_invalid: "the signature is invalid",
    verdict_indeterminate: "could not be fully checked: this does not confirm validity",
    bytes: "{0} bytes",
    written: "{0}: made ({1}) → {2}",
    written_missing: "{0}: the signature ({1}) was made but the file was not written",
    signers_n: "signers: {0}",
    extracted: "{0}: content extracted → {1}. The signature was not checked.",
    extracted_missing: "{0}: the content was not written",
    stamp_acquired: "{0}: timestamp obtained ({1}) → {2}",
    stamp_not_written: "{0}: timestamp obtained but the file was not written",
    failed: "{0}: not done — {1}",
    not_run: "{0}: not run",
    policy_strict: "strict check with the network",
    policy_offline: "offline: revocation was not asked for",
    policy_compat: "NCALayer compatibility mode",
    checked_at: "checked {0}",
    level: "level {0}",
    algorithm: "algorithm {0}",
    signer: "Signer {0}: {1}",
    claims: "JWT claims: {0}",
    claims_ok: "hold",
    claims_bad: "do not hold",
    claims_unsure: "could not be fully checked",
    token_claims_failed: "{0}: the signature is valid, but the token's claims do not hold",
    basis_current: "time of the check: now ({0})",
    basis_timestamp: "time: by a verified timestamp ({0})",
    basis_claimed: "time: only as claimed by the signer ({0}), not proven",
    claimed_time: "claimed signing time {0}",
    stamp_time: "Timestamp time: {0}",
    stamp_policy: "TSA policy {0}",
    imprint_matched: "The timestamp is of this data.",
    imprint_mismatched: "The timestamp is of other data.",
    imprint_not_provided: "No data was given: the timestamp's tie to a document was not checked.",
    xml_reference: "Signature {0}, reference {1}: {2}",
    reference_missing: "the reference target was not found",
    reference_matches: "digest matches",
    reference_differs: "digest does not match",
    pdf_revision: "Revision {0} ({1} signature(s)): {2}",
    pdf_changed_after: "the file was changed after signing",
    pdf_unchanged_after: "the file was not changed after signing",
    pdf_extent: "PDF size: {0} bytes",
    claim_no_exp: "no expiration (exp)",
    claim_bad_date: "a date in the claims is invalid",
    claim_expired: "the token has expired",
    claim_not_yet: "the token is not valid yet",
    claim_issuer: "the issuer is not the expected one",
    claim_audience: "the audience is not the expected one",
    p_malformed: "a signer or an attribute is unreadable",
    p_no_content: "no data the signature is of (a detached signature without its file)",
    p_no_cert: "the signature has no signer certificate",
    p_bad_signature: "the signature does not match the data",
    p_digest: "the digest of the data differs from the signed one",
    p_ess: "the certificate is not the one the signature names",
    p_tsp: "the timestamp does not verify",
    p_tsp_imprint: "the timestamp is of another signature",
    p_ref_digest: "reference: the digest does not match",
    p_ref_missing: "reference: the target was not found",
    r_validity: "the certificate's validity period does not allow the signature",
    r_chain: "the certificate does not chain to a trusted root",
    r_key_usage: "the certificate is not meant for signing",
    r_timestamp: "the timestamp was not accepted",
    r_revocation_unavailable: "the certificate's revocation status could not be obtained",
    r_revoked: "the certificate was revoked {0}",
    r_revoked_after: "the certificate was revoked {0}, after the proven signing time",
    r_tsa_revocation_unavailable: "the revocation status of the time service's certificate could not be obtained",
    r_tsa_revoked: "the time service's certificate was revoked {0}",
    r_tsa_revoked_after: "the time service's certificate was revoked {0}, after the timestamp",
    s_passed: "passed",
    s_failed: "failed",
    s_unavailable: "could not be checked",
    s_not_applicable: "not applicable",
    c_signature: "Signature",
    c_chain: "Certificate chain",
    c_validity: "Validity period",
    c_revocation: "Revocation",
    c_timestamp: "Timestamp",
    c_key_usage: "Key usage",
    c_tsa_usage: "Time service usage",
    c_expectations: "Expectations (algorithm, policy, age)",
    e_cancelled: "cancelled",
    e_denied: "the action is not allowed",
    e_validation: "the certificate failed its checks (chain, validity or revocation)",
    e_key: "the key is not available",
    e_io: "the file could not be read or written",
    e_invalid: "the file is not recognised or does not fit this action",
    e_limit: "over the permitted limits",
    e_deadline: "the operation timed out",
    e_no_tsa: "levels T, LT and LTA are unavailable: no time stamp service is configured",
    e_audit: "the audit record could not be written",
    e_other: "it could not be done",
};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use oncl_pki::key::AppliedState;

    use super::controller::*;
    use super::*;

    const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;
    const LOCALES: [Locale; 3] = [Locale::Ru, Locale::Kk, Locale::En];

    fn signer(verdict: Verdict, revocation: CheckStatus) -> SignerView {
        SignerView {
            verdict,
            checks: vec![
                (Check::Signature, CheckStatus::Passed),
                (Check::Revocation, revocation),
            ],
            reasons: if revocation == CheckStatus::Unavailable {
                vec![ValidationReason::RevocationUnavailable]
            } else {
                Vec::new()
            },
            level: None,
            claimed_signing_time: None,
            basis: TimeBasis::Current(NOW),
            algorithm: None,
            certificate_sha256: None,
        }
    }

    fn verified(verdict: Verdict, revocation: CheckStatus) -> ItemView {
        ItemView {
            name: "a.p7s".into(),
            outcome: Outcome::Completed(Detail::Verified(VerificationView {
                verdict,
                policy: ValidationPolicy::OfflineReport,
                checked_at: NOW,
                level: None,
                signers: vec![signer(verdict, revocation)],
                notes: Vec::new(),
                claims: None,
            })),
            applied: AppliedState::NotApplied,
            output: None,
        }
    }

    fn batch(items: Vec<ItemView>) -> BatchView {
        BatchView {
            family: Family::Verify,
            items,
            stop: None,
        }
    }

    /// The page's banner and rows carry the controller's tones: a report whose only signer
    /// could not be fully checked is not styled as success anywhere, and says why.
    #[test]
    fn an_indeterminate_report_is_not_styled_as_success_anywhere() {
        let view = batch(vec![verified(
            Verdict::Indeterminate,
            CheckStatus::Unavailable,
        )]);
        for locale in LOCALES {
            let r = render(locale, &view);
            assert_ne!(r.tone, Tone::Success, "{locale:?}: {}", r.headline);
            assert!(
                r.rows
                    .iter()
                    .all(|row| row.tone != Tone::Success || row.text.contains(':')),
                "{r:?}"
            );
            // The item row and the signer row are cautions; the unavailable check is a
            // caution; the reason is told.
            let cautions = r
                .rows
                .iter()
                .filter(|row| row.tone == Tone::Caution)
                .count();
            assert!(cautions >= 4, "{locale:?}: {r:?}");
            assert!(r.rows.iter().all(|row| !row.text.is_empty()));
        }
    }

    #[test]
    fn a_valid_report_is_success_and_names_every_check() {
        let view = batch(vec![verified(Verdict::Valid, CheckStatus::Passed)]);
        let r = render(Locale::En, &view);
        assert_eq!(r.tone, Tone::Success);
        assert!(
            r.headline.contains("every signature is valid"),
            "{}",
            r.headline
        );
        let item = &r.rows[0];
        assert_eq!((item.depth, item.tone), (0, Tone::Success));
        assert!(
            r.rows
                .iter()
                .any(|row| row.text == "Revocation: passed" && row.depth == 2)
        );
    }

    /// A partial sign batch says how far it got and what the key did, never «all signed».
    #[test]
    fn a_partial_sign_batch_says_what_the_key_did() {
        let written = ItemView {
            name: "a".into(),
            outcome: Outcome::Completed(Detail::Written {
                profile: "CMS".into(),
                signers: 1,
                bytes_out: 5,
                check: None,
            }),
            applied: AppliedState::Applied,
            output: Some(PathBuf::from("a.p7s")),
        };
        let failed = ItemView {
            name: "b".into(),
            outcome: Outcome::Failed(ErrorCode::Io),
            applied: AppliedState::Unknown,
            output: None,
        };
        let view = BatchView {
            family: Family::Sign,
            items: vec![written, failed],
            stop: None,
        };
        let r = render(Locale::En, &view);
        assert_eq!(r.tone, Tone::Caution);
        assert!(
            r.headline.starts_with("Done for only 1 of 2"),
            "{}",
            r.headline
        );
        assert!(
            r.headline.contains("not known whether the key was applied"),
            "{}",
            r.headline
        );
        assert!(
            r.rows
                .iter()
                .any(|row| row.text.contains("whether the key was applied is unknown")),
            "{r:?}"
        );
        for locale in LOCALES {
            let r = render(locale, &view);
            assert_ne!(r.tone, Tone::Success);
        }
    }

    /// An extraction never reads as a verification.
    #[test]
    fn an_extraction_says_the_signature_was_not_checked() {
        let view = BatchView {
            family: Family::Extract,
            items: vec![ItemView {
                name: "a.p7s".into(),
                outcome: Outcome::Completed(Detail::Extracted { bytes: 4 }),
                applied: AppliedState::NotApplied,
                output: Some(PathBuf::from("a")),
            }],
            stop: None,
        };
        for (locale, word) in [
            (Locale::En, "not checked"),
            (Locale::Ru, "не проверялась"),
            (Locale::Kk, "тексерілмеді"),
        ] {
            let r = render(locale, &view);
            assert_eq!(r.tone, Tone::Neutral);
            assert!(r.rows[0].text.contains(word), "{locale:?}: {r:?}");
        }
    }
}
