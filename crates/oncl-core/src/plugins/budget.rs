//! What a plugin call reserves from the engine's budgets, and the limits a desktop's manual
//! window runs plugins with ([`ManualLimits`]).
//!
//! A call of a plugin operation reserves, before the module runs: `8 * max_transfer +
//! max_memory` of the memory budget and `max_transfer` of the metadata budget
//! ([`call_scratch`]); every key import then admits its arguments (`128` bytes of metadata for
//! each byte, [`host_call_metadata`]); and the legacy XML signatures and XAdES check their own
//! output after the key was used, which takes the metadata the check of a signed document
//! needs ([`oncl_xml::verification_metadata_bound`]). An engine whose budgets cannot hold
//! all of that fails the call: before the key for the first two, **after** it for the check.
//! [`manual_call_budget`] is the sum, and [`Engine::plugin_prepare`] refuses a call whose sum
//! does not fit, before the user is asked and before any key is opened
//! ([`PluginPrepareError::ResourceBudget`]).
//!
//! Measured on the real ports (`docs/dev/plugins-manual-tests.md`, "Лимиты рабочего стола"):
//! at 16 MiB of document the attached CMS of `rating1c` takes about 194 MiB of guest memory
//! (12.1 bytes per document byte) and replies with 4/3 of the document, and a Kalkan XML
//! signature takes 62 MiB of metadata whatever the document.

use oncl_pki::resource::ProcessingError;
use oncl_plugin::InstanceLimits;
use oncl_plugin::operations::KeyKind;

/// What the argument of a key import costs in metadata, per byte (`Backend::call_import`).
const HOST_CALL_METADATA_PER_BYTE: u64 = 128;
/// What every key import costs in metadata besides its arguments.
const HOST_CALL_METADATA_BASE: u64 = 65_536;
/// What a key import's arguments hold besides the document: the handle and the options
/// (measured: 0.4 KiB for XML, none for CMS); this is a bound.
const ARGS_SLACK: u64 = 4 * 1024;
/// What the CMS and raw signatures admit besides their arguments: the work on the
/// certificates and attributes, whatever the document (measured: 2.2 MB); this is a bound.
const SIGN_WORK: u64 = 4 * 1024 * 1024;
/// Memory a call reserves besides the scratch and the metadata (CMS: 4.4 MiB, measured).
const MEMORY_SLACK: u64 = 8 * 1024 * 1024;

/// The memory a call of a plugin with `limits` reserves before its module runs: the
/// transfer buffers (`8 * max_transfer`) and the module's linear memory.
pub(super) fn call_scratch(limits: &InstanceLimits) -> Result<u64, ProcessingError> {
    (limits.max_transfer as u64)
        .checked_mul(8)
        .and_then(|n| n.checked_add(limits.max_memory as u64))
        .ok_or(ProcessingError::MemoryLimit)
}

/// The metadata the admission of a key import's `args_len` bytes of arguments reserves.
pub(super) fn host_call_metadata(args_len: u64) -> Result<u64, ProcessingError> {
    args_len
        .checked_mul(HOST_CALL_METADATA_PER_BYTE)
        .and_then(|n| n.checked_add(HOST_CALL_METADATA_BASE))
        .ok_or(ProcessingError::MemoryLimit)
}

/// What a call needs of the engine's budgets at its peak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallBudget {
    /// The memory budget: the scratch, the metadata (which counts as memory too) and a margin.
    pub memory: u64,
    /// The metadata budget.
    pub metadata: u64,
}

impl CallBudget {
    /// The part of the memory budget that is not metadata, for reserving the two apart.
    pub(super) fn direct_memory(&self) -> u64 {
        self.memory - self.metadata
    }
}

/// Whether the legacy XML signatures and XAdES check their own output after the key use.
pub(super) fn checks_own_output(kind: KeyKind) -> bool {
    matches!(kind, KeyKind::Xml | KeyKind::XmlEx | KeyKind::Xades)
}

/// What a call of an operation whose key use is `kind`, of a module with `limits`, over
/// `content_len` bytes of the bound document, reserves at its peak: a bound a little above
/// what the real ports reach, which a host sizes its budgets by (see [`ManualLimits`]) and
/// [`Engine::plugin_prepare`] checks before it lets a key be used.
///
/// # Errors
///
/// `MemoryLimit` if the sum overflows; `InvalidLimits` for XML limits the check would refuse.
pub fn manual_call_budget(
    limits: &InstanceLimits,
    kind: KeyKind,
    content_len: u64,
) -> Result<CallBudget, ProcessingError> {
    let args = content_len
        .checked_add(ARGS_SLACK)
        .ok_or(ProcessingError::MemoryLimit)?;
    let mut metadata = (limits.max_transfer as u64)
        .checked_add(host_call_metadata(args)?)
        .ok_or(ProcessingError::MemoryLimit)?;
    let work = if checks_own_output(kind) {
        oncl_xml::verification_metadata_bound(&oncl_xml::XmlVerifyProfile::default())?
    } else {
        SIGN_WORK
    };
    metadata = metadata
        .checked_add(work)
        .ok_or(ProcessingError::MemoryLimit)?;
    let memory = call_scratch(limits)?
        .checked_add(MEMORY_SLACK)
        .and_then(|n| n.checked_add(metadata))
        .ok_or(ProcessingError::MemoryLimit)?;
    Ok(CallBudget { memory, metadata })
}

/// The limits a desktop's manual window runs plugins with: the instance limits of every
/// plugin it registers and the resource limits of the engine the calls run on. The SDK's
/// defaults stay what they are (conservative, for a library); this is the host's own choice,
/// the one definition the window (`openncalayer`) and the port tests
/// (`docs/dev/plugins-manual-tests.md`) share.
///
/// They are sized for documents of up to [`ManualLimits::max_document`] bytes, which the
/// desktop caps below the 16 MiB a manifest's `max_bytes` may say: a plugin holds the whole
/// document in its linear memory several times over and the core admits every key import at
/// 128 bytes of metadata per byte, so the size of the document is what the memory of the
/// program is spent on. [`Engine::plugin_prepare`] refuses a larger document before the user
/// is asked ([`PluginPrepareError::ResourceBudget`]). [`ManualLimits::for_max_document`]
/// derives everything else from it:
///
/// * `max_transfer`: the document as base64 (the request, and the reply of the attached CMS)
///   and the template, times 1.5, in whole MiB;
/// * `max_memory`: the guest's linear memory, measured at up to 12.1 bytes per byte of
///   document and 3 MiB (13 and 4 MiB as a bound), times 2, in whole MiB, at most what the
///   target allows ([`oncl_plugin::MAX_MEMORY`]: 16 MiB on 32-bit);
/// * `metadata_bytes`, `memory_bytes`: [`manual_call_budget`] of the largest XML call, times
///   1.1, in whole 64 MiB. Budgets count what is reserved, not what is allocated.
#[derive(Clone, Debug)]
pub struct ManualLimits {
    /// The limits every plugin is registered with ([`crate::plugins::PluginRegistry::install`]).
    pub instance: InstanceLimits,
    /// The limits of the engine the calls run on, `operation_timeout` included: the
    /// engine's default (5 minutes), which a host that waits for the user inside the
    /// operation (the consent) lengthens.
    pub resources: oncl_pki::resource::ResourceLimits,
    /// The largest document these limits are sized for.
    pub max_document: u64,
}

/// The largest document of the desktop's manual window on a 64-bit target.
pub const DESKTOP_MAX_DOCUMENT: u64 = 4 << 20;
/// The largest document of the desktop's manual window on a 32-bit target, where a plugin's
/// linear memory is at most [`oncl_plugin::MAX_MEMORY`] (16 MiB).
pub const DESKTOP_MAX_DOCUMENT_32: u64 = 512 << 10;

impl ManualLimits {
    /// The limits of this platform's desktop.
    pub fn desktop() -> Self {
        if cfg!(target_pointer_width = "64") {
            Self::wide()
        } else {
            Self::narrow()
        }
    }

    /// 64-bit: [`DESKTOP_MAX_DOCUMENT`].
    pub(super) fn wide() -> Self {
        Self::for_max_document(DESKTOP_MAX_DOCUMENT, 1 << 30)
    }

    /// 32-bit: [`DESKTOP_MAX_DOCUMENT_32`], the linear memory at most 16 MiB.
    pub(super) fn narrow() -> Self {
        Self::for_max_document(DESKTOP_MAX_DOCUMENT_32, 16 << 20)
    }

    /// The limits sized for documents of up to `max_document` bytes, a plugin's linear memory
    /// at most `memory_cap` bytes (see the type's documentation for the rules).
    pub fn for_max_document(max_document: u64, memory_cap: usize) -> Self {
        const MIB: u64 = 1 << 20;
        let round = |n: u64, unit: u64| n.div_ceil(unit) * unit;
        let transfer = round((max_document.div_ceil(3) * 4 + 16 * 1024) * 3 / 2, MIB);
        let memory = round(2 * (13 * max_document + 4 * MIB), MIB).min(memory_cap as u64);
        let instance = InstanceLimits {
            max_memory: memory as usize,
            max_transfer: transfer as usize,
            ..InstanceLimits::default()
        };
        let need = manual_call_budget(&instance, KeyKind::XmlEx, max_document)
            .expect("the limits of a document fit u64");
        ManualLimits {
            instance,
            resources: oncl_pki::resource::ResourceLimits {
                metadata_bytes: round(need.metadata / 10 * 11, 64 * MIB),
                memory_bytes: round(need.memory / 10 * 11, 64 * MIB),
                ..oncl_pki::resource::ResourceLimits::default()
            },
            max_document,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [KeyKind; 6] = [
        KeyKind::Raw,
        KeyKind::Cms,
        KeyKind::CmsEx,
        KeyKind::Xml,
        KeyKind::XmlEx,
        KeyKind::Xades,
    ];

    /// The limits of both widths hold a call over the largest document of every kind, and
    /// not one more byte of document than the transfer buffer holds.
    #[test]
    fn the_desktop_limits_admit_the_largest_document_of_every_kind() {
        for limits in [ManualLimits::wide(), ManualLimits::narrow()] {
            for kind in KINDS {
                let need = manual_call_budget(&limits.instance, kind, limits.max_document).unwrap();
                assert!(
                    need.metadata <= limits.resources.metadata_bytes,
                    "{kind:?}: {need:?} vs {:?}",
                    limits.resources
                );
                assert!(
                    need.memory <= limits.resources.memory_bytes,
                    "{kind:?}: {need:?} vs {:?}",
                    limits.resources
                );
            }
            // The request holds the document as base64 and the reply as base64 again.
            assert!(
                limits.instance.max_transfer as u64 >= limits.max_document.div_ceil(3) * 4 + 16_384,
                "{limits:?}"
            );
        }
    }

    /// The chosen values (docs/dev/plugins-manual-tests.md, the trade-off table): the
    /// accounting caps of the 64-bit desktop stay under the 1 GiB control-process budget.
    #[test]
    fn the_desktop_budgets_stay_under_the_control_process_budget() {
        const MIB: u64 = 1 << 20;
        let wide = ManualLimits::wide();
        assert_eq!(wide.max_document, 4 * MIB);
        assert_eq!(wide.instance.max_transfer as u64, 9 * MIB);
        assert_eq!(wide.instance.max_memory as u64, 112 * MIB);
        assert_eq!(wide.resources.metadata_bytes, 704 * MIB);
        assert_eq!(wide.resources.memory_bytes, 896 * MIB);
        assert!(wide.resources.memory_bytes < 1 << 30);
        let narrow = ManualLimits::narrow();
        assert_eq!(narrow.max_document, 512 << 10);
        assert_eq!(narrow.instance.max_memory as u64, 16 * MIB);
        assert!(narrow.resources.memory_bytes <= 256 * MIB, "{narrow:?}");
    }

    /// The narrow limits are what a 32-bit target can install, and the limits of this target
    /// can be installed.
    #[test]
    fn the_narrow_limits_fit_what_a_32_bit_target_allows() {
        let limits = ManualLimits::desktop().instance;
        assert!(limits.max_memory <= oncl_plugin::MAX_MEMORY);
        assert!(limits.max_transfer <= oncl_plugin::MAX_TRANSFER);
        assert!(ManualLimits::narrow().instance.max_memory <= 16 << 20);
        assert!(ManualLimits::wide().instance.max_memory <= 1 << 30);
    }

    /// The measured bound for the XML signature (62 MiB at any document), and the sum of
    /// the parts of a CMS call, are what the tests and the docs say.
    #[test]
    fn the_budget_is_the_sum_of_its_parts() {
        let limits = InstanceLimits {
            max_memory: 1 << 20,
            max_transfer: 1 << 16,
            ..InstanceLimits::default()
        };
        let cms = manual_call_budget(&limits, KeyKind::CmsEx, 1000).unwrap();
        assert_eq!(
            cms.metadata,
            (1 << 16) + host_call_metadata(1000 + ARGS_SLACK).unwrap() + SIGN_WORK
        );
        assert_eq!(
            cms.memory,
            call_scratch(&limits).unwrap() + MEMORY_SLACK + cms.metadata
        );
        let xml = manual_call_budget(&limits, KeyKind::XmlEx, 1000).unwrap();
        let bound =
            oncl_xml::verification_metadata_bound(&oncl_xml::XmlVerifyProfile::default()).unwrap();
        assert_eq!(xml.metadata, cms.metadata - SIGN_WORK + bound);
        assert!(
            (60 << 20..70 << 20).contains(&bound),
            "the Kalkan signature measured 62 MiB: {bound}"
        );
        assert_eq!(xml.direct_memory(), cms.direct_memory());
    }
}
