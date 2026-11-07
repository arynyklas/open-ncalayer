use crate::{
    args::{SignArgs, SignProfile as P, evidence_limits},
    local::Input,
    secrets,
};
use oncl_core::{
    Action, Engine, OperationContext, OperationError, SignRequest,
    keys::{
        KeyId, KeyRequest, KeySelector, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
    },
};
use oncl_pki::{evidence::AdesLevel as L, io::TemporaryStore};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Authority {
    pub key: KeyId,
    pub action: Action,
    pub operation: AtomicU64,
    /// The `--plugin-bytes` grant of a declared plugin operation; without it a ticketed key
    /// use is refused.
    pub plugin: Option<crate::plugin::BytesGrant>,
    plugin_used: std::sync::atomic::AtomicBool,
}
impl Authority {
    pub fn new(key: KeyId, action: Action, plugin: Option<crate::plugin::BytesGrant>) -> Self {
        Self {
            key,
            action,
            operation: AtomicU64::new(0),
            plugin,
            plugin_used: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
impl KeyUseGuard for Authority {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        // A ticketed use is a declared plugin operation's key use: allowed only under the
        // `--plugin-bytes` grant, once, for the declared options. Plugins without
        // declarations carry no ticket and are authorized as before.
        if let Some(ticket) = event.plugin() {
            let verdict = match &self.plugin {
                None => Err(oncl_core::plugins::TicketRefusal::NotGranted),
                Some(grant) => grant.check(ticket).and_then(|()| {
                    if self.plugin_used.swap(true, Ordering::SeqCst) {
                        Err(oncl_core::plugins::TicketRefusal::AlreadyUsed)
                    } else {
                        Ok(())
                    }
                }),
            };
            if let Err(refusal) = verdict {
                let subcode = oncl_core::plugins::PluginRefusalCode::from(refusal).id();
                crate::plugin::record_subcode(subcode);
                // The operator's own line; the plugin sees only PermissionDenied.
                crate::diagnostic(format_args!(
                    "oncl: plugin_refused operation_id={} subcode={subcode} plugin={} operation={}",
                    event.operation_id,
                    ticket.identity().id,
                    ticket.operation()
                ));
                return Err(OperationError::PermissionDenied);
            }
        }
        if event.operation_id.get() != self.operation.load(Ordering::SeqCst)
            || event.key_id != self.key
            || event.action != self.action
        {
            return Err(OperationError::PermissionDenied);
        }
        if let Some(ticket) = event.plugin() {
            crate::plugin::audit_line(event.operation_id.get(), ticket);
        }
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        if receipt.event().operation_id.get() != self.operation.load(Ordering::SeqCst) {
            return Err(OperationError::PermissionDenied);
        }
        crate::diagnostic(format_args!(
            "oncl: private_use operation_id={} applied={:?} succeeded={}",
            receipt.event().operation_id,
            outcome.applied,
            outcome.succeeded
        ));
        Ok(())
    }
}
pub fn action(args: &SignArgs) -> Action {
    if matches!(
        args.profile,
        P::DigestSha256 | P::DigestGost2004 | P::DigestGost2015_512
    ) {
        Action::SignDigest
    } else {
        Action::Sign
    }
}
pub fn execute(
    engine: &Engine,
    cli: &crate::args::Cli,
    args: &SignArgs,
    selector: &KeySelector,
    store: &TemporaryStore,
    evidence: &crate::evidence::Material,
    ctx: &mut OperationContext,
) -> Result<(oncl_pki::io::StagedArtifact, oncl_core::OperationReport), OperationError> {
    let _secret_memory = ctx.resources().reserve_memory(16384)?;
    let secret = secrets::read(
        args.key_options.secret_file.as_deref(),
        args.key_options.secret_interactive,
        args.input == "-" || args.detached_input.as_deref() == Some("-"),
        ctx,
    )?;
    let key = || KeyRequest::new(selector, Some(secret.as_str()));
    let mut source = Input::open(&args.input)?;
    let mut detached = args
        .detached_input
        .as_deref()
        .map(Input::open)
        .transpose()?;
    let (ocsp, crls) = (evidence.ocsp_slices(), evidence.crl_slices());
    let material = || oncl_pki::cms::ades::ValidationMaterial {
        certificates: &evidence.certificates,
        ocsp: &ocsp,
        crls: &crls,
    };
    let xml = || oncl_xml::XmlSignProfile {
        target: args.target_id.as_deref(),
        parent: args.parent_id.as_deref(),
        signature_id: args.signature_id.as_deref(),
        mode: if args.add {
            oncl_xml::XmlSignMode::Add
        } else {
            oncl_xml::XmlSignMode::Create
        },
        evidence_limits: Some(evidence_limits()),
        ..oncl_xml::XmlSignProfile::default()
    };
    let mut legacy_chain = if args.legacy.legacy && !args.legacy.legacy_chain.is_empty() {
        Some(crate::legacy::chain(&args.legacy.legacy_chain, ctx)?)
    } else {
        None
    };
    // Host-configured TSA, identical to the Engine's CAdES configuration: the
    // facade refuses any other TSA.
    let legacy_tsa = cli
        .tsa_url
        .as_deref()
        .map(|url| {
            crate::public::tsa(
                url,
                oncl_pki::key::HashAlg::Sha256,
                std::time::Duration::from_secs(cli.timeout_seconds),
                cli.tsa_policy.as_deref(),
            )
        })
        .transpose()?;
    let mut legacy_xades = |level| oncl_xml::xades::XadesSpec {
        level,
        tsa: if level == oncl_xml::xades::XadesLevel::B {
            None
        } else {
            legacy_tsa.clone()
        },
        chain: legacy_chain
            .as_mut()
            .map(|chain| std::mem::take(&mut chain.certificates))
            .unwrap_or_default(),
        signature_method: args.legacy.xades_signature_method(),
        digest_method: args.legacy.xades_digest_method(),
    };
    let request = match args.profile {
        P::Xml if args.legacy.legacy => SignRequest::xml_legacy(key(), args.legacy.xml_spec(args)),
        P::XadesB if args.legacy.legacy => {
            SignRequest::xades_legacy(key(), legacy_xades(oncl_xml::xades::XadesLevel::B))
        }
        P::XadesT if args.legacy.legacy => {
            SignRequest::xades_legacy(key(), legacy_xades(oncl_xml::xades::XadesLevel::T))
        }
        P::XadesLt if args.legacy.legacy => {
            SignRequest::xades_legacy(key(), legacy_xades(oncl_xml::xades::XadesLevel::Lt))
        }
        P::Cms if args.add => {
            SignRequest::cms_add(vec![key()], detached.as_mut().map(Input::source))
        }
        P::Cms => SignRequest::cms_create(vec![key()], !args.detached),
        P::Raw => SignRequest::raw_message(key()),
        P::DigestSha256 | P::DigestGost2004 | P::DigestGost2015_512 => {
            let algorithm = match args.profile {
                P::DigestSha256 => oncl_pki::key::HashAlg::Sha256,
                P::DigestGost2004 => oncl_pki::key::HashAlg::Gost34311,
                _ => oncl_pki::key::HashAlg::Streebog512,
            };
            let bytes = oncl_pki::io::MetadataInput::read(source.source(), ctx.resources(), 64)?;
            let digest = oncl_pki::digest::DigestValue::from_bytes(algorithm, bytes.as_bytes())?;
            SignRequest::raw_digest(key(), digest)
        }
        P::Xml => SignRequest::xml(key(), xml()),
        P::Wsse => SignRequest::wsse(key(), args.wsse.sign_profile(args.add)),
        P::XadesB => SignRequest::xades(key(), xml(), L::B),
        P::XadesT => SignRequest::xades(key(), xml(), L::T),
        P::XadesLt => SignRequest::xades(key(), xml(), L::Lt),
        P::XadesLta => SignRequest::xades(key(), xml(), L::Lta),
        P::Pdf => SignRequest::pdf(key(), oncl_pdf::PdfSignProfile::default()),
        P::PadesB | P::PadesT | P::PadesLt | P::PadesLta => {
            let level = match args.profile {
                P::PadesB => L::B,
                P::PadesT => L::T,
                P::PadesLt => L::Lt,
                _ => L::Lta,
            };
            SignRequest::pades(
                key(),
                oncl_pdf::PdfSignProfile::default(),
                level,
                material(),
                evidence_limits(),
            )
        }
        P::CadesB | P::CadesT | P::CadesLt | P::CadesLta => {
            let level = match args.profile {
                P::CadesB => L::B,
                P::CadesT => L::T,
                P::CadesLt => L::Lt,
                _ => L::Lta,
            };
            if args.add {
                SignRequest::cades_add(
                    vec![key()],
                    detached.as_mut().map(Input::source),
                    level,
                    material(),
                    evidence_limits(),
                )
            } else {
                SignRequest::cades_create(
                    vec![key()],
                    !args.detached,
                    level,
                    material(),
                    evidence_limits(),
                )
            }
        }
    };
    let mut stage = store.stage(ctx.resources())?;
    let mut empty = &b""[..];
    let input = if action(args) == Action::SignDigest {
        oncl_pki::io::Source::sequential(&mut empty, Some(0))
    } else {
        source.source()
    };
    let result = engine.sign_staged(request, input, &mut stage, ctx)?;
    Ok((stage, result))
}
