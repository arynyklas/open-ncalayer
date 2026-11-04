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
}
impl KeyUseGuard for Authority {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        if event.operation_id.get() != self.operation.load(Ordering::SeqCst)
            || event.key_id != self.key
            || event.action != self.action
        {
            return Err(OperationError::PermissionDenied);
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
    args: &SignArgs,
    selector: &KeySelector,
    store: &TemporaryStore,
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
    let material = oncl_pki::cms::ades::ValidationMaterial {
        certificates: &[],
        ocsp: &[],
        crls: &[],
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
    let request = match args.profile {
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
                material,
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
                    material,
                    evidence_limits(),
                )
            } else {
                SignRequest::cades_create(
                    vec![key()],
                    !args.detached,
                    level,
                    material,
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
