//! Legacy wire selectors through real guarded Core facades and the original context.
use super::*;
use std::io::{self, Write};

struct Reply {
    bytes: Vec<u8>,
    limit: usize,
    failure: Option<ProcessingError>,
}
impl Write for Reply {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.failure = Some(ProcessingError::ContainerLimit);
            return Err(io::Error::other(
                "plugin XML output exceeds its ABI transfer limit",
            ));
        }
        if self.bytes.try_reserve(bytes.len()).is_err() {
            self.failure = Some(ProcessingError::MemoryLimit);
            return Err(io::Error::other("plugin XML output allocation failed"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn payload_limit(transfer: usize, import: Import) -> usize {
    let framing = if import == Import::KeysSignXades {
        12
    } else {
        4
    };
    let mut payload = transfer.saturating_sub(framing + 1);
    loop {
        let header = match payload {
            0..=23 => 1,
            24..=255 => 2,
            256..=65535 => 3,
            _ => 5,
        };
        if payload.saturating_add(framing + header) <= transfer || payload == 0 {
            return payload;
        }
        payload -= 1;
    }
}
fn argument(error: abi::HostError) -> OperationError {
    match error.code {
        abi::ErrorCode::Denied => OperationError::PermissionDenied,
        abi::ErrorCode::Limit => ProcessingError::MetadataLimit.into(),
        _ => ProcessingError::InvalidInput("invalid XML capability selectors").into(),
    }
}
struct OutputTarget<'a> {
    ctx: &'a mut OperationContext,
    previous: Option<u64>,
}
impl<'a> OutputTarget<'a> {
    fn new(ctx: &'a mut OperationContext, limit: u64) -> Self {
        let previous = ctx.plugin_xml_output_limit;
        ctx.plugin_xml_output_limit = Some(previous.map_or(limit, |old| old.min(limit)));
        Self { ctx, previous }
    }
}
impl Drop for OutputTarget<'_> {
    fn drop(&mut self) {
        self.ctx.plugin_xml_output_limit = self.previous;
    }
}
impl<'a, 'b> Backend<'a, 'b> {
    pub(super) fn sign_xml(
        &mut self,
        import: Import,
        bytes: &[u8],
    ) -> Result<Vec<u8>, OperationError> {
        match import {
            Import::KeysSignXml => {
                let args: abi::SignXmlArgs = decode(bytes)?;
                let key = self.xml_key(import, args.handle)?;
                let spec = oncl_plugin::headless::xml_spec(&args).map_err(argument)?;
                self.xml_operation(import, key, &args.xml, crate::xml::LegacySpec::Xml(spec))
            }
            Import::KeysSignXmlEx => {
                let args: abi::SignXmlExArgs = decode(bytes)?;
                let key = self.xml_key(import, args.handle)?;
                let spec = oncl_plugin::headless::xml_spec_ex(&args);
                self.xml_operation(import, key, &args.xml, crate::xml::LegacySpec::Xml(spec))
            }
            Import::KeysSignXades => {
                let args: abi::XadesArgs = decode(bytes)?;
                let key = self.xml_key(import, args.handle)?;
                let tsa = if args.level == abi::XadesLevel::B {
                    None
                } else {
                    if self.engine.cades.is_none() {
                        return Err(OperationError::MissingCadesConfiguration);
                    }
                    self.admit_tsa_choice(&args.tsa)?;
                    Some(self.with_pki(import, |services| {
                        services
                            .resolve_tsa(&args.tsa)
                            .map_err(argument)?
                            .map_err(|_| OperationError::ValidationRequired)
                    })?)
                };
                if args.level == abi::XadesLevel::Lt {
                    let limits = self
                        .engine
                        .cades
                        .as_ref()
                        .ok_or(OperationError::MissingCadesConfiguration)?
                        .evidence_limits;
                    if args.chain.len() > limits.max_chain_len
                        || args
                            .chain
                            .iter()
                            .any(|certificate| certificate.len() as u64 > limits.max_item_bytes)
                    {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                }
                let spec = oncl_plugin::headless::xades_spec(&args, tsa).map_err(argument)?;
                self.xml_operation(import, key, &args.xml, crate::xml::LegacySpec::Xades(spec))
            }
            _ => Err(OperationError::PermissionDenied),
        }
    }
    fn xml_key(
        &self,
        import: Import,
        handle: u32,
    ) -> Result<&'b PluginKeyBinding<'b>, OperationError> {
        let keys: &'b [PluginKeyBinding<'b>] = self.bindings.keys;
        let key = keys
            .iter()
            .find(|key| key.handle == handle)
            .ok_or(OperationError::PermissionDenied)?;
        self.authorize(import, Some(&key.key.selector().key_id()))?;
        if self.state.released.contains(&handle) {
            return Err(OperationError::PermissionDenied);
        }
        Ok(key)
    }
    fn xml_operation(
        &mut self,
        import: Import,
        key: &'b PluginKeyBinding<'b>,
        xml: &[u8],
        spec: crate::xml::LegacySpec<'_>,
    ) -> Result<Vec<u8>, OperationError> {
        let request = KeyRequest::new(key.key.selector(), key.key.secret());
        let request = match spec {
            crate::xml::LegacySpec::Xml(spec) => crate::SignRequest::xml_legacy(request, spec),
            crate::xml::LegacySpec::Xades(spec) => crate::SignRequest::xades_legacy(request, spec),
        };
        let mut reply = Reply {
            bytes: Vec::new(),
            limit: payload_limit(self.transfer, import),
            failure: None,
        };
        let target = OutputTarget::new(&mut *self.ctx, reply.limit as u64);
        let result = self.engine.sign(
            request,
            Source::sequential(&mut Cursor::new(xml), Some(xml.len() as u64)),
            &mut reply,
            target.ctx,
        );
        let applied = match &result {
            Ok(report) => report.applied,
            Err(error) => error.applied_state(),
        };
        self.state.applied = super::cms::aggregate(self.state.applied, applied);
        if let Some(error) = reply.failure {
            return Err(after_use(error.into(), applied));
        }
        result?;
        let bytes = abi::Bytes::from(reply.bytes);
        Ok(if import == Import::KeysSignXades {
            abi::encode(&Ok::<_, abi::HostError>(abi::XadesOutcome::Signed(bytes)))
        } else {
            abi::encode(&Ok::<_, abi::HostError>(bytes))
        })
    }
    fn admit_tsa_choice(&mut self, choice: &abi::TsaChoice) -> Result<(), OperationError> {
        if !matches!(choice, abi::TsaChoice::Basics) {
            return Ok(());
        }
        let Some(config) = &self.engine.cades else {
            return Ok(());
        };
        let spec = &config.tsa;
        let nonce = match &spec.nonce {
            oncl_pki::http::NonceSpec::Value(bytes) => bytes.len(),
            _ => 0,
        };
        let content_type = match &spec.method {
            oncl_pki::http::PkiMethod::Post { content_type } => {
                content_type.as_ref().map_or(0, String::len)
            }
            _ => 0,
        };
        let work = (std::mem::size_of_val(spec) as u64)
            .checked_add(spec.url.len() as u64)
            .and_then(|n| n.checked_add(nonce as u64))
            .and_then(|n| n.checked_add(content_type as u64))
            .and_then(|n| n.checked_mul(2))
            .ok_or(ProcessingError::MetadataLimit)?;
        self.state
            .admission
            .as_mut()
            .ok_or(OperationError::InvalidContext)?
            .admit_metadata(work)
    }
}
