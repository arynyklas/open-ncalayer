//! Trusted invocation bindings for public capabilities. No ambient browser or filesystem lookup.
use super::*;
use oncl_pki::{
    http::{HttpTransport, deadline::DeadlineTransport},
    io::Region,
};
use std::io::Read;

fn host_error(error: abi::HostError) -> OperationError {
    match error.code {
        abi::ErrorCode::Denied => OperationError::PermissionDenied,
        abi::ErrorCode::Limit => ProcessingError::ContainerLimit.into(),
        _ => ProcessingError::InvalidInput("invalid plugin capability arguments or binding").into(),
    }
}
fn encoded<T: serde::Serialize>(value: T) -> Vec<u8> {
    abi::encode(&Ok::<T, abi::HostError>(value))
}
impl Backend<'_, '_> {
    fn resource(&self, import: Import, name: &str, network: bool) -> Result<(), OperationError> {
        let allowed = |permissions: &[PluginPermission]| {
            permissions.iter().any(|p| {
                p.matches(&self.call, self.bindings.caller)
                    && p.permits(import, None)
                    && if network {
                        p.endpoints.iter().any(|u| u == name)
                    } else {
                        p.files.iter().any(|u| u == name)
                    }
            })
        };
        if allowed(self.ctx.grant.plugin_permissions()) && allowed(self.host) {
            Ok(())
        } else {
            Err(OperationError::PermissionDenied)
        }
    }
    pub(super) fn capability(
        &mut self,
        import: Import,
        args: &[u8],
    ) -> Result<Vec<u8>, OperationError> {
        if let Some(result) = oncl_plugin::headless::public_capability(import, args) {
            return Ok(result);
        }
        match import {
            Import::SharedGet | Import::SharedPut => {
                let host = self
                    .engine
                    .validation
                    .as_ref()
                    .ok_or(OperationError::MissingValidationServices)?;
                oncl_plugin::headless::shared_capability(
                    self.shared,
                    (host.clock)().unix_timestamp_nanos() / 1_000_000,
                    import,
                    args,
                )
                .ok_or(OperationError::PermissionDenied)
            }
            Import::Now => {
                let (): () = decode(args)?;
                let host = self
                    .engine
                    .validation
                    .as_ref()
                    .ok_or(OperationError::MissingValidationServices)?;
                Ok(encoded(
                    ((host.clock)().unix_timestamp_nanos() / 1_000_000) as i64,
                ))
            }
            Import::Log => {
                let _: abi::LogArgs = decode(args)?;
                tracing::info!(
                    plugin = self.call.plugin_id,
                    capability = "log",
                    "headless plugin event"
                );
                Ok(encoded(()))
            }
            Import::SettingsGet => {
                let (): () = decode(args)?;
                let settings = self
                    .bindings
                    .settings
                    .ok_or(OperationError::PermissionDenied)?;
                Ok(abi::encode(&settings.get()))
            }
            Import::SettingsPut => {
                let values = decode(args)?;
                let settings = self
                    .bindings
                    .settings
                    .ok_or(OperationError::PermissionDenied)?;
                Ok(abi::encode(&settings.put(values)))
            }
            Import::PageFileRead => self.read_bound_file(import, args),
            Import::PageFileWrite => self.write_bound_file(import, args),
            Import::HttpRequest | Import::HttpRequestEx => self.http(import, args),
            Import::KeysSignCms | Import::KeysSignCmsEx => self.sign_cms(import, args),
            Import::KeysSignXml | Import::KeysSignXmlEx | Import::KeysSignXades => {
                self.sign_xml(import, args)
            }
            Import::CmsVerify => self.verify_cms(args),
            Import::CaList
            | Import::CaIssuer
            | Import::PkixPath
            | Import::OcspFetch
            | Import::CrlFetch
            | Import::TspRequest
            | Import::TspStamp => self.with_pki(import, |services| {
                services
                    .capability(import, args)
                    .ok_or(OperationError::PermissionDenied)
            }),
            Import::KeysDescribe | Import::KeysChain => {
                use der::Encode;
                let args: abi::Handle = decode(args)?;
                let binding = self.bound_key(args.handle)?;
                self.authorize(import, Some(&binding.key.selector().key_id()))?;
                if self.state.released.contains(&args.handle) {
                    return Err(OperationError::PermissionDenied);
                }
                let metadata = binding
                    .metadata
                    .as_ref()
                    .ok_or(OperationError::PermissionDenied)?;
                let selected = if import == Import::KeysChain {
                    metadata.chain
                } else {
                    &[]
                };
                super::metadata::admit_bound_metadata(
                    self.state,
                    &self.ctx.scope,
                    metadata.certificate,
                    selected,
                    if import == Import::KeysDescribe {
                        metadata.alias
                    } else {
                        ""
                    },
                )?;
                if import == Import::KeysChain {
                    let chain = std::iter::once(metadata.certificate)
                        .chain(metadata.chain.iter())
                        .map(|cert| {
                            cert.to_der().map(abi::Bytes::from).map_err(|_| {
                                ProcessingError::InvalidInput("invalid bound certificate")
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(encoded(chain))
                } else {
                    let oid = metadata
                        .certificate
                        .tbs_certificate()
                        .subject_public_key_info()
                        .algorithm
                        .oid;
                    let alg = if oid == oncl_pki::oid::RSA_ENCRYPTION {
                        "rsa"
                    } else if oid == oncl_pki::oid::GOST_2004_KEY {
                        "gost2004"
                    } else if oid == oncl_pki::oid::GOST_2015_512_KEY {
                        "gost2015_512"
                    } else {
                        return Err(oncl_pki::key::KeyError::UnsupportedAlgorithm.into());
                    };
                    Ok(encoded(abi::KeyDescription {
                        alias: metadata.alias.to_owned(),
                        alg: alg.to_owned(),
                        certificate: metadata
                            .certificate
                            .to_der()
                            .map_err(|_| {
                                ProcessingError::InvalidInput("invalid bound certificate")
                            })?
                            .into(),
                    }))
                }
            }
            Import::KeysRelease => {
                let args: abi::Handle = decode(args)?;
                let key = self.bound_key(args.handle)?;
                self.authorize(import, Some(&key.key.selector().key_id()))?;
                if self.state.released.contains(&args.handle) {
                    // A declared operation's one key: releasing it again is a no-op.
                    return if self.declared.is_some() {
                        Ok(encoded(()))
                    } else {
                        Err(OperationError::PermissionDenied)
                    };
                }
                self.state.released.push(args.handle);
                Ok(encoded(()))
            }
            _ => Err(OperationError::PermissionDenied),
        }
    }
    fn read_bound_file(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, OperationError> {
        let args: abi::PagePathArgs = decode(args)?;
        self.resource(import, &args.path, false)?;
        let binding = self
            .bindings
            .inputs
            .iter()
            .find(|b| b.name == args.path)
            .ok_or(OperationError::PermissionDenied)?;
        let mut input = binding
            .input
            .try_borrow_mut()
            .map_err(|_| OperationError::InvalidContext)?;
        let len = input.len();
        if len > self.transfer as u64 {
            return Err(OperationError::Plugin(
                oncl_plugin::PluginError::TooLarge.into(),
            ));
        }
        let mut view = input.reader(&[Region { offset: 0, len }], &self.ctx.scope)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len as usize)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        view.source()
            .read_to_end(&mut bytes)
            .map_err(ProcessingError::from)?;
        view.finish()?;
        self.ctx.scope.checkpoint()?;
        Ok(encoded(abi::PageRead::Ok(abi::OpenedFile {
            path: args.path,
            data: bytes.into(),
        })))
    }
    fn write_bound_file(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, OperationError> {
        let args: abi::PageWriteArgs = decode(args)?;
        // These are opaque host names, never OS paths, even if a guest supplies traversal.
        let safe = |name: &str| {
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains(['/', '\\', ':', '\0'])
        };
        if !safe(&args.dir) || !safe(&args.name) {
            return Err(OperationError::PermissionDenied);
        }
        let extension = args
            .name
            .rsplit_once('.')
            .map(|(_, e)| e)
            .ok_or(OperationError::PermissionDenied)?;
        if !self
            .capabilities
            .page_files_ext
            .iter()
            .any(|e| e.eq_ignore_ascii_case(extension))
        {
            return Err(OperationError::PermissionDenied);
        }
        let name = format!("{}/{}", args.dir, args.name);
        self.resource(import, &name, false)?;
        if !self
            .bindings
            .outputs
            .iter()
            .any(|b| b.directory == args.dir && b.name == args.name)
            || self.state.outputs.iter().any(|(key, _)| key == &name)
        {
            return Err(OperationError::PermissionDenied);
        }
        let store = self
            .engine
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let mut stage = store.stage(&mut self.ctx.scope)?;
        stage.write_chunk(&args.data)?;
        self.state.outputs.push((name.clone(), stage));
        Ok(encoded(abi::PageWrite::Written(name)))
    }
    fn http(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, OperationError> {
        let args: abi::HttpExArgs = if import == Import::HttpRequest {
            let simple: abi::HttpArgs = decode(args)?;
            abi::HttpExArgs {
                method: simple.method,
                url: simple.url,
                relative_to_origin: false,
                headers: Vec::new(),
                content_type: simple.content_type,
                body: simple.body,
                timeout_ms: None,
            }
        } else {
            decode(args)?
        };
        let (inner, policy) = self
            .bindings
            .network
            .ok_or(OperationError::PermissionDenied)?;
        let prepared = oncl_plugin::headless::prepare_http(
            import,
            self.capabilities,
            self.bindings.caller,
            &args,
        )
        .map_err(host_error)?;
        self.resource(import, prepared.url(), true)?;
        let counted = self.ctx.guest_http(inner);
        let transport = DeadlineTransport::new(&counted, policy, &self.ctx.scope);
        let request = prepared.request((self.transfer as u64).min(oncl_plugin::MAX_HTTP_BODY));
        let result = transport.send_scoped(&request);
        transport.finish()?;
        self.ctx.network_status()?;
        let reply =
            result.map_err(|e| ProcessingError::Io(std::io::Error::other(e.to_string())))?;
        #[derive(serde::Serialize)]
        struct Response<'a> {
            status: u16,
            content_type: Option<&'a str>,
            location: Option<&'a str>,
            body: Bytes<'a>,
        }
        struct Bytes<'a>(&'a [u8]);
        impl serde::Serialize for Bytes<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.0)
            }
        }
        Ok(encoded(Response {
            status: reply.status(),
            content_type: reply.content_type(),
            location: reply.location(),
            body: Bytes(reply.body()),
        }))
    }
}

impl Backend<'_, '_> {
    pub(super) fn with_pki<T>(
        &self,
        import: Import,
        operation: impl FnOnce(&oncl_plugin::headless::PkiServices<'_>) -> Result<T, OperationError>,
    ) -> Result<T, OperationError> {
        let authorize = self
            .ctx
            .plugin_pki
            .as_ref()
            .ok_or(OperationError::InvalidContext)?;
        if authorize.import != import {
            return Err(OperationError::InvalidContext);
        }
        let host = self
            .engine
            .validation
            .as_ref()
            .ok_or(OperationError::MissingValidationServices)?;
        let counted = self.ctx.http(host.http.as_ref());
        let transport = DeadlineTransport::new(&counted, &host.network, &self.ctx.scope);
        let default_tsa = oncl_pki::tsp::TsaSpec::from(oncl_pki::tsp::TsaProfile::basics_default());
        let tsa = self
            .engine
            .cades
            .as_ref()
            .map_or(&default_tsa, |config| &config.tsa);
        let services = oncl_plugin::headless::PkiServices {
            cas: &host.anchors,
            clock: host.clock.as_ref(),
            tsa,
            http: &transport,
            authorize,
        };
        let result = operation(&services);
        self.ctx.network_status()?;
        let result = result?;
        transport.finish()?;
        Ok(result)
    }
}
