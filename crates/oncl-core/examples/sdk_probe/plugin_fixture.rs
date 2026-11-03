//! Synthetic-only actual WASM calls shared by L01 acceptance and its runtime probe.
pub(crate) use crate::plugin_crypto as crypto;
use oncl_core::keys::{KeyRequest, KeySelector};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationPolicy, plugins::*,
};
use oncl_pdk::abi::{self, Import};
use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
use oncl_plugin::{InstanceLimits, Manifest};
use std::sync::Arc;
pub(crate) const ID: &str = "test.l01";
pub(crate) const MESSAGE: &[u8] = b"L01 real WASM source-bound signature";
pub(crate) struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
pub(crate) fn caller() -> CallerContext {
    CallerContext::ServiceClient("l01-authorized-service".into())
}
pub(crate) fn permission(imports: &[Import], keys: &[KeySelector]) -> PluginPermission {
    PluginPermission::new(ID, "sign", caller(), imports.iter().copied())
        .with_keys(keys.iter().map(KeySelector::key_id))
}
pub(crate) fn wasm(calls: &[(Import, Vec<u8>)]) -> Vec<u8> {
    let mut imports = String::new();
    let mut data = String::new();
    let mut body = String::new();
    let mut seen = Vec::new();
    let mut at = 1024;
    for (import, args) in calls {
        if !seen.contains(import) {
            seen.push(*import);
            imports.push_str(&format!(
                "(import \"oncl\" \"{0}\" (func ${0} (param i32 i32) (result i64)))",
                import.name()
            ));
        }
        let escaped: String = args.iter().map(|b| format!("\\{b:02x}")).collect();
        data.push_str(&format!("(data (i32.const {at}) \"{escaped}\")"));
        body.push_str(&format!(
            "(local.set $r (call ${} (i32.const {at}) (i32.const {})))",
            import.name(),
            args.len()
        ));
        at += args.len();
    }
    wat::parse_str(format!(r#"(module {imports}
      (memory (export "memory") 16 16)
      (global $heap (mut i32) (i32.const 65536))
      (func (export "oncl_abi_version") (result i32) (i32.const 1))
      (func (export "oncl_alloc") (param $n i32) (result i32) (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
      (func (export "oncl_free") (param i32 i32))
      {data} (data (i32.const 512) "0123456789abcdef")
      (func (export "oncl_process") (param i32 i32) (result i64)
        (local $r i64) (local $src i32) (local $len i32) (local $i i32) (local $b i32) (local $out i32) (local $hex i32)
        {body}
        (local.set $src (i32.wrap_i64 (i64.shr_u (local.get $r) (i64.const 32))))
        (local.set $len (i32.wrap_i64 (local.get $r)))
        (local.set $out (global.get $heap))
        (i32.store8 (local.get $out) (i32.const 0xa1))
        (i32.store8 offset=1 (local.get $out) (i32.const 0x68))
        (i64.store offset=2 (local.get $out) (i64.const 0x65736e6f70736572))
        (i32.store8 offset=10 (local.get $out) (i32.const 0x7a))
        (local.set $hex (i32.shl (local.get $len) (i32.const 1)))
        (i32.store8 offset=11 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 24)))
        (i32.store8 offset=12 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 16)))
        (i32.store8 offset=13 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 8)))
        (i32.store8 offset=14 (local.get $out) (local.get $hex))
        (block $done (loop $next
          (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
          (local.set $b (i32.load8_u (i32.add (local.get $src) (local.get $i))))
          (i32.store8 offset=15 (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
            (i32.load8_u offset=512 (i32.shr_u (local.get $b) (i32.const 4))))
          (i32.store8 offset=16 (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
            (i32.load8_u offset=512 (i32.and (local.get $b) (i32.const 15))))
          (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $next)))
        (i64.or (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
          (i64.extend_i32_u (i32.add (local.get $hex) (i32.const 15))))))"#)).unwrap()
}
pub(crate) fn engine(
    calls: &[(Import, Vec<u8>)],
    keys: &[KeySelector],
    host_imports: &[Import],
) -> (Engine, Arc<crypto::Guard>, Arc<crypto::Provider>) {
    engine_configured(calls, permission(host_imports, keys), |services| services)
}
pub(crate) fn engine_configured(
    calls: &[(Import, Vec<u8>)],
    host_permission: PluginPermission,
    configure: impl FnOnce(EngineServices) -> EngineServices,
) -> (Engine, Arc<crypto::Guard>, Arc<crypto::Provider>) {
    let manifest = Manifest::from_toml(&format!(
        r#"id = "{ID}"
name.ru = "L01 synthetic"
name.kk = "L01 synthetic"
name.en = "L01 synthetic"
version = "1.0.0"
min_core = "0.1.0"
modules = ["test.l01.module"]
[capabilities]
keys = true
dialogs = true
settings = true
page_files = true
page_files_ext = ["bin"]
http = ["https://network.synthetic.test/"]
origins = ["https://trusted.example"]
"#
    ))
    .unwrap();
    let mut plugins = PluginRegistry::new();
    plugins
        .install(
            manifest,
            &wasm(calls),
            InstanceLimits {
                max_memory: 1 << 20,
                max_transfer: 1 << 18,
                ..InstanceLimits::default()
            },
            vec![host_permission],
        )
        .unwrap();
    let guard = Arc::new(crypto::Guard::default());
    let provider = Arc::new(crypto::Provider::default());
    let engine = Engine::new(configure(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(provider.clone(), guard.clone())
            .with_validation(crypto::validation())
            .with_plugins(plugins),
    ))
    .unwrap();
    (engine, guard, provider)
}
pub(crate) fn begin(
    engine: &Engine,
    keys: &[KeySelector],
    permission: Option<PluginPermission>,
) -> OperationContext {
    let mut grant = ExecutionGrant::new([Action::Sign, Action::Hash])
        .with_keys(keys.iter().map(KeySelector::key_id));
    if let Some(p) = permission {
        grant = grant.with_plugins([p]);
    }
    engine
        .begin(grant, OperationPolicy::strict_online(), Arc::new(Control))
        .unwrap()
}
pub(crate) fn signature(response: &str) -> Vec<u8> {
    let bytes: Vec<u8> = (0..response.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&response[i..i + 2], 16).unwrap())
        .collect();
    abi::decode::<abi::HostResult<abi::Bytes>>(&bytes)
        .unwrap()
        .unwrap()
        .into_vec()
}
pub(crate) fn binding(key: &KeySelector, handle: u32) -> PluginKeyBinding<'_> {
    PluginKeyBinding::new(handle, KeyRequest::new(key, Some(crypto::PASSWORD)))
}
