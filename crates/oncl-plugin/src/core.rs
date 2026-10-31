//! What the core tells its built-in modules about itself and does for them (capability
//! `builtin`): the modules it serves, the bundles its plugins port, the installation of a
//! plugin a page asks for and the windows a page opens ([`CoreHooks`]).

use std::sync::Arc;

use oncl_pdk::abi::{
    CoreBundles, CoreModules, ErrorCode, HostError, HostResult, InstallBundleArgs, Window,
    WindowArgs,
};

use crate::host::HostState;

/// A window a page asks the daemon to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiRequest {
    /// `showSettings` (the original's proxy settings).
    Settings,
    /// `showBundleManager`.
    BundleManager,
    /// `showKeystoreExplorer`.
    KeystoreExplorer,
    /// `showAdesSigning`.
    AdesSigning,
    /// `installBundle` of `symname` by the page `origin`, which no plugin of the catalog
    /// ports (or one is installed already): the daemon points the user to the plugin
    /// registry.
    InstallBundle { symname: String, origin: String },
    /// `showAdesValidation`.
    AdesValidation,
}

/// What opens the daemon's windows. It is called synchronously from a module's call on a
/// blocking-pool thread, and the page's reply waits for it: it must hand the request to the
/// UI event loop and return at once, not run the window.
pub type UiCallback = Arc<dyn Fn(UiRequest) + Send + Sync>;

/// The daemon's plugins, as the core reports and installs them.
pub trait Bundles: Send + Sync {
    /// The modules the plugins serve now.
    fn services(&self) -> Vec<String>;
    /// `(symname, version)` of the original bundles the enabled plugins port.
    fn bundles(&self) -> Vec<(String, String)>;
    /// The page `origin` asks to install the bundle `symname`: whether a plugin porting it,
    /// not installed, is offered (its installation, which asks the user, then goes on in
    /// the background). Called on a blocking-pool thread; it may take seconds (the catalog
    /// is downloaded if none is in use).
    fn request_install(&self, symname: &str, origin: &str) -> bool;
}

/// What the `core_*` host functions answer and do.
pub struct CoreHooks {
    /// The built-in modules' names, sorted.
    pub builtin_modules: Vec<String>,
    /// The plugins.
    pub bundles: Arc<dyn Bundles>,
    /// Opens the windows.
    pub ui: UiCallback,
    /// The core's version.
    pub core_version: String,
}

/// The hooks of `state`'s services: `failed` without them.
fn hooks(state: &HostState) -> HostResult<Arc<CoreHooks>> {
    state.services.core.clone().ok_or_else(|| {
        HostError::new(
            ErrorCode::Failed,
            "the core does not serve its modules here",
        )
    })
}

/// `core_modules`.
pub(crate) fn core_modules(state: &HostState) -> HostResult<CoreModules> {
    let hooks = hooks(state)?;
    Ok(CoreModules {
        builtin: hooks.builtin_modules.clone(),
        plugins: hooks.bundles.services(),
    })
}

/// `core_bundles`.
pub(crate) fn core_bundles(state: &HostState) -> HostResult<CoreBundles> {
    let hooks = hooks(state)?;
    Ok(CoreBundles {
        core_version: hooks.core_version.clone(),
        plugins: hooks.bundles.bundles(),
    })
}

/// `core_install_bundle`: from the call's origin; `invalid` without one.
pub(crate) fn core_install_bundle(state: &HostState, args: InstallBundleArgs) -> HostResult<bool> {
    let hooks = hooks(state)?;
    let origin = call_origin(state)?;
    let offered = hooks.bundles.request_install(&args.symname, &origin);
    // Page strings are logged as `&str` fields, which the log escapes.
    tracing::info!(
        symname = args.symname.as_str(),
        origin = origin.as_str(),
        offered,
        "bundle installation requested"
    );
    Ok(offered)
}

/// `core_open_window`: a bundle hint from the call's origin; `invalid` without one.
pub(crate) fn core_open_window(state: &HostState, args: WindowArgs) -> HostResult<()> {
    let hooks = hooks(state)?;
    let request = match args.window {
        Window::Settings => UiRequest::Settings,
        Window::BundleManager => UiRequest::BundleManager,
        Window::KeystoreExplorer => UiRequest::KeystoreExplorer,
        Window::AdesSigning => UiRequest::AdesSigning,
        Window::AdesValidation => UiRequest::AdesValidation,
        Window::BundleHint { symname } => UiRequest::InstallBundle {
            symname,
            origin: call_origin(state)?,
        },
    };
    (hooks.ui)(request);
    Ok(())
}

/// The page's origin of the call being answered.
fn call_origin(state: &HostState) -> HostResult<String> {
    state
        .call
        .origin
        .clone()
        .ok_or_else(|| HostError::new(ErrorCode::Invalid, "the page sent no origin"))
}
