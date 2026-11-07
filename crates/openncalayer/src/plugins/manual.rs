//! What the manual-tools window may offer of the installed plugins: a [`PluginRegistry`]
//! built from the [`Store`] and the data the window lists ([`ManualOperation`]).
//!
//! Only plugins that are installed, on and not withdrawn, and that declare `manual`
//! `[[operations]]` are registered, each from its own [`Package`]: the manifest, the module
//! and the digest of that package file are read together, so the identity of the plugin
//! the registry names is the file that was checked. A plugin without operations is not
//! registered here (deny by default); it keeps serving its modules to pages through
//! [`PluginModules`](oncl_plugin::PluginModules), which this does not touch.
//!
//! Nothing here signs, builds a request or asks the user: the call path is the manual
//! window's. Operations the manual window cannot run (`derived`, `network = [urls]`, and
//! the ports the inventory marks unsupported, `docs/design/manual-plugins-inventory.md`)
//! are not listed; the inventory, not this code, says which are which.

use oncl_core::plugins::{CallerContext, PackageHash, PluginRegistry};
use oncl_pki::http::HttpMethod;
use oncl_plugin::operations::{Network, Operation, Param};
use oncl_plugin::{DEFAULT_OCSP, DEFAULT_TSA, InstanceLimits, Localized, NCA_PKI_HOSTS, Store};
use tracing::warn;

use super::Version;

/// The caller the manual window's permissions are issued to.
pub const MANUAL_CALLER: &str = "manual-window";

/// The caller of the manual window: the local operator, never a page.
pub fn manual_caller() -> CallerContext {
    CallerContext::LocalOperator(MANUAL_CALLER.to_owned())
}

/// The exact PKI endpoints an operation with `network = "pki"` may use: the NCA's own
/// time-stamp and OCSP services (what `PkiUrl::Default` names), each by the methods the core
/// uses: the core validates the signer's certificate online before the key is applied, and its
/// OCSP request to the responder named by the certificate is a `GET` under the responder's
/// address (a plugin's own request, a `POST`). A method that is not listed is denied, and a
/// denied PKI request fails the whole call, so a key use would be refused for want of the
/// `GET`. CRLs are fetched under the provenance of the certificate, not from this list.
const PKI_ENDPOINTS: [(HttpMethod, &str); 4] = [
    (HttpMethod::Get, DEFAULT_TSA),
    (HttpMethod::Post, DEFAULT_TSA),
    (HttpMethod::Get, DEFAULT_OCSP),
    (HttpMethod::Post, DEFAULT_OCSP),
];

/// One operation of an installed plugin that the manual window may offer.
///
/// `plugin_name` and `label` are the plugin's own text: untrusted, to be shown as such and
/// never as a promise of what the operation does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualOperation {
    /// The plugin's id.
    pub plugin_id: String,
    /// The installed version.
    pub plugin_version: Version,
    /// The plugin's name (untrusted text).
    pub plugin_name: Localized,
    /// The operation's name: `^[a-z][a-z0-9-]{0,31}$`.
    pub operation: String,
    /// The operation's label (untrusted text).
    pub label: Localized,
    /// The parameters the window asks for, in the manifest's order.
    pub params: Vec<Param>,
    /// Whether it uses the user's key.
    pub uses_key: bool,
    /// The exact PKI endpoints the registry granted the operation (empty when its network is
    /// not `pki`): the window's per-call grant must name the same.
    pub pki_endpoints: Vec<(HttpMethod, String)>,
}

/// An installed plugin (on, not withdrawn, its package readable) that offers no operation to the
/// manual window. Why is not known here: its manifest declares none for this window (no
/// `[[operations]]`, none `manual`, or only ones the window cannot run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithoutOperations {
    /// The plugin's id.
    pub plugin_id: String,
    /// The installed version.
    pub plugin_version: Version,
    /// The plugin's name (untrusted text).
    pub plugin_name: Localized,
}

/// An installed plugin that was not registered because its package could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The plugin's id.
    pub plugin_id: String,
    /// Why, for the log and the window.
    pub reason: String,
}

/// The registry and the list of the manual window.
#[derive(Debug)]
pub struct ManualPlugins {
    /// Exactly the plugins with offered operations, each with its declared policy for
    /// [`manual_caller`].
    pub registry: PluginRegistry,
    /// The operations offered, plugin by plugin in the store's order, each plugin's in its
    /// manifest's order.
    pub operations: Vec<ManualOperation>,
    /// Installed plugins whose package could not be used.
    pub skipped: Vec<Skipped>,
    /// Installed plugins that are readable and offer nothing to the window, in the store's
    /// order. They are not in the registry.
    pub without_operations: Vec<WithoutOperations>,
}

impl ManualPlugins {
    /// Builds the registry from the installed plugins of `store`.
    pub fn build(store: &Store) -> ManualPlugins {
        let mut out = ManualPlugins {
            registry: PluginRegistry::new(),
            operations: Vec::new(),
            skipped: Vec::new(),
            without_operations: Vec::new(),
        };
        for (id, installed) in store.state().plugins {
            if !installed.enabled || installed.withdrawn {
                continue;
            }
            let package = match store.load_package(&id) {
                Ok(package) => package,
                Err(e) => {
                    warn!(plugin = %id, error = %e, "the manual window cannot use the installed plugin");
                    out.skipped.push(Skipped {
                        plugin_id: id,
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            out.add(package);
        }
        out
    }

    /// Registers `package` with a policy for each of its manual operations the window can
    /// run; a package with none is left out.
    fn add(&mut self, package: oncl_plugin::Package) {
        let manifest = &package.manifest;
        // `network = [urls]` is not runnable in the window: the registry refuses it too.
        let ops: Vec<&Operation> = manifest
            .manual_operations()
            .filter(|o| !matches!(o.uses().network(), Network::Urls(_)))
            .collect();
        if ops.is_empty() {
            self.without_operations.push(without(&package));
            return;
        }
        // The digest comes from the same `Package` as the manifest and the module.
        if let Err(e) = self.registry.install(
            manifest.clone(),
            PackageHash::File(package.sha256),
            &package.wasm,
            InstanceLimits::default(),
            Vec::new(),
        ) {
            warn!(plugin = %manifest.id, error = %e, "the manual window cannot register the plugin");
            self.skipped.push(Skipped {
                plugin_id: manifest.id.clone(),
                reason: e.to_string(),
            });
            return;
        }
        let before = self.operations.len();
        for op in ops {
            let endpoints = endpoints_of(op);
            match self.registry.allow_declared_with_pki(
                &manifest.id,
                op.name(),
                manual_caller(),
                endpoints.iter().copied(),
                &NCA_PKI_HOSTS,
            ) {
                Ok(()) => self.operations.push(offer(&package, op)),
                Err(e) => {
                    warn!(plugin = %manifest.id, operation = op.name(), error = ?e, "the manual window does not offer the operation");
                }
            }
        }
        if self.operations.len() == before {
            // Registered, but nothing of it is offered: the window says so, one honest line.
            self.without_operations.push(without(&package));
        }
    }
}

/// The exact PKI endpoints an operation is granted: the national authority's own services when
/// its network is `pki`, none otherwise.
fn endpoints_of(op: &Operation) -> &'static [(HttpMethod, &'static str)] {
    if matches!(op.uses().network(), Network::Pki) {
        &PKI_ENDPOINTS
    } else {
        &[]
    }
}

fn without(package: &oncl_plugin::Package) -> WithoutOperations {
    WithoutOperations {
        plugin_id: package.manifest.id.clone(),
        plugin_version: package.manifest.version.clone(),
        plugin_name: package.manifest.name.clone(),
    }
}

fn offer(package: &oncl_plugin::Package, op: &Operation) -> ManualOperation {
    ManualOperation {
        plugin_id: package.manifest.id.clone(),
        plugin_version: package.manifest.version.clone(),
        plugin_name: package.manifest.name.clone(),
        operation: op.name().to_owned(),
        label: op.label().clone(),
        params: op.params().to_vec(),
        uses_key: !op.uses().keys().is_empty(),
        pki_endpoints: endpoints_of(op)
            .iter()
            .map(|(method, url)| (*method, (*url).to_owned()))
            .collect(),
    }
}

/// What the tools window's Plugins page gets of `manual`: the operations by plugin, the
/// installed plugins with nothing for the window, and the ones whose package could not be read
/// (the reason stays in the log).
pub fn listing(manual: &ManualPlugins) -> oncl_ui::ManualListing {
    oncl_ui::ManualListing {
        operations: manual
            .operations
            .iter()
            .map(|o| oncl_ui::OfferedOperation {
                plugin_id: o.plugin_id.clone(),
                plugin_version: o.plugin_version.to_string(),
                plugin_name: o.plugin_name.clone(),
                operation: o.operation.clone(),
                label: o.label.clone(),
                params: o.params.clone(),
                uses_key: o.uses_key,
                pki_endpoints: o.pki_endpoints.clone(),
            })
            .collect(),
        without_operations: manual
            .without_operations
            .iter()
            .map(|p| oncl_ui::WithoutOperations {
                plugin_id: p.plugin_id.clone(),
                plugin_version: p.plugin_version.to_string(),
                plugin_name: p.plugin_name.clone(),
            })
            .collect(),
        unusable: manual
            .skipped
            .iter()
            .map(|p| oncl_ui::UnusablePlugin {
                plugin_id: p.plugin_id.clone(),
            })
            .collect(),
    }
}

/// The plugins of the tools window's Plugins page: read from the plugin service each time the
/// page lists them, and run on an engine of their own ([`oncl_ui::plugin_offer`]).
pub struct DesktopManualPlugins {
    service: std::sync::Arc<super::PluginService>,
    kit: oncl_ui::PluginEngineKit,
}

impl DesktopManualPlugins {
    /// `kit` is what the engine is made of: the same authority as the tools window's own
    /// engine has, and the program's activity gate.
    pub fn new(
        service: std::sync::Arc<super::PluginService>,
        kit: oncl_ui::PluginEngineKit,
    ) -> Self {
        Self { service, kit }
    }
}

impl oncl_ui::ManualPluginSource for DesktopManualPlugins {
    fn offer(&self) -> Result<oncl_ui::PluginOffer, oncl_ui::OfferError> {
        let manual = self.service.manual_plugins();
        let listing = listing(&manual);
        oncl_ui::plugin_offer(manual.registry, manual_caller(), listing, &self.kit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::tests::{ID, example, example_ops, operation};
    use oncl_core::plugins::PluginIdentity;
    use oncl_core::{Engine, EngineServices};
    use oncl_pki::resource::ResourceLimits;
    use oncl_plugin::{Package, Source};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn store_with(bytes: &[u8]) -> (tempfile::TempDir, Store) {
        let (dir, store) = store();
        install(&store, bytes);
        (dir, store)
    }

    fn install(store: &Store, bytes: &[u8]) -> Package {
        let package = Package::read(bytes).unwrap();
        store.install(&package, bytes, Source::Local).unwrap();
        package
    }

    fn engine(plugins: ManualPlugins) -> Engine {
        Engine::new(
            EngineServices::hash_only(ResourceLimits::default()).with_plugins(plugins.registry),
        )
        .unwrap()
    }

    fn other(operations: &[String]) -> Vec<u8> {
        oncl_testkit::plugin::example_package_with(|m| {
            m.replacen("version = \"0.1.0\"", "version = \"0.3.0\"", 1)
                .replacen(
                    "min_core = \"0.1.0-alpha.3\"",
                    &format!(
                        "min_core = \"{}\"",
                        oncl_plugin::operations::operations_min_core()
                    ),
                    1,
                )
                .replace(ID, "kz.other.plugin")
                + &operations.concat()
        })
    }

    #[test]
    fn the_pki_endpoints_are_within_the_nca_hosts() {
        for (_, url) in PKI_ENDPOINTS {
            let host = url.trim_start_matches("http://");
            assert!(
                NCA_PKI_HOSTS
                    .iter()
                    .any(|h| host == *h || host.ends_with(&format!(".{h}"))),
                "{url}"
            );
        }
    }

    #[test]
    fn nothing_installed_registers_nothing() {
        let (_dir, store) = store();
        let plugins = ManualPlugins::build(&store);
        assert!(plugins.operations.is_empty() && plugins.skipped.is_empty());
        assert!(engine(plugins).plugin_identity(ID).is_none());
    }

    #[test]
    fn the_registry_names_the_installed_package_file() {
        let (_dir, store) = store();
        let bytes = example_ops(
            "0.1.0",
            &[
                operation("sign", "Sign", true, false),
                operation("stamp", "Stamp", false, true),
            ],
        );
        let package = install(&store, &bytes);
        let plugins = ManualPlugins::build(&store);
        assert!(plugins.skipped.is_empty());
        let names: Vec<&str> = plugins
            .operations
            .iter()
            .map(|o| o.operation.as_str())
            .collect();
        assert_eq!(names, ["sign", "stamp"]);
        let sign = &plugins.operations[0];
        assert_eq!(sign.plugin_id, ID);
        assert_eq!(sign.label.en, "Sign");
        assert_eq!(sign.params.len(), 1);
        assert_eq!(sign.params[0].name, "f");
        assert!(sign.uses_key && !plugins.operations[1].uses_key);
        let engine = engine(plugins);
        // The digest is the package file's own, not a digest of its parts.
        assert_eq!(
            engine.plugin_identity(ID),
            Some(&PluginIdentity {
                id: ID.to_owned(),
                package: PackageHash::File(package.sha256),
                version: "0.1.0".to_owned(),
            })
        );
        assert_eq!(package.sha256, oncl_update::Sha256::of(&bytes).0);
        let offered: Vec<&str> = engine
            .plugin_operations(ID)
            .unwrap()
            .iter()
            .map(|o| o.name())
            .collect();
        assert_eq!(offered, ["sign", "stamp"]);
    }

    #[test]
    fn a_plugin_without_operations_is_not_registered() {
        let (_dir, store) = store();
        install(&store, &example("0.1.0"));
        install(&store, &other(&[operation("sign", "Sign", true, false)]));
        let plugins = ManualPlugins::build(&store);
        assert_eq!(plugins.operations.len(), 1);
        assert_eq!(plugins.operations[0].plugin_id, "kz.other.plugin");
        let engine = engine(plugins);
        assert!(engine.plugin_identity(ID).is_none());
        assert!(engine.plugin_identity("kz.other.plugin").is_some());
    }

    #[test]
    fn an_installed_plugin_with_nothing_for_the_window_is_listed_as_such() {
        let (_dir, store) = store();
        install(&store, &example("0.1.0"));
        let none = ManualPlugins::build(&store);
        assert!(none.operations.is_empty() && none.skipped.is_empty());
        assert_eq!(none.without_operations.len(), 1);
        assert_eq!(none.without_operations[0].plugin_id, ID);
        assert_eq!(
            none.without_operations[0].plugin_version.to_string(),
            "0.1.0"
        );
        assert!(!none.without_operations[0].plugin_name.en.is_empty());
        // One with operations is not in that list, and one that is off or withdrawn is in
        // neither (it is not installed for this purpose).
        install(&store, &other(&[operation("sign", "Sign", true, false)]));
        let both = ManualPlugins::build(&store);
        assert_eq!(both.operations.len(), 1);
        let ids: Vec<&str> = both
            .without_operations
            .iter()
            .map(|p| p.plugin_id.as_str())
            .collect();
        assert_eq!(ids, [ID]);
        store.set_enabled(ID, false).unwrap();
        assert!(ManualPlugins::build(&store).without_operations.is_empty());
        // An operation the window cannot run (a URL network) leaves its plugin with nothing.
        let urls = operation("fetch", "Fetch", false, false).replace(
            "[operations.uses]\n",
            "[operations.uses]\nnetwork = [\"https://example.invalid/\"]\n",
        );
        let (_dir, store) = store_with(&example_ops("0.1.0", &[urls]));
        assert_eq!(ManualPlugins::build(&store).without_operations.len(), 1);
    }

    #[test]
    fn the_listing_for_the_window_carries_the_granted_endpoints_and_every_plugin() {
        let (_dir, store) = store();
        install(
            &store,
            &example_ops(
                "0.1.0",
                &[
                    operation("sign", "Sign", true, true),
                    operation("local", "Local", true, false),
                ],
            ),
        );
        install(&store, &other(&[]));
        let plugins = ManualPlugins::build(&store);
        let listing = super::listing(&plugins);
        assert_eq!(listing.operations.len(), 2);
        let sign = &listing.operations[0];
        assert_eq!(sign.operation, "sign");
        assert_eq!(sign.plugin_version, "0.1.0");
        // The endpoints are exactly the ones the registry was given for a `pki` operation:
        // the NCA's services, by GET and POST (the signer is validated online by a GET).
        let granted: Vec<(HttpMethod, String)> = PKI_ENDPOINTS
            .iter()
            .map(|(m, u)| (*m, (*u).to_owned()))
            .collect();
        assert_eq!(sign.pki_endpoints, granted);
        assert!(
            sign.pki_endpoints
                .contains(&(HttpMethod::Get, DEFAULT_OCSP.to_owned()))
        );
        assert!(listing.operations[1].pki_endpoints.is_empty());
        assert!(sign.uses_key);
        assert_eq!(
            listing.without_operations.len(),
            1,
            "the other plugin offers none"
        );
        assert!(listing.unusable.is_empty());
    }

    /// Writes the data directory the native smoke of the tools window starts from: a plugin that
    /// declares a key operation, another that declares none, a synthetic key store with its
    /// password and a small file. `ONCL_SMOKE_DIR=<dir> cargo test -p openncalayer --lib
    /// smoke_data_dir -- --ignored`.
    #[test]
    #[ignore = "writes the data directory of the native smoke (ONCL_SMOKE_DIR)"]
    fn smoke_data_dir() {
        let dir =
            std::path::PathBuf::from(std::env::var("ONCL_SMOKE_DIR").expect("ONCL_SMOKE_DIR"));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir).unwrap();
        install(
            &store,
            &example_ops(
                "0.1.0",
                &[operation("sign-file", "Sign a file", true, false)],
            ),
        );
        install(&store, &other(&[]));
        let key = oncl_testkit::synthetic("user-rsa-sign");
        std::fs::copy(key.path, dir.join("smoke-key.p12")).unwrap();
        std::fs::write(dir.join("smoke-key.password"), &key.password).unwrap();
        std::fs::write(
            dir.join("smoke-file.bin"),
            b"a synthetic file for the plugin smoke",
        )
        .unwrap();
    }

    #[test]
    fn a_plugin_that_is_off_or_withdrawn_is_not_offered() {
        let (_dir, store) = store();
        install(
            &store,
            &example_ops("0.1.0", &[operation("sign", "Sign", true, false)]),
        );
        store.set_enabled(ID, false).unwrap();
        assert!(ManualPlugins::build(&store).operations.is_empty());
        store.set_enabled(ID, true).unwrap();
        store.set_withdrawn(ID, true).unwrap();
        assert!(ManualPlugins::build(&store).operations.is_empty());
        store.set_withdrawn(ID, false).unwrap();
        assert_eq!(ManualPlugins::build(&store).operations.len(), 1);
    }

    #[test]
    fn a_package_changed_on_disk_is_skipped_not_registered() {
        let (dir, store) = store();
        install(
            &store,
            &example_ops("0.1.0", &[operation("sign", "Sign", true, false)]),
        );
        let file = std::fs::read_dir(dir.path().join("plugins").join("packages"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = std::fs::read(&file).unwrap();
        bytes.push(0);
        std::fs::write(&file, bytes).unwrap();
        let plugins = ManualPlugins::build(&store);
        assert!(plugins.operations.is_empty());
        assert_eq!(plugins.skipped.len(), 1);
        assert_eq!(plugins.skipped[0].plugin_id, ID);
        assert!(engine(plugins).plugin_identity(ID).is_none());
    }

    #[test]
    fn declared_urls_operations_are_not_offered() {
        let (_dir, store) = store();
        let urls = operation("fetch", "Fetch", false, false).replace(
            "[operations.uses]\n",
            "[operations.uses]\nnetwork = [\"https://example.invalid/\"]\n",
        );
        install(&store, &example_ops("0.1.0", &[urls]));
        let plugins = ManualPlugins::build(&store);
        assert!(plugins.operations.is_empty());
        assert!(engine(plugins).plugin_identity(ID).is_none());
    }
}
