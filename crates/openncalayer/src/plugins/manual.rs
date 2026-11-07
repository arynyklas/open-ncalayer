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
use oncl_plugin::{InstanceLimits, Localized, NCA_PKI_HOSTS, Store};
use tracing::warn;

use super::Version;

/// The caller the manual window's permissions are issued to.
pub const MANUAL_CALLER: &str = "manual-window";

/// The caller of the manual window: the local operator, never a page.
pub fn manual_caller() -> CallerContext {
    CallerContext::LocalOperator(MANUAL_CALLER.to_owned())
}

/// The exact PKI endpoints an operation with `network = "pki"` may use: the NCA's own
/// time-stamp and OCSP services (what `PkiUrl::Default` names). CRLs are fetched under the
/// provenance of the certificate, not from this list.
const PKI_ENDPOINTS: [(HttpMethod, &str); 2] = [
    (HttpMethod::Post, "http://tsp.pki.gov.kz"),
    (HttpMethod::Post, "http://ocsp.pki.gov.kz"),
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
}

impl ManualPlugins {
    /// Builds the registry from the installed plugins of `store`.
    pub fn build(store: &Store) -> ManualPlugins {
        let mut out = ManualPlugins {
            registry: PluginRegistry::new(),
            operations: Vec::new(),
            skipped: Vec::new(),
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
        for op in ops {
            let endpoints: &[(HttpMethod, &str)] = if matches!(op.uses().network(), Network::Pki) {
                &PKI_ENDPOINTS
            } else {
                &[]
            };
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
