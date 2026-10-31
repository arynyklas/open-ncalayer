//! The built-in modules embedded in the program ([`SOURCES`]), as the build script laid
//! them out: the same bytes in every flavour of a release.

use oncl_plugin::{BuiltinInfo, BuiltinSource, Builtins, Engine, LoadError};

include!(concat!(env!("OUT_DIR"), "/builtins.rs"));

/// The modules of `sources`, checked without running them (manifests, ABI): what
/// `openncalayer builtins` prints and the start checks first.
///
/// # Errors
///
/// The first module that does not load.
pub fn check(sources: &[BuiltinSource<'_>]) -> Result<Vec<BuiltinInfo>, LoadError> {
    Builtins::check(&Engine::new(), sources)
}

/// The line `openncalayer builtins` prints for `info`: `<id> <version> <sha256>`.
pub fn line(info: &BuiltinInfo) -> String {
    let sha256: String = info.sha256.iter().map(|b| format!("{b:02x}")).collect();
    format!("{} {} {sha256}", info.id, info.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
    use oncl_plugin::{BuiltinLimits, HostServices};
    use std::sync::Arc;

    fn services() -> HostServices {
        HostServices::new(
            Arc::new(ScriptedPrompter::new(Vec::<Step>::new())),
            Arc::new(MemoryRecentPath::new(None)),
            Arc::new(crate::LiveProxyTransport::new(
                oncl_desktop::ProxySetting::None,
            )),
            oncl_token::Tokens::disabled(),
        )
    }

    /// A plugin porting one bundle and one of the core's.
    struct OnePlugin;

    impl oncl_plugin::core::Bundles for OnePlugin {
        fn services(&self) -> Vec<String> {
            vec!["kz.example.Plugin".to_owned()]
        }

        fn bundles(&self) -> Vec<(String, String)> {
            vec![
                ("kz.example.echo".to_owned(), "1.0.0".to_owned()),
                ("kz.gov.pki.kalkan.xmldsig".to_owned(), "9.9.9".to_owned()),
            ]
        }

        fn request_install(&self, _: &str, _: &str) -> bool {
            false
        }
    }

    #[test]
    fn about_lists_core_bundles() {
        let plugins = crate::Plugins {
            modules: Arc::new(oncl_plugin::PluginModules::new(
                Arc::new(Engine::new()),
                services(),
                crate::builtin_modules(),
            )),
            bundles: Arc::new(OnePlugin),
        };
        let registry = crate::build_registry(services(), Arc::new(|_| {}), Some(plugins)).unwrap();
        let mut about = crate::about_bundles(&registry, &OnePlugin);
        about.sort();
        let mut expected: Vec<(String, String)> = oncl_builtin_accessory::bundles()
            .into_iter()
            .map(|(s, v)| (s.to_owned(), v.to_owned()))
            .collect();
        expected.sort();
        assert_eq!(about, expected);
        // Without plugins, the same.
        let registry = crate::build_registry(services(), Arc::new(|_| {}), None).unwrap();
        let mut about = crate::about_bundles(&registry, &crate::NoPlugins);
        about.sort();
        assert_eq!(about, expected);
    }

    #[test]
    fn builtins_load_with_this_core() {
        let services = services();
        let builtins = Builtins::load(
            &Engine::new(),
            services,
            SOURCES,
            BuiltinLimits::default(),
            None,
        )
        .unwrap();
        let loaded = builtins.loaded();
        assert_eq!(loaded.len(), SOURCES.len());
        for info in &loaded {
            assert_eq!(info.version.to_string(), env!("CARGO_PKG_VERSION"));
            for module in &info.modules {
                assert!(builtins.module(module).is_some(), "{module}");
            }
        }
        assert!(
            builtins
                .module("kz.gov.pki.ncalayerservices.accessory")
                .is_some()
        );
        assert_eq!(check(SOURCES).unwrap(), loaded);
        let line = line(&loaded[0]);
        assert!(
            line.starts_with(&format!("{} {} ", loaded[0].id, loaded[0].version)),
            "{line}"
        );
        assert_eq!(line.rsplit(' ').next().unwrap().len(), 64);
    }
}
