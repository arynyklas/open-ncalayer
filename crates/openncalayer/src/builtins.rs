//! The built-in modules embedded in the program ([`SOURCES`]), as the build script laid
//! them out: the same bytes in every flavour of a release.

use oncl_plugin::{BuiltinInfo, BuiltinSource, Builtins, Engine, LoadError};

include!(concat!(env!("OUT_DIR"), "/builtins.rs"));

/// The modules of `sources`, checked without serving anything (manifests, ABI, one
/// instance each): what `openncalayer builtins` prints and the start checks.
///
/// # Errors
///
/// The first module that does not load.
pub fn check(sources: &[BuiltinSource<'_>]) -> Result<Vec<BuiltinInfo>, LoadError> {
    Builtins::check(&Engine::new(), sources)
}

/// The line `openncalayer builtins` prints for `info`: `<id> <version> <sha256 of
/// plugin.wasm> <sha256 of plugin.toml>`.
pub fn line(info: &BuiltinInfo) -> String {
    let hex = |bytes: &[u8; 32]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    format!(
        "{} {} {} {}",
        info.id,
        info.version,
        hex(&info.sha256),
        hex(&info.manifest_sha256)
    )
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
        for module in [
            "kz.gov.pki.ncalayerservices.accessory",
            "kz.gov.pki.knca.basics",
            "kz.gov.pki.knca.commonUtils",
            "kz.gov.pki.knca.applet.Applet",
        ] {
            assert!(builtins.module(module).is_some(), "{module}");
        }
        assert_eq!(check(SOURCES).unwrap(), loaded);
        let line = line(&loaded[0]);
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 4, "{line}");
        assert_eq!(fields[0], loaded[0].id);
        assert_eq!(fields[1], loaded[0].version.to_string());
        assert_eq!(fields[2].len(), 64);
        assert_eq!(fields[3].len(), 64);
        assert_ne!(fields[2], fields[3], "the code's and the manifest's");
    }
}
