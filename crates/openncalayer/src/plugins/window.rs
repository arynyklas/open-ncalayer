//! The plugins in the daemon's windows: the plugin window's services over the
//! [`PluginService`] ([`WindowServices`]), and the user asked in the install confirmation
//! ([`WindowInstallUi`]).

use std::path::PathBuf;
use std::sync::Arc;

use oncl_plugin::{Capabilities, Localized, Replaces, Source};
use oncl_ui::plugins_view::{
    AvailablePlugin, CapabilityLine, CatalogLine, InstalledPlugin, LocalizedText, PluginStatus,
    ReplacedBundle,
};
use oncl_ui::{InstallPluginRequest, PluginActionError, PluginsServices, PluginsView};

use super::{CatalogView, InstallRequest, InstallUi, PluginService, PluginState, ServiceView};

/// Asks the user in the install confirmation window ([`oncl_ui::ask_install_plugin`]).
pub struct WindowInstallUi;

impl InstallUi for WindowInstallUi {
    fn confirm(&self, request: InstallRequest, decide: Box<dyn FnOnce(bool) + Send>) {
        oncl_ui::ask_install_plugin(install_request(request, decide));
    }
}

/// `request` as the confirmation window shows it.
pub fn install_request(
    request: InstallRequest,
    decide: Box<dyn FnOnce(bool) + Send>,
) -> InstallPluginRequest {
    InstallPluginRequest {
        origin: request.origin,
        name: text(&request.name),
        version: request.version.to_string(),
        replaces: request.replaces.as_ref().map(bundle),
        capabilities: capability_lines(&request.capabilities),
        local: request.local,
        decide,
    }
}

fn capability_lines(capabilities: &Capabilities) -> Vec<CapabilityLine> {
    let mut lines = Vec::new();
    if capabilities.keys {
        lines.push(CapabilityLine::Keys);
    }
    if capabilities.dialogs {
        lines.push(CapabilityLine::Dialogs);
    }
    if capabilities.files {
        lines.push(CapabilityLine::Files);
    }
    if !capabilities.http.is_empty() {
        lines.push(CapabilityLine::Http(
            capabilities.http.iter().map(ToString::to_string).collect(),
        ));
    }
    lines
}

/// The plugin window's services: the plugins of `service`, or, if they could not start,
/// why (the window says so and does nothing else).
pub struct WindowServices(pub Result<Arc<PluginService>, String>);

impl PluginsServices for WindowServices {
    fn view(&self) -> PluginsView {
        match &self.0 {
            Ok(service) => plugins_view(service.view()),
            Err(e) => PluginsView {
                catalog: CatalogLine::Off(e.clone()),
                installed: Vec::new(),
                available: Vec::new(),
            },
        }
    }

    fn install(&self, id: &str) -> Result<(), PluginActionError> {
        self.service()?.install_from_catalog(id, None)
    }

    fn install_file(&self, path: PathBuf) -> Result<(), PluginActionError> {
        self.service()?.install_from_file(path)
    }

    fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), PluginActionError> {
        self.service()?.set_enabled(id, enabled)
    }

    fn remove(&self, id: &str) -> Result<(), PluginActionError> {
        self.service()?.remove(id)
    }

    fn refresh(&self) {
        if let Ok(service) = &self.0 {
            service.check_now();
        }
    }
}

impl WindowServices {
    /// The service, or why the plugins are off.
    fn service(&self) -> Result<&Arc<PluginService>, PluginActionError> {
        self.0
            .as_ref()
            .map_err(|e| PluginActionError::Failed(e.clone()))
    }
}

/// `view` as the plugin window shows it.
pub fn plugins_view(view: ServiceView) -> PluginsView {
    PluginsView {
        catalog: match view.catalog {
            CatalogView::Unavailable => CatalogLine::Unavailable,
            CatalogView::Ready {
                channel,
                generated,
                error,
                ..
            } => CatalogLine::Ready {
                channel: channel.to_string(),
                generated,
                error,
            },
            CatalogView::Missing { channel, error } => CatalogLine::Missing {
                channel: channel.to_string(),
                error,
            },
        },
        installed: view
            .installed
            .into_iter()
            .map(|p| InstalledPlugin {
                name: text(&p.name),
                version: p.version.to_string(),
                replaces: p.replaces.as_ref().map(bundle),
                local: p.source == Source::Local,
                state: match p.state {
                    PluginState::Enabled => PluginStatus::Enabled,
                    PluginState::Disabled => PluginStatus::Disabled,
                    PluginState::Withdrawn => PluginStatus::Withdrawn,
                    PluginState::Error(e) => PluginStatus::Error(e),
                },
                id: p.id,
            })
            .collect(),
        available: view
            .available
            .into_iter()
            .map(|p| AvailablePlugin {
                name: text(&p.name),
                version: p.version.to_string(),
                replaces: p.replaces.as_ref().map(bundle),
                needed: p.needed_by.is_some(),
                needed_by: p.needed_by.flatten(),
                id: p.id,
            })
            .collect(),
    }
}

fn text(name: &Localized) -> LocalizedText {
    LocalizedText {
        ru: name.ru.clone(),
        kk: name.kk.clone(),
        en: name.en.clone(),
    }
}

fn bundle(replaces: &Replaces) -> ReplacedBundle {
    ReplacedBundle {
        symname: replaces.symname.clone(),
        version: replaces.version.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{AvailableView, InstalledView};
    use oncl_plugin::HttpPrefix;
    use oncl_update::{Channel, Version};
    use time::macros::datetime;

    fn name() -> Localized {
        Localized {
            ru: "Пример".to_owned(),
            kk: "Үлгі".to_owned(),
            en: "Example".to_owned(),
        }
    }

    #[test]
    fn the_request_lists_what_the_plugin_may_do() {
        let request = InstallRequest {
            origin: Some("https://shop.kz".to_owned()),
            name: name(),
            version: Version::new(1, 2, 3),
            replaces: Some(Replaces {
                symname: "kz.example.echo".to_owned(),
                version: "1.0.0".to_owned(),
            }),
            capabilities: Capabilities {
                keys: true,
                dialogs: false,
                files: true,
                http: vec![
                    "https://a.kz/api/".parse::<HttpPrefix>().unwrap(),
                    "https://b.kz:8443/".parse::<HttpPrefix>().unwrap(),
                ],
                key_files: false,
            },
            local: true,
        };
        let shown = install_request(request, Box::new(|_| {}));
        assert_eq!(shown.origin.as_deref(), Some("https://shop.kz"));
        assert_eq!(shown.name.kk, "Үлгі");
        assert_eq!(shown.version, "1.2.3");
        assert_eq!(shown.replaces.unwrap().symname, "kz.example.echo");
        assert_eq!(
            shown.capabilities,
            [
                CapabilityLine::Keys,
                CapabilityLine::Files,
                CapabilityLine::Http(vec![
                    "https://a.kz/api/".to_owned(),
                    "https://b.kz:8443/".to_owned()
                ]),
            ]
        );
        assert!(shown.local);
    }

    #[test]
    fn the_view_maps_to_the_window() {
        let generated = datetime!(2026-10-29 10:00 UTC);
        let view = ServiceView {
            catalog: CatalogView::Ready {
                channel: Channel::Beta,
                generated,
                checked: None,
                error: Some("timed out".to_owned()),
            },
            installed: vec![
                InstalledView {
                    id: "kz.a".to_owned(),
                    name: name(),
                    version: Version::new(1, 0, 0),
                    replaces: None,
                    source: Source::Local,
                    state: PluginState::Error("broken".to_owned()),
                },
                InstalledView {
                    id: "kz.b".to_owned(),
                    name: name(),
                    version: Version::new(2, 0, 0),
                    replaces: None,
                    source: Source::Catalog,
                    state: PluginState::Withdrawn,
                },
            ],
            available: vec![
                AvailableView {
                    id: "kz.c".to_owned(),
                    name: name(),
                    version: Version::new(3, 0, 0),
                    replaces: None,
                    needed_by: Some(None),
                },
                AvailableView {
                    id: "kz.d".to_owned(),
                    name: name(),
                    version: Version::new(4, 0, 0),
                    replaces: None,
                    needed_by: None,
                },
            ],
        };
        let shown = plugins_view(view);
        assert_eq!(
            shown.catalog,
            CatalogLine::Ready {
                channel: "beta".to_owned(),
                generated,
                error: Some("timed out".to_owned()),
            }
        );
        assert!(shown.installed[0].local);
        assert_eq!(
            shown.installed[0].state,
            PluginStatus::Error("broken".to_owned())
        );
        assert!(!shown.installed[1].local);
        assert_eq!(shown.installed[1].state, PluginStatus::Withdrawn);
        assert!(shown.available[0].needed && shown.available[0].needed_by.is_none());
        assert!(!shown.available[1].needed);
        // Plugins that could not start: the window says why.
        let off = WindowServices(Err("access denied".to_owned()));
        assert_eq!(
            off.view().catalog,
            CatalogLine::Off("access denied".to_owned())
        );
        assert_eq!(
            off.remove("kz.a"),
            Err(PluginActionError::Failed("access denied".to_owned()))
        );
    }
}
