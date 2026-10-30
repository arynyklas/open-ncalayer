//! What the tray tells the user: its warning (wss off, the original NCALayer holding the
//! port, the certificate due or not renewed), whether it offers «Остановить оригинал…», and
//! its notifications (wss off at the start, the certificate's renewal, a page's
//! `installBundle`, the updates, the plugins), in the user's language.

use std::time::{Duration, Instant};

use oncl_basics::Locale;
use oncl_desktop::PortOwner;
use oncl_ui::settings_view::{UpdateStatus, update_view};
use oncl_ui::view::page_text;
use oncl_ui::{ActionTarget, Notification, NotificationAction, TrayCommand, TrayState};

use crate::cli::WssOff;
use crate::plugins::PluginNotice;
use crate::renewal::{RenewFailure, RenewalCheck};
use crate::update::Notice;

/// The project site (`site/config.toml`'s `base_url`).
pub const SITE: &str = "https://arynyklas.github.io/open-ncalayer";

/// The plugin catalog of the site in `l`, at the row of the bundle `symname` when it is a
/// symbolic name (otherwise at the top).
pub fn plugin_registry(l: Locale, symname: &str) -> String {
    let lang = match l {
        Locale::Ru => "",
        Locale::Kk => "/kk",
        Locale::En => "/en",
    };
    if oncl_plugin::is_symbolic_name(symname) {
        format!("{SITE}{lang}/plugins/#{symname}")
    } else {
        format!("{SITE}{lang}/plugins/")
    }
}

/// A page asking for bundles again and again is told about the registry at most this often.
const BUNDLE_NOTICE_EVERY: Duration = Duration::from_secs(10 * 60);
/// Pages needing plugins of the catalog are told about at most this often.
const NEEDED_NOTICE_EVERY: Duration = Duration::from_secs(10 * 60);

/// The tray's state of the daemon.
#[derive(Debug)]
pub struct TrayStatus {
    pub locale: Locale,
    /// Why the wss server is off.
    pub wss_off: Option<WssOff>,
    /// The original NCALayer found holding the port while it is busy.
    pub original: Option<PortOwner>,
    /// The last renewal check.
    pub renewal: RenewalCheck,
    last_bundle_notice: Option<Instant>,
    last_needed_notice: Option<Instant>,
}

impl TrayStatus {
    pub fn new(locale: Locale, wss_off: Option<WssOff>) -> Self {
        TrayStatus {
            locale,
            wss_off,
            original: None,
            renewal: RenewalCheck::Nothing,
            last_bundle_notice: None,
            last_needed_notice: None,
        }
    }

    /// What the tray shows: the warning, and «Остановить оригинал…» while the original
    /// holds the port.
    pub fn tray_state(&self) -> TrayState {
        TrayState {
            warning: self.warning(),
            stop_original: self.original_on_port().is_some(),
        }
    }

    /// The original NCALayer holding the port wss needs, if that is why wss is off.
    pub fn original_on_port(&self) -> Option<&PortOwner> {
        match self.wss_off {
            Some(WssOff::PortBusy(_)) => self.original.as_ref(),
            _ => None,
        }
    }

    /// The warning the tray shows: wss being off comes first, then the certificate's.
    pub fn warning(&self) -> Option<String> {
        if self.original_on_port().is_some() {
            return Some(original_text(self.locale).to_owned());
        }
        match self.wss_off {
            Some(off) => Some(off.text(self.locale)),
            None => self.renewal_warning(),
        }
    }

    /// The notification of wss being off at the start, if the user can lift it here: TLS
    /// not set up (leads to the wizard), the port held by the original (leads to
    /// «Остановить оригинал…»).
    pub fn wss_off_notification(&self) -> Option<Notification> {
        let l = self.locale;
        let (body, action) = if self.original_on_port().is_some() {
            (
                match l {
                    Locale::Ru => {
                        "Пока оригинал работает, сайты подключаются к нему, а не к OpenNCALayer. Его можно остановить из меню значка."
                    }
                    Locale::Kk => {
                        "Түпнұсқа жұмыс істеп тұрғанда сайттар OpenNCALayer-ге емес, соған қосылады. Оны белгіше мәзірінен тоқтатуға болады."
                    }
                    Locale::En => {
                        "While the original runs, sites connect to it rather than to OpenNCALayer. It can be stopped from the icon's menu."
                    }
                },
                NotificationAction {
                    label: match l {
                        Locale::Ru => "Остановить оригинал…",
                        Locale::Kk => "Түпнұсқаны тоқтату…",
                        Locale::En => "Stop the original…",
                    }
                    .to_owned(),
                    target: ActionTarget::Command(TrayCommand::StopOriginal),
                },
            )
        } else if self.wss_off == Some(WssOff::TlsNotConfigured) {
            (
                match l {
                    Locale::Ru => {
                        "Сайты не подключатся к OpenNCALayer, пока не выпущен сертификат для браузера; расширение браузера уже работает. Выпустите сертификат в мастере."
                    }
                    Locale::Kk => {
                        "Браузерге арналған сертификат шығарылмайынша сайттар OpenNCALayer-ге қосылмайды; браузер кеңейтімі жұмыс істеп тұр. Сертификатты шеберде шығарыңыз."
                    }
                    Locale::En => {
                        "Sites cannot connect to OpenNCALayer until a certificate for browsers is issued; the browser extension works already. Issue the certificate in the wizard."
                    }
                },
                wizard_action(l),
            )
        } else {
            return None;
        };
        Some(Notification {
            title: self.warning()?,
            body: body.to_owned(),
            action: Some(action),
        })
    }

    /// The notification of «Остановить оригинал…» finding the original no longer on
    /// `port`: whether wss took the port (`wss_off` as it is now), or another program
    /// holds it.
    pub fn original_gone_notification(&self, port: u16) -> Notification {
        let l = self.locale;
        let title = match l {
            Locale::Ru => "Оригинальный NCALayer уже не держит порт",
            Locale::Kk => "Түпнұсқа NCALayer портты енді алып тұрған жоқ",
            Locale::En => "The original NCALayer no longer holds the port",
        };
        let body = match (self.wss_off, l) {
            (None, Locale::Ru) => format!(
                "Ничего не остановлено. OpenNCALayer принимает подключения сайтов на порту {port}."
            ),
            (None, Locale::Kk) => format!(
                "Ештеңе тоқтатылмады. OpenNCALayer сайттардың қосылуларын {port} портында қабылдайды."
            ),
            (None, Locale::En) => format!(
                "Nothing was stopped. OpenNCALayer accepts the sites' connections on port {port}."
            ),
            (Some(_), Locale::Ru) => format!(
                "Ничего не остановлено. Порт {port} занят другой программой, поэтому OpenNCALayer не принимает подключения сайтов."
            ),
            (Some(_), Locale::Kk) => format!(
                "Ештеңе тоқтатылмады. {port} портын басқа бағдарлама алып тұр, сондықтан OpenNCALayer сайттардың қосылуларын қабылдамайды."
            ),
            (Some(_), Locale::En) => format!(
                "Nothing was stopped. Another program holds port {port}, so OpenNCALayer does not accept the sites' connections."
            ),
        };
        Notification {
            title: title.to_owned(),
            body,
            action: None,
        }
    }

    /// What the last renewal check warns about, if anything.
    fn renewal_warning(&self) -> Option<String> {
        let l = self.locale;
        let days = |days: i64| days.max(0).to_string();
        match &self.renewal {
            RenewalCheck::Nothing | RenewalCheck::Renewed { .. } => None,
            RenewalCheck::Due { expired: true, .. } => Some(
                match l {
                    Locale::Ru => "Сертификат для браузера истёк",
                    Locale::Kk => "Браузерге арналған сертификаттың мерзімі аяқталды",
                    Locale::En => "The certificate for browsers has expired",
                }
                .to_owned(),
            ),
            RenewalCheck::Due { days: 0, .. } => Some(
                match l {
                    Locale::Ru => "Сертификат для браузера истекает сегодня",
                    Locale::Kk => "Браузерге арналған сертификаттың мерзімі бүгін аяқталады",
                    Locale::En => "The certificate for browsers expires today",
                }
                .to_owned(),
            ),
            RenewalCheck::Due { days: d, .. } => Some(match l {
                Locale::Ru => format!("Сертификат для браузера истекает через {} дн.", days(*d)),
                Locale::Kk => format!(
                    "Браузерге арналған сертификаттың мерзімі {} күннен кейін аяқталады",
                    days(*d)
                ),
                Locale::En => format!("The certificate for browsers expires in {} days", days(*d)),
            }),
            RenewalCheck::RenewFailed { days: d, .. } => Some(match l {
                Locale::Ru => format!(
                    "Сертификат для браузера не перевыпущен (истекает через {} дн.)",
                    days(*d)
                ),
                Locale::Kk => format!(
                    "Браузерге арналған сертификат қайта шығарылмады ({} күннен кейін аяқталады)",
                    days(*d)
                ),
                Locale::En => format!(
                    "The certificate for browsers was not re-issued (expires in {} days)",
                    days(*d)
                ),
            }),
        }
    }

    /// The notification of a renewal check, if it has one. Its title is the renewal's own,
    /// whatever else the tray warns about.
    pub fn renewal_notification(&self) -> Option<Notification> {
        let l = self.locale;
        let wizard = || wizard_action(l);
        let (title, body, action) = match &self.renewal {
            RenewalCheck::Nothing => return None,
            RenewalCheck::Due { .. } => (
                self.renewal_warning()?,
                match l {
                    Locale::Ru => "Перевыпустите сертификат в мастере, иначе сайты перестанут подключаться к OpenNCALayer.",
                    Locale::Kk => "Сертификатты шеберде қайта шығарыңыз, әйтпесе сайттар OpenNCALayer-ге қосыла алмайды.",
                    Locale::En => "Re-issue the certificate in the wizard, or sites stop connecting to OpenNCALayer.",
                }
                .to_owned(),
                Some(wizard()),
            ),
            RenewalCheck::Renewed { not_after } => (
                match l {
                    Locale::Ru => "Сертификат для браузера перевыпущен",
                    Locale::Kk => "Браузерге арналған сертификат қайта шығарылды",
                    Locale::En => "The certificate for browsers is re-issued",
                }
                .to_owned(),
                match l {
                    Locale::Ru => format!("OpenNCALayer выпустил новый сертификат центром mkcert; он действует до {}.", date(not_after)),
                    Locale::Kk => format!("OpenNCALayer mkcert орталығымен жаңа сертификат шығарды; ол {} дейін жарамды.", date(not_after)),
                    Locale::En => format!("OpenNCALayer issued a new certificate with the mkcert CA; it is valid until {}.", date(not_after)),
                },
                None,
            ),
            RenewalCheck::RenewFailed { failure, .. } => (
                self.renewal_warning()?,
                failure_text(failure, l),
                Some(wizard()),
            ),
        };
        Some(Notification {
            title,
            body,
            action,
        })
    }

    /// The notification of a page's `installBundle` of `symname` that the catalog offers
    /// nothing to install for (no port, one installed already — maybe turned off or
    /// withdrawn —, or no catalog), unless one was shown within the last ten minutes (at
    /// `now`). `origin` and `symname` come from the page: control characters go, and each is
    /// cut to [`MAX_PAGE_TEXT`](oncl_ui::view::MAX_PAGE_TEXT) characters.
    pub fn bundle_notification(
        &mut self,
        symname: &str,
        origin: &str,
        now: Instant,
    ) -> Option<Notification> {
        if self
            .last_bundle_notice
            .is_some_and(|last| now.duration_since(last) < BUNDLE_NOTICE_EVERY)
        {
            return None;
        }
        self.last_bundle_notice = Some(now);
        let l = self.locale;
        let registry = plugin_registry(l, symname);
        let (symname, origin) = (page_text(symname), page_text(origin));
        Some(Notification {
            title: match l {
                Locale::Ru => "Сайт просит установить модуль",
                Locale::Kk => "Сайт модуль орнатуды сұрайды",
                Locale::En => "A site asks to install a module",
            }
            .to_owned(),
            body: match l {
                Locale::Ru => format!(
                    "Сайт {origin} запросил модуль {symname}. Каталог OpenNCALayer не предлагает его установить: его там нет или он уже установлен."
                ),
                Locale::Kk => format!(
                    "{origin} сайты {symname} модулін сұрады. OpenNCALayer каталогы оны орнатуды ұсынбайды: ол онда жоқ немесе орнатылып қойған."
                ),
                Locale::En => format!(
                    "The site {origin} asked for the module {symname}. The OpenNCALayer catalog offers nothing to install: it does not have it, or it is installed already."
                ),
            },
            action: Some(NotificationAction {
                label: match l {
                    Locale::Ru => "Реестр плагинов",
                    Locale::Kk => "Плагиндер тізілімі",
                    Locale::En => "Plugin registry",
                }
                .to_owned(),
                target: ActionTarget::Url(registry),
            }),
        })
    }

    /// The notification of a plugin `notice` (at `now`); a page's need of a plugin
    /// ([`PluginNotice::Needed`]) only if none was told within the last ten minutes.
    pub fn plugin_notification(
        &mut self,
        notice: &PluginNotice,
        now: Instant,
    ) -> Option<Notification> {
        let l = self.locale;
        let (title, body, action) = match notice {
            PluginNotice::Installed { name } => {
                let name = name.get(l);
                (
                    match l {
                        Locale::Ru => "Плагин установлен",
                        Locale::Kk => "Плагин орнатылды",
                        Locale::En => "Plugin installed",
                    }
                    .to_owned(),
                    match l {
                        Locale::Ru => format!("Плагин «{name}» установлен."),
                        Locale::Kk => format!("«{name}» плагині орнатылды."),
                        Locale::En => format!("The plugin «{name}» is installed."),
                    },
                    None,
                )
            }
            PluginNotice::Updated { name, version } => {
                let name = name.get(l);
                (
                    match l {
                        Locale::Ru => "Плагин обновлён",
                        Locale::Kk => "Плагин жаңартылды",
                        Locale::En => "Plugin updated",
                    }
                    .to_owned(),
                    match l {
                        Locale::Ru => format!("Плагин «{name}» обновлён до версии {version}."),
                        Locale::Kk => format!("«{name}» плагині {version} нұсқасына жаңартылды."),
                        Locale::En => {
                            format!("The plugin «{name}» is updated to version {version}.")
                        }
                    },
                    None,
                )
            }
            PluginNotice::Withdrawn { name } => {
                let name = name.get(l);
                (
                    match l {
                        Locale::Ru => "Плагин выключен",
                        Locale::Kk => "Плагин өшірілді",
                        Locale::En => "Plugin turned off",
                    }
                    .to_owned(),
                    match l {
                        Locale::Ru => format!(
                            "Версия плагина «{name}» отозвана в каталоге OpenNCALayer, а замены нет: плагин выключен."
                        ),
                        Locale::Kk => format!(
                            "«{name}» плагинінің нұсқасы OpenNCALayer каталогында кері қайтарылды, ал оны алмастыратын нұсқа жоқ: плагин өшірілді."
                        ),
                        Locale::En => format!(
                            "The version of the plugin «{name}» is revoked in the OpenNCALayer catalog, with nothing to replace it: the plugin is turned off."
                        ),
                    },
                    None,
                )
            }
            PluginNotice::Failed { name, error } => (
                match l {
                    Locale::Ru => "Ошибка плагина",
                    Locale::Kk => "Плагин қатесі",
                    Locale::En => "Plugin error",
                }
                .to_owned(),
                format!("«{}»: {error}", name.get(l)),
                None,
            ),
            PluginNotice::UpdateNeedsConfirmation { name, version } => {
                let name = name.get(l);
                (
                    match l {
                        Locale::Ru => "Обновление плагина ждёт разрешения",
                        Locale::Kk => "Плагин жаңартуы рұқсат күтеді",
                        Locale::En => "A plugin update waits for permission",
                    }
                    .to_owned(),
                    match l {
                        Locale::Ru => format!(
                            "Версия {version} плагина «{name}» сможет больше, чем установленная. Установленная работает, пока вы не разрешите обновление в окне «Плагины»."
                        ),
                        Locale::Kk => format!(
                            "«{name}» плагинінің {version} нұсқасы орнатылғаннан көп нәрсе істей алады. «Плагиндер» терезесінде жаңартуға рұқсат бермейінше, орнатылған нұсқа жұмыс істей береді."
                        ),
                        Locale::En => format!(
                            "Version {version} of the plugin «{name}» can do more than the installed one. The installed one runs until you allow the update in the Plugins window."
                        ),
                    },
                    Some(NotificationAction {
                        label: match l {
                            Locale::Ru => "Плагины…",
                            Locale::Kk => "Плагиндер…",
                            Locale::En => "Plugins…",
                        }
                        .to_owned(),
                        target: ActionTarget::Command(TrayCommand::Plugins),
                    }),
                )
            }
            PluginNotice::Needed { origin, name, .. } => {
                let origin = origin.as_deref().map(page_text);
                if self
                    .last_needed_notice
                    .is_some_and(|last| now.duration_since(last) < NEEDED_NOTICE_EVERY)
                {
                    return None;
                }
                self.last_needed_notice = Some(now);
                let name = name.get(l);
                (
                    match l {
                        Locale::Ru => "Сайту нужен плагин",
                        Locale::Kk => "Сайтқа плагин қажет",
                        Locale::En => "A site needs a plugin",
                    }
                    .to_owned(),
                    match (l, origin) {
                        (Locale::Ru, Some(origin)) => format!(
                            "Сайту {origin} нужен плагин «{name}» из каталога OpenNCALayer."
                        ),
                        (Locale::Ru, None) => {
                            format!("Сайту нужен плагин «{name}» из каталога OpenNCALayer.")
                        }
                        (Locale::Kk, Some(origin)) => format!(
                            "{origin} сайтына OpenNCALayer каталогындағы «{name}» плагині қажет."
                        ),
                        (Locale::Kk, None) => {
                            format!("Сайтқа OpenNCALayer каталогындағы «{name}» плагині қажет.")
                        }
                        (Locale::En, Some(origin)) => format!(
                            "The site {origin} needs the plugin «{name}» from the OpenNCALayer catalog."
                        ),
                        (Locale::En, None) => format!(
                            "A site needs the plugin «{name}» from the OpenNCALayer catalog."
                        ),
                    },
                    Some(NotificationAction {
                        label: match l {
                            Locale::Ru => "Установить…",
                            Locale::Kk => "Орнату…",
                            Locale::En => "Install…",
                        }
                        .to_owned(),
                        target: ActionTarget::Command(TrayCommand::Plugins),
                    }),
                )
            }
        };
        Some(Notification {
            title,
            body,
            action,
        })
    }

    /// The notification of an update `notice`; none for a check that has not run.
    pub fn update_notification(&self, notice: &Notice) -> Option<Notification> {
        let l = self.locale;
        let (title, body, action) = match notice {
            Notice::Checked(UpdateStatus::NotChecked) => return None,
            Notice::Checked(UpdateStatus::Available {
                version,
                installing,
            }) => (
                match l {
                    Locale::Ru => format!("Доступна версия {version}"),
                    Locale::Kk => format!("{version} нұсқасы қолжетімді"),
                    Locale::En => format!("Version {version} is available"),
                },
                if *installing {
                    match l {
                        Locale::Ru => "OpenNCALayer установит её сам, когда не будет идти подпись, и перезапустится.",
                        Locale::Kk => "OpenNCALayer оны қол қою жүрмеген кезде өзі орнатып, қайта іске қосылады.",
                        Locale::En => "OpenNCALayer installs it by itself when no signing is in progress, and restarts.",
                    }
                } else {
                    match l {
                        Locale::Ru => "Автоматическое обновление выключено: включите его в настройках.",
                        Locale::Kk => "Автоматты жаңарту өшірулі: оны баптауларда қосыңыз.",
                        Locale::En => "Automatic updates are off: turn them on in the settings.",
                    }
                }
                .to_owned(),
                (!*installing).then(|| settings_action(l)),
            ),
            Notice::Checked(UpdateStatus::UpToDate) => (
                match l {
                    Locale::Ru => "Обновлений нет",
                    Locale::Kk => "Жаңартулар жоқ",
                    Locale::En => "No updates",
                }
                .to_owned(),
                match l {
                    Locale::Ru => "Установлена последняя версия OpenNCALayer.",
                    Locale::Kk => "OpenNCALayer-дің соңғы нұсқасы орнатылған.",
                    Locale::En => "The latest version of OpenNCALayer is installed.",
                }
                .to_owned(),
                None,
            ),
            Notice::Checked(unpublished @ UpdateStatus::NotPublished(_)) => (
                match l {
                    Locale::Ru => "Обновлений нет",
                    Locale::Kk => "Жаңартулар жоқ",
                    Locale::En => "No updates",
                }
                .to_owned(),
                update_view(unpublished, l),
                None,
            ),
            Notice::Checked(failed @ UpdateStatus::InstallFailed { .. }) => (
                match l {
                    Locale::Ru => "Не удалось обновить OpenNCALayer",
                    Locale::Kk => "OpenNCALayer жаңарту мүмкін болмады",
                    Locale::En => "Cannot update OpenNCALayer",
                }
                .to_owned(),
                update_view(failed, l),
                None,
            ),
            Notice::Checked(UpdateStatus::Failed(e)) => (
                match l {
                    Locale::Ru => "Не удалось проверить обновления",
                    Locale::Kk => "Жаңартуларды тексеру мүмкін болмады",
                    Locale::En => "Cannot check for updates",
                }
                .to_owned(),
                e.clone(),
                None,
            ),
            Notice::Checked(
                off @ (UpdateStatus::NotInstalled
                | UpdateStatus::PackageManaged(_)
                | UpdateStatus::NoKeys),
            ) => (
                match l {
                    Locale::Ru => "Обновления недоступны",
                    Locale::Kk => "Жаңартулар қолжетімсіз",
                    Locale::En => "Updates are unavailable",
                }
                .to_owned(),
                update_view(off, l),
                None,
            ),
            Notice::Updated(version) => (
                match l {
                    Locale::Ru => format!("Обновлено до {version}"),
                    Locale::Kk => format!("{version} нұсқасына жаңартылды"),
                    Locale::En => format!("Updated to {version}"),
                },
                match l {
                    Locale::Ru => format!("OpenNCALayer обновлён до версии {version}."),
                    Locale::Kk => format!("OpenNCALayer {version} нұсқасына жаңартылды."),
                    Locale::En => format!("OpenNCALayer is updated to version {version}."),
                },
                None,
            ),
            Notice::NoRollback { failed, version } => (
                match l {
                    Locale::Ru => format!("Версия {failed} работает с ошибками"),
                    Locale::Kk => format!("{failed} нұсқасы қатемен жұмыс істейді"),
                    Locale::En => format!("Version {failed} does not work properly"),
                },
                match l {
                    Locale::Ru => format!(
                        "Версия {failed} не запустилась как следует, а вернуть версию {version} нельзя: её нет в индексе обновлений. OpenNCALayer установит исправленную версию, когда она выйдет."
                    ),
                    Locale::Kk => format!(
                        "{failed} нұсқасы дұрыс іске қосылмады, ал {version} нұсқасын қайтару мүмкін емес: ол жаңартулар индексінде жоқ. OpenNCALayer түзетілген нұсқа шыққанда оны орнатады."
                    ),
                    Locale::En => format!(
                        "Version {failed} did not start properly, and version {version} cannot be put back: the update index no longer has it. OpenNCALayer installs a fixed version once one is out."
                    ),
                },
                None,
            ),
            Notice::RollbackFailed { failed, version } => (
                match l {
                    Locale::Ru => format!("Версия {failed} работает с ошибками"),
                    Locale::Kk => format!("{failed} нұсқасы қатемен жұмыс істейді"),
                    Locale::En => format!("Version {failed} does not work properly"),
                },
                match l {
                    Locale::Ru => format!(
                        "Версия {failed} не запустилась как следует, а вернуть версию {version} не удалось. OpenNCALayer установит исправленную версию, когда она выйдет."
                    ),
                    Locale::Kk => format!(
                        "{failed} нұсқасы дұрыс іске қосылмады, ал {version} нұсқасын қайтару мүмкін болмады. OpenNCALayer түзетілген нұсқа шыққанда оны орнатады."
                    ),
                    Locale::En => format!(
                        "Version {failed} did not start properly, and version {version} could not be put back. OpenNCALayer installs a fixed version once one is out."
                    ),
                },
                None,
            ),
            Notice::RolledBack { failed, version } => (
                match l {
                    Locale::Ru => "Обновление откачено",
                    Locale::Kk => "Жаңарту кері қайтарылды",
                    Locale::En => "The update is rolled back",
                }
                .to_owned(),
                match l {
                    Locale::Ru => format!(
                        "Версия {failed} не запустилась как следует, возвращена версия {version}. Версия {failed} больше не будет предлагаться."
                    ),
                    Locale::Kk => format!(
                        "{failed} нұсқасы дұрыс іске қосылмады, {version} нұсқасы қайтарылды. {failed} нұсқасы енді ұсынылмайды."
                    ),
                    Locale::En => format!(
                        "Version {failed} did not start properly; version {version} is back. Version {failed} will not be offered again."
                    ),
                },
                None,
            ),
        };
        Some(Notification {
            title,
            body,
            action,
        })
    }
}

/// The warning while the original NCALayer holds the port, in `l`.
fn original_text(l: Locale) -> &'static str {
    match l {
        Locale::Ru => "Порт занят оригинальным NCALayer",
        Locale::Kk => "Портты түпнұсқа NCALayer алып тұр",
        Locale::En => "The port is held by the original NCALayer",
    }
}

/// A notification's button that opens the TLS wizard, in `l`.
fn wizard_action(l: Locale) -> NotificationAction {
    NotificationAction {
        label: match l {
            Locale::Ru => "Открыть «Сертификат для браузера»",
            Locale::Kk => "«Браузерге арналған сертификат» ашу",
            Locale::En => "Open «Certificate for browsers»",
        }
        .to_owned(),
        target: ActionTarget::Command(TrayCommand::TlsWizard),
    }
}

/// A notification's button that opens the settings, in `l`.
fn settings_action(l: Locale) -> NotificationAction {
    NotificationAction {
        label: match l {
            Locale::Ru => "Открыть настройки",
            Locale::Kk => "Баптауларды ашу",
            Locale::En => "Open the settings",
        }
        .to_owned(),
        target: ActionTarget::Command(TrayCommand::Settings),
    }
}

/// What a failed mkcert re-issue means for the user, in `l`.
fn failure_text(failure: &RenewFailure, l: Locale) -> String {
    let e = failure.detail();
    match (failure, l) {
        (RenewFailure::Mkcert(_), Locale::Ru) => {
            format!("Ключ центра mkcert недоступен ({e}). Прежний сертификат пока работает.")
        }
        (RenewFailure::Mkcert(_), Locale::Kk) => format!(
            "mkcert орталығының кілті қолжетімсіз ({e}). Бұрынғы сертификат әзірге жұмыс істейді."
        ),
        (RenewFailure::Mkcert(_), Locale::En) => {
            format!("The mkcert CA key cannot be used ({e}). The previous certificate still works.")
        }
        (RenewFailure::CaChanged(_), Locale::Ru) => format!(
            "Центр mkcert сменился ({e}): текущий сертификат выпущен другим центром, и ключ нового OpenNCALayer не читал. Прежний сертификат пока работает; запустите мастер TLS заново."
        ),
        (RenewFailure::CaChanged(_), Locale::Kk) => format!(
            "mkcert орталығы ауысты ({e}): ағымдағы сертификатты басқа орталық шығарған, жаңасының кілтін OpenNCALayer оқымады. Бұрынғы сертификат әзірге жұмыс істейді; TLS шеберін қайта іске қосыңыз."
        ),
        (RenewFailure::CaChanged(_), Locale::En) => format!(
            "The mkcert CA has changed ({e}): another CA issued the certificate in use, and OpenNCALayer did not read the new one's key. The previous certificate still works; run the TLS wizard again."
        ),
        (RenewFailure::Save(_), Locale::Ru) => format!(
            "Новый сертификат не удалось сохранить ({e}). Сервер пока работает с прежним; перевыпустите сертификат в мастере."
        ),
        (RenewFailure::Save(_), Locale::Kk) => format!(
            "Жаңа сертификатты сақтау мүмкін болмады ({e}). Сервер әзірге бұрынғысымен жұмыс істейді; сертификатты шеберде қайта шығарыңыз."
        ),
        (RenewFailure::Save(_), Locale::En) => format!(
            "The new certificate could not be saved ({e}). The server still uses the previous one; re-issue the certificate in the wizard."
        ),
        (RenewFailure::Reload(_), Locale::Ru) => format!(
            "Новый сертификат сохранён, но сервер не смог его загрузить ({e}) и работает с прежним. Перевыпустите сертификат в мастере."
        ),
        (RenewFailure::Reload(_), Locale::Kk) => format!(
            "Жаңа сертификат сақталды, бірақ сервер оны жүктей алмады ({e}) және бұрынғысымен жұмыс істейді. Сертификатты шеберде қайта шығарыңыз."
        ),
        (RenewFailure::Reload(_), Locale::En) => format!(
            "The new certificate is saved, but the server cannot load it ({e}) and keeps the previous one. Re-issue the certificate in the wizard."
        ),
    }
}

/// `dd.MM.yyyy` of an RFC 3339 time; the text itself if it is not one.
fn date(rfc3339: &str) -> String {
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::parse(rfc3339, &Rfc3339) {
        Ok(t) => {
            let t = t.to_offset(time::UtcOffset::UTC);
            format!("{:02}.{:02}.{:04}", t.day(), u8::from(t.month()), t.year())
        }
        Err(_) => rfc3339.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_ui::view::MAX_PAGE_TEXT;

    #[test]
    fn wss_off_comes_before_the_certificate() {
        let mut status = TrayStatus::new(Locale::Ru, Some(WssOff::PortBusy(13579)));
        status.renewal = RenewalCheck::Due {
            days: 12,
            expired: false,
        };
        assert_eq!(
            status.warning().as_deref(),
            Some("Порт 13579 занят (возможно, оригинальным NCALayer)")
        );
        // The notification still speaks of the certificate.
        assert_eq!(
            status.renewal_notification().unwrap().title,
            "Сертификат для браузера истекает через 12 дн."
        );
        status.wss_off = None;
        assert_eq!(
            status.warning().as_deref(),
            Some("Сертификат для браузера истекает через 12 дн.")
        );
        // Hours left are not "expired".
        status.renewal = RenewalCheck::Due {
            days: 0,
            expired: false,
        };
        assert_eq!(
            status.warning().as_deref(),
            Some("Сертификат для браузера истекает сегодня")
        );
        status.renewal = RenewalCheck::Due {
            days: 0,
            expired: true,
        };
        assert_eq!(
            status.warning().as_deref(),
            Some("Сертификат для браузера истёк")
        );
        status.renewal = RenewalCheck::Renewed {
            not_after: "2029-01-05T09:00:00Z".to_owned(),
        };
        assert_eq!(status.warning(), None);
    }

    fn original() -> PortOwner {
        PortOwner {
            pid: 4242,
            exe: std::path::PathBuf::from(r"C:\Program Files\NCALayer\NCALayer.exe"),
            started: std::time::SystemTime::UNIX_EPOCH,
            looks_original: true,
        }
    }

    #[test]
    fn the_original_on_the_port_is_offered_to_be_stopped() {
        let mut status = TrayStatus::new(Locale::Ru, Some(WssOff::PortBusy(13579)));
        // Another program: the plain warning, nothing to stop.
        assert_eq!(
            status.tray_state(),
            TrayState {
                warning: Some("Порт 13579 занят (возможно, оригинальным NCALayer)".to_owned()),
                stop_original: false,
            }
        );
        assert_eq!(status.wss_off_notification(), None);

        status.original = Some(original());
        assert_eq!(
            status.tray_state(),
            TrayState {
                warning: Some("Порт занят оригинальным NCALayer".to_owned()),
                stop_original: true,
            }
        );
        let notice = status.wss_off_notification().unwrap();
        assert_eq!(notice.title, "Порт занят оригинальным NCALayer");
        assert_eq!(
            notice.action.unwrap(),
            NotificationAction {
                label: "Остановить оригинал…".to_owned(),
                target: ActionTarget::Command(TrayCommand::StopOriginal),
            }
        );
        for l in [Locale::Kk, Locale::En] {
            status.locale = l;
            assert_ne!(status.warning(), Some(original_text(Locale::Ru).to_owned()));
            assert!(status.wss_off_notification().is_some());
        }

        // wss serves (the original stopped): the warning and the item go.
        status.wss_off = None;
        assert_eq!(status.tray_state(), TrayState::default());
        assert_eq!(status.original_on_port(), None);
    }

    /// «Остановить оригинал…» found the original gone: the user is told whether wss took
    /// the port, in every language.
    #[test]
    fn an_original_gone_on_the_click_is_told() {
        let mut status = TrayStatus::new(Locale::Ru, None);
        let serving = status.original_gone_notification(13579);
        assert_eq!(serving.title, "Оригинальный NCALayer уже не держит порт");
        assert!(
            serving
                .body
                .contains("принимает подключения сайтов на порту 13579"),
            "{}",
            serving.body
        );
        assert_eq!(serving.action, None);
        status.wss_off = Some(WssOff::PortBusy(13579));
        let busy = status.original_gone_notification(13579);
        assert!(
            busy.body.contains("Порт 13579 занят другой программой"),
            "{}",
            busy.body
        );
        for l in [Locale::Kk, Locale::En] {
            status.locale = l;
            let other = status.original_gone_notification(13579);
            assert_ne!(other.title, serving.title);
            assert!(other.body.contains("13579"));
        }
    }

    #[test]
    fn tls_not_set_up_leads_to_the_wizard() {
        let status = TrayStatus::new(Locale::Ru, Some(WssOff::TlsNotConfigured));
        let state = status.tray_state();
        assert_eq!(
            state.warning.as_deref(),
            Some("TLS не настроен: нет сертификата для браузера")
        );
        assert!(!state.stop_original);
        let notice = status.wss_off_notification().unwrap();
        assert_eq!(notice.title, state.warning.unwrap());
        assert_eq!(
            notice.action.unwrap().target,
            ActionTarget::Command(TrayCommand::TlsWizard)
        );
        // A broken certificate or an unbindable port is only warned of.
        for off in [WssOff::TlsUnusable, WssOff::PortUnavailable(1)] {
            assert_eq!(
                TrayStatus::new(Locale::Ru, Some(off)).wss_off_notification(),
                None
            );
        }
    }

    #[test]
    fn renewal_notifications_lead_to_the_wizard() {
        let mut status = TrayStatus::new(Locale::En, None);
        assert_eq!(status.renewal_notification(), None);
        status.renewal = RenewalCheck::Due {
            days: 59,
            expired: false,
        };
        let due = status.renewal_notification().unwrap();
        assert_eq!(due.title, "The certificate for browsers expires in 59 days");
        assert_eq!(
            due.action.unwrap().target,
            ActionTarget::Command(TrayCommand::TlsWizard)
        );
        status.renewal = RenewalCheck::Renewed {
            not_after: "2029-01-05T09:00:00Z".to_owned(),
        };
        let renewed = status.renewal_notification().unwrap();
        assert!(renewed.body.contains("05.01.2029"), "{}", renewed.body);
        assert_eq!(renewed.action, None);
        for (failure, says) in [
            (
                RenewFailure::Mkcert("rootCA-key.pem: missing".to_owned()),
                "mkcert CA key",
            ),
            (
                RenewFailure::Save("disk full".to_owned()),
                "could not be saved",
            ),
            (
                RenewFailure::CaChanged("/ca/rootCA.pem".to_owned()),
                "run the TLS wizard again",
            ),
            (
                RenewFailure::Reload("key mismatch".to_owned()),
                "cannot load it",
            ),
        ] {
            status.renewal = RenewalCheck::RenewFailed {
                days: 20,
                failure: failure.clone(),
            };
            let failed = status.renewal_notification().unwrap();
            assert!(failed.title.contains("not re-issued"), "{}", failed.title);
            assert!(failed.body.contains(failure.detail()), "{}", failed.body);
            assert!(failed.body.contains(says), "{}", failed.body);
        }
        for l in [Locale::Ru, Locale::Kk] {
            status.locale = l;
            assert!(status.renewal_notification().is_some());
        }
    }

    #[test]
    fn registry_link_per_locale_with_anchor() {
        assert_eq!(
            plugin_registry(Locale::Ru, "kz.x"),
            "https://arynyklas.github.io/open-ncalayer/plugins/#kz.x"
        );
        assert_eq!(
            plugin_registry(Locale::Kk, "kz.x"),
            "https://arynyklas.github.io/open-ncalayer/kk/plugins/#kz.x"
        );
        assert_eq!(
            plugin_registry(Locale::En, "kz.x"),
            "https://arynyklas.github.io/open-ncalayer/en/plugins/#kz.x"
        );
    }

    #[test]
    fn registry_link_without_anchor_for_odd_symname() {
        for symname in ["a b", "x#y", "<s>", ""] {
            assert_eq!(
                plugin_registry(Locale::En, symname),
                "https://arynyklas.github.io/open-ncalayer/en/plugins/",
                "{symname}"
            );
        }
    }

    #[test]
    fn site_urls_follow_the_site_config() {
        let path = oncl_testkit::workspace_root().join("site/config.toml");
        let config: toml::Table = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let base_url = config["base_url"].as_str().unwrap();
        assert_eq!(SITE, base_url);
        assert_eq!(crate::update::INDEX_BASE, format!("{base_url}/updates/v1"));
        assert_eq!(config["default_language"].as_str(), Some("ru"));
        let languages = config["languages"].as_table().unwrap();
        for (l, lang) in [(Locale::Kk, "kk"), (Locale::En, "en")] {
            assert!(languages.contains_key(lang), "{lang}");
            assert_eq!(
                plugin_registry(l, "kz.x"),
                format!("{base_url}/{lang}/plugins/#kz.x")
            );
        }
        assert_eq!(
            plugin_registry(Locale::Ru, "kz.x"),
            format!("{base_url}/plugins/#kz.x")
        );
    }

    #[test]
    fn bundle_requests_point_to_the_registry_once_in_a_while() {
        let mut status = TrayStatus::new(Locale::Ru, None);
        let t0 = Instant::now();
        let first = status
            .bundle_notification("kz.x", "https://shop.kz", t0)
            .unwrap();
        assert_eq!(
            first.body,
            "Сайт https://shop.kz запросил модуль kz.x. Каталог OpenNCALayer не предлагает его установить: его там нет или он уже установлен."
        );
        let action = first.action.unwrap();
        assert_eq!(action.label, "Реестр плагинов");
        assert_eq!(
            action.target,
            ActionTarget::Url(plugin_registry(Locale::Ru, "kz.x"))
        );
        assert_eq!(
            status.bundle_notification("kz.x", "https://shop.kz", t0 + Duration::from_secs(60)),
            None
        );
        assert!(
            status
                .bundle_notification("kz.y", "https://a.kz", t0 + Duration::from_secs(11 * 60))
                .is_some()
        );
        for l in [Locale::Kk, Locale::En] {
            let n = TrayStatus::new(l, None)
                .bundle_notification("kz.x", "https://shop.kz", t0)
                .unwrap();
            assert!(n.body.contains("kz.x") && n.body.contains("https://shop.kz"));
            assert_ne!(n.body, first.body);
        }
    }

    #[test]
    fn update_notifications_in_each_language() {
        let v = |s: &str| oncl_update::Version::parse(s).unwrap();
        let ru = TrayStatus::new(Locale::Ru, None);
        let found = |installing| {
            Notice::Checked(UpdateStatus::Available {
                version: "0.2.0".to_owned(),
                installing,
            })
        };
        let n = ru.update_notification(&found(true)).unwrap();
        assert_eq!(n.title, "Доступна версия 0.2.0");
        assert_eq!(n.action, None);
        // Updates off: the button leads to the settings.
        let n = ru.update_notification(&found(false)).unwrap();
        assert_eq!(
            n.action.unwrap().target,
            ActionTarget::Command(TrayCommand::Settings)
        );
        assert_eq!(
            ru.update_notification(&Notice::Updated(v("0.2.0")))
                .unwrap()
                .title,
            "Обновлено до 0.2.0"
        );
        let back = Notice::RolledBack {
            failed: v("0.2.0"),
            version: v("0.1.0"),
        };
        assert_eq!(
            ru.update_notification(&back).unwrap().title,
            "Обновление откачено"
        );
        let off = ru
            .update_notification(&Notice::Checked(UpdateStatus::NotInstalled))
            .unwrap();
        assert_eq!(
            off.body,
            "Обновления доступны только для установленной версии."
        );
        assert_eq!(
            ru.update_notification(&Notice::Checked(UpdateStatus::NotChecked)),
            None
        );
        for l in [Locale::Kk, Locale::En] {
            let status = TrayStatus::new(l, None);
            for notice in [
                found(true),
                found(false),
                Notice::Updated(v("0.2.0")),
                back.clone(),
                Notice::NoRollback {
                    failed: v("0.2.0"),
                    version: v("0.1.0"),
                },
                Notice::RollbackFailed {
                    failed: v("0.2.0"),
                    version: v("0.1.0"),
                },
                Notice::Checked(UpdateStatus::UpToDate),
                Notice::Checked(UpdateStatus::Failed("timed out".to_owned())),
                Notice::Checked(UpdateStatus::NoKeys),
            ] {
                let n = status.update_notification(&notice).unwrap();
                let ours = ru.update_notification(&notice).unwrap();
                assert!(
                    !n.title.is_empty() && !n.body.is_empty(),
                    "{l:?} {notice:?}"
                );
                assert_ne!(n.title, ours.title, "{l:?} {notice:?}");
            }
        }
    }

    #[test]
    fn plugin_notifications_in_each_language() {
        let name = oncl_plugin::Localized {
            ru: "Пример".to_owned(),
            kk: "Үлгі".to_owned(),
            en: "Example".to_owned(),
        };
        let notices = [
            PluginNotice::Installed { name: name.clone() },
            PluginNotice::Updated {
                name: name.clone(),
                version: oncl_update::Version::new(0, 2, 0),
            },
            PluginNotice::Withdrawn { name: name.clone() },
            PluginNotice::Failed {
                name: name.clone(),
                error: "boom".to_owned(),
            },
            PluginNotice::UpdateNeedsConfirmation {
                name: name.clone(),
                version: oncl_update::Version::new(0, 3, 0),
            },
        ];
        let t0 = Instant::now();
        let mut ru = TrayStatus::new(Locale::Ru, None);
        let n = ru.plugin_notification(&notices[1], t0).unwrap();
        assert_eq!(n.title, "Плагин обновлён");
        assert_eq!(n.body, "Плагин «Пример» обновлён до версии 0.2.0.");
        assert_eq!(
            ru.plugin_notification(&notices[3], t0).unwrap().body,
            "«Пример»: boom"
        );
        let n = ru.plugin_notification(&notices[4], t0).unwrap();
        assert_eq!(n.title, "Обновление плагина ждёт разрешения");
        assert!(n.body.contains("0.3.0"), "{}", n.body);
        assert_eq!(
            n.action.map(|a| a.target),
            Some(ActionTarget::Command(TrayCommand::Plugins))
        );
        for l in [Locale::Kk, Locale::En] {
            let mut status = TrayStatus::new(l, None);
            for notice in &notices {
                let n = status.plugin_notification(notice, t0).unwrap();
                let ours = ru.plugin_notification(notice, t0).unwrap();
                assert!(
                    !n.title.is_empty() && !n.body.is_empty(),
                    "{l:?} {notice:?}"
                );
                assert_ne!(n.title, ours.title, "{l:?} {notice:?}");
                assert!(n.body.contains(name.get(l)), "{l:?} {notice:?}");
            }
        }
    }

    #[test]
    fn a_needed_plugin_is_told_once_in_a_while() {
        let needed = |origin: Option<&str>| PluginNotice::Needed {
            origin: origin.map(str::to_owned),
            name: oncl_plugin::Localized {
                ru: "Пример".to_owned(),
                kk: "Үлгі".to_owned(),
                en: "Example".to_owned(),
            },
            id: "kz.example".to_owned(),
        };
        let mut status = TrayStatus::new(Locale::Ru, None);
        let t0 = Instant::now();
        let first = status
            .plugin_notification(&needed(Some("https://shop.kz")), t0)
            .unwrap();
        assert_eq!(first.title, "Сайту нужен плагин");
        assert_eq!(
            first.body,
            "Сайту https://shop.kz нужен плагин «Пример» из каталога OpenNCALayer."
        );
        assert_eq!(
            status.plugin_notification(&needed(None), t0 + Duration::from_secs(60)),
            None
        );
        // Other plugin notices are not held back.
        assert!(
            status
                .plugin_notification(
                    &PluginNotice::Withdrawn {
                        name: oncl_plugin::Localized {
                            ru: "Пример".to_owned(),
                            kk: "Үлгі".to_owned(),
                            en: "Example".to_owned(),
                        }
                    },
                    t0
                )
                .is_some()
        );
        let later = status
            .plugin_notification(&needed(None), t0 + Duration::from_secs(11 * 60))
            .unwrap();
        assert_eq!(
            later.body,
            "Сайту нужен плагин «Пример» из каталога OpenNCALayer."
        );
        for l in [Locale::Kk, Locale::En] {
            let mut status = TrayStatus::new(l, None);
            for origin in [Some("https://shop.kz"), None] {
                status.last_needed_notice = None;
                let n = status.plugin_notification(&needed(origin), t0).unwrap();
                assert!(n.body.contains(if l == Locale::Kk {
                    "Үлгі"
                } else {
                    "Example"
                }));
                assert_eq!(n.body.contains("https://shop.kz"), origin.is_some());
            }
        }
    }

    #[test]
    fn page_text_is_cleaned_and_cut() {
        assert_eq!(
            page_text(
                "a\u{2028}b\u{2029}c\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}d\u{2066}\u{2067}\u{2068}\u{2069}e"
            ),
            "abcde"
        );
        // Other format characters (a zero-width joiner in an emoji) stay.
        assert_eq!(page_text("x\u{200D}y"), "x\u{200D}y");
        let mut status = TrayStatus::new(Locale::En, None);
        let long = "a".repeat(MAX_PAGE_TEXT + 10);
        let n = status
            .bundle_notification(
                &format!("kz.x\n\u{1b}[31m{long}"),
                "https://e.kz\r\nX: 1",
                Instant::now(),
            )
            .unwrap();
        assert!(!n.body.chars().any(char::is_control), "{:?}", n.body);
        assert!(n.body.contains("https://e.kzX: 1"));
        let shown = format!("kz.x[31m{}…", "a".repeat(MAX_PAGE_TEXT - 8));
        assert!(n.body.contains(&shown), "{}", n.body);
        assert_eq!(page_text("short"), "short");
        assert_eq!(
            page_text(&"я".repeat(MAX_PAGE_TEXT)),
            "я".repeat(MAX_PAGE_TEXT)
        );
        let mut status = TrayStatus::new(Locale::Ru, None);
        let needed = status
            .plugin_notification(
                &PluginNotice::Needed {
                    origin: Some("https://e.kz\n".to_owned()),
                    name: oncl_plugin::Localized {
                        ru: "П".to_owned(),
                        kk: "П".to_owned(),
                        en: "P".to_owned(),
                    },
                    id: "kz.p".to_owned(),
                },
                Instant::now(),
            )
            .unwrap();
        assert!(!needed.body.chars().any(char::is_control));
    }
}
