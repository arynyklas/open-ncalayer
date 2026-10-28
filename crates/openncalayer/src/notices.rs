//! What the tray tells the user: its warning (wss off, the original NCALayer holding the
//! port, the certificate due or not renewed), whether it offers «Остановить оригинал…», and
//! its notifications (wss off at the start, the certificate's renewal, a page's
//! `installBundle`, the updates), in the user's language.

use std::time::{Duration, Instant};

use oncl_basics::Locale;
use oncl_desktop::PortOwner;
use oncl_ui::settings_view::{UpdateStatus, update_view};
use oncl_ui::{ActionTarget, Notification, NotificationAction, TrayCommand, TrayState};

use crate::cli::WssOff;
use crate::renewal::{RenewFailure, RenewalCheck};
use crate::update::Notice;

/// Where the plugins of OpenNCALayer are to be listed (the page arrives with plugins, P12).
pub const PLUGIN_REGISTRY: &str = "https://arynyklas.github.io/open-ncalayer/plugins/";
/// A page asking for bundles again and again is told about the registry at most this often.
const BUNDLE_NOTICE_EVERY: Duration = Duration::from_secs(10 * 60);

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
}

impl TrayStatus {
    pub fn new(locale: Locale, wss_off: Option<WssOff>) -> Self {
        TrayStatus {
            locale,
            wss_off,
            original: None,
            renewal: RenewalCheck::Nothing,
            last_bundle_notice: None,
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

    /// The notification of a page's `installBundle`, unless one was shown within the last
    /// ten minutes (at `now`).
    pub fn bundle_notification(&mut self, now: Instant) -> Option<Notification> {
        if self
            .last_bundle_notice
            .is_some_and(|last| now.duration_since(last) < BUNDLE_NOTICE_EVERY)
        {
            return None;
        }
        self.last_bundle_notice = Some(now);
        let l = self.locale;
        Some(Notification {
            title: match l {
                Locale::Ru => "Сайт просит установить модуль",
                Locale::Kk => "Сайт модуль орнатуды сұрайды",
                Locale::En => "A site asks to install a module",
            }
            .to_owned(),
            body: match l {
                Locale::Ru => format!(
                    "Модули OpenNCALayer встроены, установить новый нельзя. Список плагинов: {PLUGIN_REGISTRY}"
                ),
                Locale::Kk => format!(
                    "OpenNCALayer модульдері кірістірілген, жаңасын орнату мүмкін емес. Плагиндер тізімі: {PLUGIN_REGISTRY}"
                ),
                Locale::En => format!(
                    "OpenNCALayer's modules are built in; no other can be installed. The list of plugins: {PLUGIN_REGISTRY}"
                ),
            },
            action: Some(NotificationAction {
                label: match l {
                    Locale::Ru => "Открыть список плагинов",
                    Locale::Kk => "Плагиндер тізімін ашу",
                    Locale::En => "Open the list of plugins",
                }
                .to_owned(),
                target: ActionTarget::Url(PLUGIN_REGISTRY.to_owned()),
            }),
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
            Notice::Checked(off @ (UpdateStatus::NotInstalled | UpdateStatus::NoKeys)) => (
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
    fn bundle_requests_point_to_the_registry_once_in_a_while() {
        let mut status = TrayStatus::new(Locale::Ru, None);
        let t0 = Instant::now();
        let first = status.bundle_notification(t0).unwrap();
        assert!(first.body.contains(PLUGIN_REGISTRY));
        assert_eq!(
            first.action.unwrap().target,
            ActionTarget::Url(PLUGIN_REGISTRY.to_owned())
        );
        assert_eq!(
            status.bundle_notification(t0 + Duration::from_secs(60)),
            None
        );
        assert!(
            status
                .bundle_notification(t0 + Duration::from_secs(11 * 60))
                .is_some()
        );
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
}
