//! What the tray tells the user: its warning (wss off, the certificate due or not renewed)
//! and its notifications (the certificate's renewal, a page's `installBundle`), in the
//! user's language.

use std::time::{Duration, Instant};

use oncl_basics::Locale;
use oncl_ui::{ActionTarget, Notification, NotificationAction, TrayCommand};

use crate::cli::WssOff;
use crate::renewal::{RenewFailure, RenewalCheck};

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
    /// The last renewal check.
    pub renewal: RenewalCheck,
    last_bundle_notice: Option<Instant>,
}

impl TrayStatus {
    pub fn new(locale: Locale, wss_off: Option<WssOff>) -> Self {
        TrayStatus {
            locale,
            wss_off,
            renewal: RenewalCheck::Nothing,
            last_bundle_notice: None,
        }
    }

    /// The warning the tray shows: wss being off comes first, then the certificate's.
    pub fn warning(&self) -> Option<String> {
        match self.wss_off {
            Some(off) => Some(off.text(self.locale)),
            None => self.renewal_warning(),
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
        let wizard = || NotificationAction {
            label: match l {
                Locale::Ru => "Открыть «Сертификат для браузера»",
                Locale::Kk => "«Браузерге арналған сертификат» ашу",
                Locale::En => "Open «Certificate for browsers»",
            }
            .to_owned(),
            target: ActionTarget::Command(TrayCommand::TlsWizard),
        };
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
}
