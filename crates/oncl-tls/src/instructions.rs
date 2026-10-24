//! Per-OS instructions for trusting the local CA (Russian text).
//!
//! OpenNCALayer only shows these commands; it never runs them and never writes to OS or
//! browser trust stores itself.

use std::fmt::Write;

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::{TlsFiles, TlsInfo, TlsSource};

/// Operating system the instructions are written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    Windows,
    MacOs,
    Linux,
}

/// Re-issue the server certificate this long before it expires.
const RENEW_BEFORE: Duration = Duration::days(60);
/// NSS nickname of the CA in `certutil -d sql:<nssdb>` commands.
const NSS_NICKNAME: &str = "OpenNCALayer Local CA";

/// Step-by-step instructions to trust the local CA on `os`, check the result at
/// `https://127.0.0.1:<port>/` (`port` is the configured server port), remove the CA later,
/// and the date by which the server certificate should be re-issued.
pub fn instructions(os: TargetOs, files: &TlsFiles, info: &TlsInfo, port: u16) -> String {
    let mut s = String::new();
    match info.source {
        TlsSource::Generated => generated(&mut s, os, files, info),
        TlsSource::Imported => imported(&mut s),
    }
    let _ = writeln!(s, "Проверка");
    let _ = writeln!(
        s,
        "Перезапустите браузер и откройте https://127.0.0.1:{port}/ — страница должна \
         открыться без предупреждения о сертификате."
    );
    let _ = writeln!(s);
    validity(&mut s, info);
    s
}

/// `"1A2B3C4D 5E6F7081 …"`: the hex digits of a SHA-1 thumbprint in upper case, in groups of
/// eight, as the Windows "Security Warning" dialog shows them.
pub fn sha1_grouped(sha1_hex: &str) -> String {
    let digits: Vec<char> = sha1_hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    digits
        .chunks(8)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn generated(s: &mut String, os: TargetOs, files: &TlsFiles, info: &TlsInfo) {
    let ca_pem = files.ca_pem().display().to_string();
    let ca_der = files.ca_der().display().to_string();
    let sha1 = info
        .ca_sha1
        .as_deref()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let sha1_grouped = sha1_grouped(&sha1);
    let sha256 = info
        .ca_sha256
        .as_deref()
        .unwrap_or_default()
        .to_ascii_uppercase();

    let _ = writeln!(s, "Доверие к локальному центру сертификации OpenNCALayer");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "OpenNCALayer сам ничего не устанавливает в хранилища сертификатов: выполните шаги \
         ниже вручную. Этот центр сертификации может выпускать сертификаты только для \
         127.0.0.1, ::1 и localhost — для других сайтов он недействителен."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Сертификат: {ca_der} (DER), {ca_pem} (PEM)");
    let _ = writeln!(s, "Отпечаток SHA-1: {sha1_grouped}");
    let _ = writeln!(s, "Отпечаток SHA-256: {sha256}");
    let _ = writeln!(s);

    match os {
        TargetOs::Windows => windows(s, &ca_pem, &ca_der, &sha1, &sha1_grouped),
        TargetOs::MacOs => macos(s, &ca_pem, &sha1),
        TargetOs::Linux => linux(s, &ca_pem),
    }
}

fn windows(s: &mut String, ca_pem: &str, ca_der: &str, sha1: &str, sha1_grouped: &str) {
    let _ = writeln!(
        s,
        "Способ 1 — командная строка (права администратора не нужны):"
    );
    let _ = writeln!(s, "    certutil -user -addstore Root \"{ca_der}\"");
    let _ = writeln!(s);
    let _ = writeln!(s, "Способ 2 — оснастка «Сертификаты»:");
    let _ = writeln!(
        s,
        "  1. Нажмите Win+R, введите certmgr.msc и нажмите Enter."
    );
    let _ = writeln!(
        s,
        "  2. Откройте «Доверенные корневые центры сертификации» → «Сертификаты»."
    );
    let _ = writeln!(
        s,
        "  3. Меню «Действие» → «Все задачи» → «Импорт…», выберите файл {ca_der} и хранилище \
         «Доверенные корневые центры сертификации»."
    );
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "В обоих случаях Windows покажет окно «Предупреждение системы безопасности» \
         («Security Warning») с вопросом об установке сертификата. Нажимайте «Да», только \
         если отпечаток (sha1) в этом окне совпадает с этим:"
    );
    let _ = writeln!(s, "    {sha1_grouped}");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Chrome и Edge используют хранилище Windows. Firefox 120 и новее тоже доверяет ему \
         автоматически. В Firefox ESR 115 включите в about:config параметр \
         security.enterprise_roots.enabled = true или импортируйте {ca_pem} в «Настройки» → \
         «Приватность и защита» → «Сертификаты» → «Просмотр сертификатов» → «Центры \
         сертификации» → «Импортировать…» с флажком «Доверять при идентификации веб-сайтов»."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Удаление");
    let _ = writeln!(s, "    certutil -user -delstore Root {sha1}");
    let _ = writeln!(
        s,
        "или в certmgr.msc удалите «OpenNCALayer Local CA …» из «Доверенных корневых центров \
         сертификации». Если сертификат импортировался в Firefox, удалите его и там \
         («Центры сертификации» → «Удалить или не доверять»)."
    );
    let _ = writeln!(s);
}

fn macos(s: &mut String, ca_pem: &str, sha1: &str) {
    let _ = writeln!(
        s,
        "Способ 1 — Терминал (система запросит пароль пользователя):"
    );
    let _ = writeln!(
        s,
        "    security add-trusted-cert -r trustRoot -p ssl -k \
         ~/Library/Keychains/login.keychain-db \"{ca_pem}\""
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Способ 2 — «Связка ключей»:");
    let _ = writeln!(
        s,
        "  1. Откройте «Связку ключей», выберите связку «login» и перетащите в окно файл \
         {ca_pem} (или «Файл» → «Импортировать объекты…»)."
    );
    let _ = writeln!(
        s,
        "  2. Дважды щёлкните сертификат «OpenNCALayer Local CA …», сверьте отпечаток SHA-1 \
         с указанным выше, раскройте «Доверие» и для «SSL» выберите «Всегда доверять»."
    );
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Safari и Chrome используют «Связку ключей», Firefox 120 и новее тоже доверяет ей \
         автоматически. В Firefox ESR 115 включите в about:config параметр \
         security.enterprise_roots.enabled = true или импортируйте {ca_pem} в «Центры \
         сертификации» Firefox с флажком «Доверять при идентификации веб-сайтов»."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Удаление");
    let _ = writeln!(
        s,
        "    security delete-certificate -Z {sha1} ~/Library/Keychains/login.keychain-db"
    );
    let _ = writeln!(
        s,
        "или удалите «OpenNCALayer Local CA …» в «Связке ключей»."
    );
    let _ = writeln!(s);
}

fn linux(s: &mut String, ca_pem: &str) {
    let _ = writeln!(s, "Chrome и Chromium:");
    let _ = writeln!(
        s,
        "  откройте chrome://certificate-manager → «Свои» → «Установленные вами» → \
         «Импортировать» и выберите файл {ca_pem}."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Firefox:");
    let _ = writeln!(
        s,
        "  «Настройки» → «Приватность и защита» → «Сертификаты» → «Просмотр сертификатов» → \
         «Центры сертификации» → «Импортировать…», выберите {ca_pem} и отметьте флажок \
         «Доверять при идентификации веб-сайтов»."
    );
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Или командой certutil (пакет libnss3-tools / nss-tools):"
    );
    let _ = writeln!(
        s,
        "    certutil -d sql:<nssdb> -A -t \"C,,\" -n \"{NSS_NICKNAME}\" -i \"{ca_pem}\""
    );
    let _ = writeln!(
        s,
        "где <nssdb> — $HOME/.pki/nssdb для Chrome и Chromium или каталог профиля Firefox \
         (~/.mozilla/firefox/<профиль>, для snap — \
         ~/snap/firefox/common/.mozilla/firefox/<профиль>). Браузер перед этим закройте."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Удаление");
    let _ = writeln!(s, "    certutil -d sql:<nssdb> -D -n \"{NSS_NICKNAME}\"");
    let _ = writeln!(
        s,
        "или удалите «OpenNCALayer Local CA …» в chrome://certificate-manager («Свои» → \
         «Установленные вами») и в «Центрах сертификации» Firefox."
    );
    let _ = writeln!(s);
}

fn imported(s: &mut String) {
    let _ = writeln!(s, "Импортированный сертификат");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "OpenNCALayer использует ваш сертификат и не выпускал собственный центр \
         сертификации. Браузер должен доверять центру сертификации, выпустившему ваш \
         сертификат; если доверие настроено, дополнительных шагов не нужно. Удаление \
         доверия к этому центру сертификации — по правилам вашей организации."
    );
    let _ = writeln!(s);
}

fn validity(s: &mut String, info: &TlsInfo) {
    let Ok(not_after) = OffsetDateTime::parse(&info.leaf_not_after, &Rfc3339) else {
        let _ = writeln!(
            s,
            "Сертификат сервера действует до {}.",
            info.leaf_not_after
        );
        return;
    };
    let renew = not_after - RENEW_BEFORE;
    let _ = writeln!(
        s,
        "Сертификат сервера действует до {} (UTC). Перевыпустите его до {}.",
        ru_date(not_after),
        ru_date(renew)
    );
}

fn ru_date(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!("{:02}.{:02}.{:04}", t.day(), u8::from(t.month()), t.year())
}
