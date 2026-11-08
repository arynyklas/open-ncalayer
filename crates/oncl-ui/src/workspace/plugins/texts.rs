//! The words of the Plugins page in the three languages of the program. Every text the page
//! composes is here, in one table per language: a field added to [`Texts`] does not build until
//! all three tables have it, and the tests check every field in every language (no empty text,
//! the same `{n}` placeholders everywhere).
//!
//! These are the HOST's words. A plugin's own text (its name, its label of an operation, the
//! reply of its module) is never put into one of them: it is shown in a frame of its own, under
//! a caption that says whose words they are (`frame_name` here and the caption of the
//! installation window, [`crate::install_plugin::frame_caption`]).
//!
//! The Kazakh texts are written from the vocabulary of the other windows of the program and
//! have not been read by a native speaker yet: they need that check before a release.

use oncl_flows::Locale;

macro_rules! texts {
    ($($(#[$meta:meta])* $field:ident),+ $(,)?) => {
        /// The texts of the page in one language.
        pub(in crate::workspace) struct Texts {
            $($(#[$meta])* pub $field: &'static str,)+
        }
        impl Texts {
            /// Every text with its field's name, for the tests.
            #[cfg(test)]
            pub(in crate::workspace) fn fields(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($field), self.$field)),+]
            }
        }
    };
}

texts! {
    // The list of operations.
    page_title,
    intro,
    refresh,
    reading,
    no_source,
    none_offered,
    /// `{0}` the plugin's id, `{1}` its version.
    plugin_heading,
    /// `{0}` the operation's identifier.
    operation_heading,
    operation_invalid,
    key_use_yes,
    key_use_no,
    open_operation,
    /// `{0}` the operation's identifier.
    open_label,
    hidden_heading,
    /// `{0}` the plugin's id, `{1}` its version.
    without_ops,
    without_ops_why,
    /// `{0}` the plugin's id.
    unusable,
    frame_name,
    // The form.
    /// `{0}` the operation's identifier.
    form_title,
    /// `{0}` the plugin's id, `{1}` its version.
    form_intro,
    /// `{0}` the parameter's name, `{1}` the largest size.
    doc_label,
    doc_placeholder,
    /// `{0}` the parameter's name, `{1}` the most characters.
    text_label,
    /// `{0}` the parameter's name.
    choice_label,
    /// `{0}` the parameter's name.
    flag_label,
    /// `{0}` the parameter's name.
    locale_label,
    store_label,
    store_placeholder,
    continue_,
    back,
    cancel,
    /// `{0}` the parameter's name.
    e_no_path,
    /// `{0}` the parameter's name.
    e_unreadable,
    /// `{0}` the parameter's name, `{1}` the largest size.
    e_too_big,
    /// `{0}` the parameter's name.
    e_empty,
    /// `{0}` the parameter's name, `{1}` the most characters.
    e_text_long,
    e_no_store,
    busy,
    stale,
    choose_one,
    // The key.
    key_title,
    password_label,
    open_store,
    choose_cert,
    show_consent,
    no_password,
    wrong_password,
    store_unreadable,
    expired,
    not_yet,
    not_for_signing,
    expired_refusal,
    not_yet_refusal,
    not_for_signing_refusal,
    /// `{0}` the subject, `{1}` the alias, `{2}` why it cannot be used (or empty).
    cert_row,
    // The confirmation.
    consent_title,
    consent_lead,
    /// `{0}` the operation's identifier.
    c_operation,
    /// `{0}` the plugin's id, `{1}` its version.
    c_plugin,
    c_package,
    c_package_loose,
    /// `{0}` how many times.
    c_uses,
    c_network_none,
    /// `{0}` the servers.
    c_network_pki,
    /// `{0}` the file's name.
    c_file,
    /// `{0}` the parameter's name.
    c_text_signed,
    r_applied_no_reply,
    /// `{0}` the size.
    c_size,
    c_sha,
    /// `{0}` the hash algorithm.
    c_prehash,
    c_key_heading,
    /// `{0}` the alias.
    c_alias,
    /// `{0}` the serial number.
    c_serial,
    /// `{0}` the subject's common name.
    c_subject,
    c_no_subject,
    /// `{0}` the date.
    c_valid,
    c_fingerprint,
    c_inputs,
    /// `{0}` the parameter's name, `{1}` its value.
    c_input_line,
    /// `{0}` the parameter's name, `{1}` the choice (quoted).
    c_choice_line,
    no_reason,
    /// `{0}` the stable id of a refusal.
    row_code,
    e_text_bad,
    c_flag_yes,
    c_flag_no,
    /// `{0}` the seconds.
    c_ttl,
    c_trust_note,
    /// `{0}` the operation's identifier.
    confirm_label,
    consent_cancel,
    consent_arming,
    preparing,
    consent_idle,
    key_idle,
    consent_invalid,
    // Running and the result.
    running,
    r_ok,
    /// `{0}` why.
    r_applied_failed,
    r_unknown,
    /// `{0}` why.
    r_not_applied,
    r_cancelled_before,
    r_lost,
    r_cancel_slow,
    row_key_applied,
    row_key_not_applied,
    row_key_unknown,
    /// `{0}` the operation's identifier.
    row_operation,
    /// `{0}` the plugin's id, `{1}` its version.
    row_plugin,
    /// `{0}` the reason.
    row_reason,
    row_not_verified,
    /// `{0}` the most characters shown.
    reply_caption,
    /// `{0}` how many characters are not shown.
    reply_cut,
    no_save,
    again,
    finish,
    // Why a key use was refused (what Core says; one for each of its variants).
    f_no_ticket,
    f_no_approval,
    f_uses,
    f_expired,
    f_operation_id,
    f_identity,
    f_operation,
    f_caller,
    f_key,
    f_action,
    f_kind,
    f_content,
    f_options,
    f_already_used,
    f_undeclared,
    f_certificate_changed,
    f_no_guard,
    f_busy,
    f_replayed,
    f_other,
    // Why the confirmation could not be prepared.
    p_not_runnable,
    p_too_large,
    p_value,
    p_key_unavailable,
    p_cert_mismatch,
    p_unsupported_key,
    p_no_key_use,
    p_options,
    p_budget,
    p_no_store,
    p_other,
    // The status line.
    s_reading,
    s_preparing,
    s_waiting,
    s_running,
}

impl Texts {
    pub(in crate::workspace) fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Ru => &RU,
            Locale::Kk => &KK,
            Locale::En => &EN,
        }
    }
}

static EN: Texts = Texts {
    page_title: "Plugins",
    intro: "These are the operations of your installed plugins that this window can run. You choose a file and your key; the window then shows exactly what the key will be used for, and only your confirmation lets the plugin use it.",
    refresh: "Refresh the list",
    reading: "Reading the installed plugins…",
    no_source: "Plugins are not available in this run of the program.",
    none_offered: "No installed plugin offers an operation for this window.",
    plugin_heading: "Plugin {0}, version {1}",
    operation_heading: "Operation {0}",
    operation_invalid: "An operation with an invalid name",
    key_use_yes: "Uses your key; every use needs your confirmation.",
    key_use_no: "Does not use your key, so there is nothing to confirm: this window does not run it.",
    open_operation: "Open",
    open_label: "Open the operation {0}",
    hidden_heading: "Installed plugins with nothing for this window",
    without_ops: "Plugin {0}, version {1}: no operations for the manual window.",
    without_ops_why: "OpenNCALayer does not know why: the package declares none for this window.",
    unusable: "Plugin {0}: its package cannot be read, so it is not offered. The log says why.",
    frame_name: "The plugin's name (the plugin's own words, not checked):",
    form_title: "Operation {0}",
    form_intro: "Plugin {0}, version {1}. Choose the file and the key. Nothing is signed until you confirm on a later page.",
    doc_label: "Document {0}: a file you choose, at most {1}",
    doc_placeholder: "Path to the file",
    text_label: "Text {0} (at most {1} characters)",
    choice_label: "Choice {0}",
    flag_label: "Option {0}",
    locale_label: "Language {0}",
    store_label: "Key store (PKCS#12, JKS)",
    store_placeholder: "Path to the key store file",
    continue_: "Continue",
    back: "Back",
    cancel: "Cancel",
    e_no_path: "Choose the file for {0}.",
    e_unreadable: "The file for {0} cannot be read.",
    e_too_big: "The file for {0} is larger than the {1} this operation takes.",
    e_empty: "The file for {0} is empty.",
    e_text_long: "The text {0} is longer than {1} characters.",
    e_no_store: "Choose the key store file.",
    busy: "The previous step is still running. Please wait.",
    stale: "The installed plugins changed. The list was read again; choose the operation again.",
    choose_one: "Choose…",
    key_title: "Your key",
    password_label: "Password of the key store",
    open_store: "Open key store",
    choose_cert: "Choose the certificate",
    show_consent: "Show what will be approved",
    no_password: "Enter the password.",
    wrong_password: "The key store did not open: wrong password, or it is not a key store.",
    store_unreadable: "The key store file could not be read.",
    expired: "expired",
    not_yet: "not valid yet",
    not_for_signing: "not for signing",
    expired_refusal: "This certificate cannot sign: it has expired.",
    not_yet_refusal: "This certificate cannot sign: it is not valid yet.",
    not_for_signing_refusal: "This certificate is not meant for signing.",
    cert_row: "{0} ({1}){2}",
    consent_title: "Confirm the use of your key",
    consent_lead: "OpenNCALayer wrote everything on this page except the framed box. If you confirm, your key signs once, and only what is described here.",
    c_operation: "Operation: {0}",
    c_plugin: "Plugin: {0}, version {1}",
    c_package: "SHA-256 of the plugin package file:",
    c_package_loose: "SHA-256 of the plugin's manifest and module:",
    c_uses: "Uses of your key: {0}. The confirmation works once and is not remembered.",
    c_network_none: "Network: none. The plugin cannot send anything anywhere.",
    c_network_pki: "Network: only these servers of the national PKI: {0}. The plugin may send the document or data made from it to them.",
    c_file: "File chosen by you: {0}",
    c_text_signed: "What is signed is the text you typed for {0}, exactly as listed below.",
    r_applied_no_reply: "Your key WAS applied, but the plugin gave no reply and reported no error: whether the signature was made is not known to this window.",
    c_size: "Size: {0}",
    c_sha: "SHA-256 of the file:",
    c_prehash: "The key signs the digest of the file that OpenNCALayer computed ({0}):",
    c_key_heading: "The key that signs",
    c_alias: "Alias in the key store: {0}",
    c_serial: "Serial number: {0}",
    c_subject: "Owner (CN): {0}",
    c_no_subject: "Owner (CN): not stated",
    c_valid: "Valid until: {0}",
    c_fingerprint: "SHA-256 of the certificate:",
    c_inputs: "Values you entered, passed to the plugin as they are (not part of what is approved):",
    c_input_line: "{0} = {1}",
    c_choice_line: "Choice {0}, one of those the plugin offers: {1}",
    no_reason: "no reason was reported",
    row_code: "Code: {0}",
    e_text_bad: "The text {0} has a character that cannot be shown as typed (a control, an invisible or a direction-changing character). Remove it.",
    c_flag_yes: "yes",
    c_flag_no: "no",
    c_ttl: "After you confirm, the plugin has {0} seconds to use the key; then the approval expires and you confirm again.",
    c_trust_note: "The box below holds the plugin's own words. They are not checked and are not part of what you approve.",
    confirm_label: "Sign with the plugin {0}",
    consent_cancel: "Cancel: do not sign",
    consent_arming: "The button works a moment after the page appears.",
    preparing: "Preparing the confirmation: the plugin is not started and your key is not used.",
    consent_idle: "The confirmation page was left open too long and was closed. Nothing was signed and your key was not used.",
    key_idle: "The key page was left open too long and was closed, and the password was forgotten. Nothing was signed and your key was not used.",
    consent_invalid: "This confirmation cannot be shown safely: the operation's description and the prepared key use do not agree. Nothing was signed.",
    running: "The plugin runs under your confirmation. Your key may be used now. Cancel asks it to stop; the result says honestly whether the key was used.",
    r_ok: "The plugin returned a reply and your key was applied once. OpenNCALayer did not check the signature in the reply.",
    r_applied_failed: "Your key WAS applied, but the plugin did not finish properly: {0}",
    r_unknown: "It is not known whether your key was applied: the key use did not report. Treat the key as possibly used.",
    r_not_applied: "Nothing was signed: your key was not used. {0}",
    r_cancelled_before: "Cancelled: your key was not used.",
    r_lost: "The worker stopped unexpectedly after your confirmation. Whether your key was applied is not known.",
    r_cancel_slow: "Cancel was asked, but the plugin has not stopped yet. You can leave this page: the plugin finishes in the background, and whether your key was applied is not known.",
    row_key_applied: "Key use: applied",
    row_key_not_applied: "Key use: not applied",
    row_key_unknown: "Key use: not known",
    row_operation: "Operation: {0}",
    row_plugin: "Plugin: {0}, version {1}",
    row_reason: "Why: {0}",
    row_not_verified: "The signature in the reply was not verified by OpenNCALayer.",
    reply_caption: "The plugin's reply (its own text, not checked; the first {0} characters):",
    reply_cut: "… {0} more characters are not shown.",
    no_save: "The result is shown here and is not saved: this window has no file output for plugins.",
    again: "Prepare again",
    finish: "Back to the list",
    f_no_ticket: "the key use did not come from a declared operation",
    f_no_approval: "there was no approval for this key use",
    f_uses: "the approval does not allow exactly one use",
    f_expired: "the approval expired before the key was used (it is valid for a short time after you confirm): confirm again",
    f_operation_id: "the approval was made for another run",
    f_identity: "the approval was made for another plugin, package or version",
    f_operation: "the approval was made for another operation",
    f_caller: "the approval was made for another caller",
    f_key: "the approval was made for another key",
    f_action: "the kind of key use does not fit the content",
    f_kind: "the plugin asked for another kind of signature than the one you approved",
    f_content: "the plugin tried to sign other content than the one you approved",
    f_options: "the plugin asked for other signature options than the ones you approved",
    f_already_used: "the approved use was already spent",
    f_undeclared: "the plugin does not declare this operation",
    f_certificate_changed: "the key's certificate is not the one you approved",
    f_no_guard: "this program has no approval guard for plugins",
    f_busy: "another plugin call is running: confirm again when it has finished",
    f_replayed: "this approval was already used",
    f_other: "the key use was refused",
    p_not_runnable: "This operation cannot be run in this window.",
    p_too_large: "The file or the text is too large for this operation.",
    p_value: "A value you entered is not accepted by the operation.",
    p_key_unavailable: "The key could not be opened: check the password and the key store.",
    p_cert_mismatch: "The key store's certificate is not the one shown in the list: the key store changed.",
    p_unsupported_key: "The certificate or the algorithm of this key cannot be used for this operation.",
    p_no_key_use: "This operation does not use a key.",
    p_options: "A text for the signature's profile (an XPath, for example) is not valid.",
    p_budget: "The document is too large for the limits of this plugin window, or the program has too little working memory for it. Choose a smaller file.",
    p_no_store: "There is no temporary storage available to sign this document. Nothing was signed.",
    p_other: "The operation could not be prepared.",
    s_reading: "Reading the installed plugins…",
    s_preparing: "Preparing the confirmation…",
    s_waiting: "Waiting for your confirmation. The key is not used until you confirm.",
    s_running: "The plugin is running…",
};

static RU: Texts = Texts {
    page_title: "Плагины",
    intro: "Здесь операции установленных плагинов, которые это окно умеет выполнять. Вы выбираете файл и свой ключ; окно покажет, для чего именно будет применён ключ, и только ваше подтверждение разрешит плагину им воспользоваться.",
    refresh: "Обновить список",
    reading: "Читаются установленные плагины…",
    no_source: "В этом запуске программы плагины недоступны.",
    none_offered: "Ни один установленный плагин не предлагает операций для этого окна.",
    plugin_heading: "Плагин {0}, версия {1}",
    operation_heading: "Операция {0}",
    operation_invalid: "Операция с недопустимым именем",
    key_use_yes: "Использует ваш ключ; каждое применение требует вашего подтверждения.",
    key_use_no: "Не использует ваш ключ, подтверждать нечего: это окно такую операцию не запускает.",
    open_operation: "Открыть",
    open_label: "Открыть операцию {0}",
    hidden_heading: "Установленные плагины, у которых для этого окна ничего нет",
    without_ops: "Плагин {0}, версия {1}: нет операций для окна ручных инструментов.",
    without_ops_why: "Почему, OpenNCALayer не знает: в пакете для этого окна ничего не объявлено.",
    unusable: "Плагин {0}: его пакет не читается, поэтому он не предлагается. Причина в журнале.",
    frame_name: "Название плагина (слова самого плагина, не проверены):",
    form_title: "Операция {0}",
    form_intro: "Плагин {0}, версия {1}. Выберите файл и ключ. Ничего не подписывается, пока вы не подтвердите на одной из следующих страниц.",
    doc_label: "Документ {0}: файл на ваш выбор, не больше {1}",
    doc_placeholder: "Путь к файлу",
    text_label: "Текст {0} (не больше {1} символов)",
    choice_label: "Выбор {0}",
    flag_label: "Параметр {0}",
    locale_label: "Язык {0}",
    store_label: "Хранилище ключей (PKCS#12, JKS)",
    store_placeholder: "Путь к файлу хранилища ключей",
    continue_: "Продолжить",
    back: "Назад",
    cancel: "Отмена",
    e_no_path: "Выберите файл для {0}.",
    e_unreadable: "Файл для {0} не удалось прочитать.",
    e_too_big: "Файл для {0} больше, чем принимает эта операция ({1}).",
    e_empty: "Файл для {0} пуст.",
    e_text_long: "Текст {0} длиннее {1} символов.",
    e_no_store: "Укажите файл хранилища ключей.",
    busy: "Предыдущий шаг ещё выполняется. Подождите.",
    stale: "Набор установленных плагинов изменился. Список прочитан заново; выберите операцию снова.",
    choose_one: "Выберите…",
    key_title: "Ваш ключ",
    password_label: "Пароль хранилища ключей",
    open_store: "Открыть хранилище",
    choose_cert: "Выберите сертификат",
    show_consent: "Показать, что будет разрешено",
    no_password: "Введите пароль.",
    wrong_password: "Хранилище не открылось: неверный пароль или это не хранилище ключей.",
    store_unreadable: "Файл хранилища не удалось прочитать.",
    expired: "срок действия истёк",
    not_yet: "срок действия ещё не начался",
    not_for_signing: "не предназначен для подписи",
    expired_refusal: "Этим сертификатом нельзя подписать: срок его действия истёк.",
    not_yet_refusal: "Этим сертификатом нельзя подписать: срок его действия ещё не начался.",
    not_for_signing_refusal: "Этот сертификат не предназначен для подписи.",
    cert_row: "{0} ({1}){2}",
    consent_title: "Подтвердите применение вашего ключа",
    consent_lead: "Всё на этой странице, кроме рамки, написала программа OpenNCALayer. Если вы подтвердите, ваш ключ подпишет один раз и только то, что здесь описано.",
    c_operation: "Операция: {0}",
    c_plugin: "Плагин: {0}, версия {1}",
    c_package: "SHA-256 файла пакета плагина:",
    c_package_loose: "SHA-256 манифеста и модуля плагина:",
    c_uses: "Применений вашего ключа: {0}. Подтверждение действует один раз и не запоминается.",
    c_network_none: "Сеть: нет. Плагин ничего никуда отправить не может.",
    c_network_pki: "Сеть: только эти серверы национальной PKI: {0}. Плагин может отправить им документ или данные, полученные из него.",
    c_file: "Файл, выбранный вами: {0}",
    c_text_signed: "Подписывается текст, который вы ввели в {0}, ровно в том виде, как он перечислен ниже.",
    r_applied_no_reply: "Ваш ключ БЫЛ применён, но плагин не дал ответа и не сообщил об ошибке: создана ли подпись, это окно не знает.",
    c_size: "Размер: {0}",
    c_sha: "SHA-256 файла:",
    c_prehash: "Ключ подписывает хеш файла, который посчитала программа OpenNCALayer ({0}):",
    c_key_heading: "Ключ, которым подпишут",
    c_alias: "Имя в хранилище ключей: {0}",
    c_serial: "Серийный номер: {0}",
    c_subject: "Владелец (CN): {0}",
    c_no_subject: "Владелец (CN): не указан",
    c_valid: "Действителен до: {0}",
    c_fingerprint: "SHA-256 сертификата:",
    c_inputs: "Введённые вами значения, передаются плагину как есть (в то, что разрешается, не входят):",
    c_input_line: "{0} = {1}",
    c_choice_line: "Выбор {0}, один из предложенных плагином: {1}",
    no_reason: "причина не сообщена",
    row_code: "Код: {0}",
    e_text_bad: "В тексте {0} есть символ, который нельзя показать как введён (управляющий, невидимый или меняющий направление). Уберите его.",
    c_flag_yes: "да",
    c_flag_no: "нет",
    c_ttl: "После подтверждения у плагина {0} с на применение ключа; затем разрешение истекает и подтвердить нужно заново.",
    c_trust_note: "В рамке ниже собственные слова плагина. Они не проверены и в то, что вы разрешаете, не входят.",
    confirm_label: "Подписать плагином {0}",
    consent_cancel: "Отмена: не подписывать",
    consent_arming: "Кнопка заработает через мгновение после появления страницы.",
    preparing: "Готовится подтверждение: плагин не запущен, ваш ключ не применяется.",
    consent_idle: "Страница подтверждения простояла слишком долго и закрыта. Ничего не подписано, ключ не применялся.",
    key_idle: "Страница ключа простояла слишком долго и закрыта, пароль забыт. Ничего не подписано, ключ не применялся.",
    consent_invalid: "Это подтверждение нельзя показать безопасно: описание операции и подготовленное применение ключа не совпадают. Ничего не подписано.",
    running: "Плагин работает по вашему подтверждению. Ключ может применяться прямо сейчас. Отмена просит его остановиться; результат честно скажет, применялся ли ключ.",
    r_ok: "Плагин вернул ответ, ваш ключ применён один раз. OpenNCALayer не проверял подпись в ответе.",
    r_applied_failed: "Ваш ключ БЫЛ применён, но плагин завершился некорректно: {0}",
    r_unknown: "Неизвестно, применялся ли ваш ключ: применение не сообщило о себе. Считайте, что ключ мог быть применён.",
    r_not_applied: "Ничего не подписано: ваш ключ не применялся. {0}",
    r_cancelled_before: "Отменено: ваш ключ не применялся.",
    r_lost: "Рабочий поток неожиданно остановился после вашего подтверждения. Применялся ли ваш ключ, неизвестно.",
    r_cancel_slow: "Отмена запрошена, но плагин ещё не остановился. Эту страницу можно покинуть: плагин закончит работу в фоне, а применялся ли ваш ключ, неизвестно.",
    row_key_applied: "Применение ключа: выполнено",
    row_key_not_applied: "Применение ключа: не выполнялось",
    row_key_unknown: "Применение ключа: неизвестно",
    row_operation: "Операция: {0}",
    row_plugin: "Плагин: {0}, версия {1}",
    row_reason: "Причина: {0}",
    row_not_verified: "Подпись в ответе программа OpenNCALayer не проверяла.",
    reply_caption: "Ответ плагина (его собственный текст, не проверен; первые {0} символов):",
    reply_cut: "… ещё {0} символов не показано.",
    no_save: "Результат показан здесь и не сохраняется: у этого окна нет вывода плагинов в файл.",
    again: "Подготовить заново",
    finish: "К списку",
    f_no_ticket: "применение ключа не относилось к объявленной операции",
    f_no_approval: "для этого применения ключа не было разрешения",
    f_uses: "разрешение допускает не ровно одно применение",
    f_expired: "разрешение истекло до применения ключа (оно действует недолго после вашего подтверждения): подтвердите заново",
    f_operation_id: "разрешение выдано для другого запуска",
    f_identity: "разрешение выдано для другого плагина, пакета или версии",
    f_operation: "разрешение выдано для другой операции",
    f_caller: "разрешение выдано для другого вызывающего",
    f_key: "разрешение выдано для другого ключа",
    f_action: "вид применения ключа не подходит к содержимому",
    f_kind: "плагин запросил другой вид подписи, чем вы разрешили",
    f_content: "плагин пытался подписать другое содержимое, чем то, которое вы разрешили",
    f_options: "плагин запросил другие параметры подписи, чем вы разрешили",
    f_already_used: "разрешённое применение уже израсходовано",
    f_undeclared: "плагин не объявляет эту операцию",
    f_certificate_changed: "сертификат ключа не тот, что вы разрешили",
    f_no_guard: "в этой программе нет защиты разрешений для плагинов",
    f_busy: "выполняется другой вызов плагина: подтвердите заново, когда он закончится",
    f_replayed: "это разрешение уже использовалось",
    f_other: "применение ключа отклонено",
    p_not_runnable: "Эту операцию в этом окне выполнить нельзя.",
    p_too_large: "Файл или текст слишком велик для этой операции.",
    p_value: "Введённое вами значение операция не принимает.",
    p_key_unavailable: "Ключ не удалось открыть: проверьте пароль и хранилище.",
    p_cert_mismatch: "Сертификат в хранилище не тот, что показан в списке: хранилище изменилось.",
    p_unsupported_key: "Сертификат или алгоритм этого ключа нельзя использовать для этой операции.",
    p_no_key_use: "Эта операция не использует ключ.",
    p_options: "Текст для профиля подписи (например, XPath) недопустим.",
    p_budget: "Документ слишком велик для ограничений окна плагинов (или не хватает рабочей памяти программы). Выберите файл меньшего размера.",
    p_no_store: "Нет временного хранилища для подписи этого документа. Ничего не подписано.",
    p_other: "Операцию не удалось подготовить.",
    s_reading: "Читаются установленные плагины…",
    s_preparing: "Готовится подтверждение…",
    s_waiting: "Ожидается ваше подтверждение. Ключ не применяется, пока вы не подтвердите.",
    s_running: "Плагин работает…",
};

static KK: Texts = Texts {
    page_title: "Плагиндер",
    intro: "Мұнда осы терезе орындай алатын орнатылған плагиндердің әрекеттері тұр. Сіз файлды және өз кілтіңізді таңдайсыз; терезе кілттің нақты не үшін қолданылатынын көрсетеді, ал плагинге оны қолдануға тек сіздің растауыңыз рұқсат береді.",
    refresh: "Тізімді жаңарту",
    reading: "Орнатылған плагиндер оқылуда…",
    no_source: "Бағдарламаның осы іске қосылуында плагиндер қолжетімсіз.",
    none_offered: "Орнатылған плагиндердің ешқайсысы осы терезе үшін әрекет ұсынбайды.",
    plugin_heading: "{0} плагині, {1} нұсқасы",
    operation_heading: "Әрекет {0}",
    operation_invalid: "Атауы жарамсыз әрекет",
    key_use_yes: "Кілтіңізді пайдаланады; әр пайдалану сіздің растауыңызды қажет етеді.",
    key_use_no: "Кілтіңізді пайдаланбайды, растайтын ештеңе жоқ: бұл терезе оны іске қоспайды.",
    open_operation: "Ашу",
    open_label: "{0} әрекетін ашу",
    hidden_heading: "Бұл терезе үшін ештеңесі жоқ орнатылған плагиндер",
    without_ops: "{0} плагині, {1} нұсқасы: қолмен жұмыс терезесі үшін әрекеттер жоқ.",
    without_ops_why: "Себебін OpenNCALayer білмейді: пакетте бұл терезе үшін ештеңе жарияланбаған.",
    unusable: "{0} плагині: оның пакеті оқылмайды, сондықтан ұсынылмайды. Себебі журналда.",
    frame_name: "Плагиннің атауы (плагиннің өз сөзі, тексерілмеген):",
    form_title: "Әрекет {0}",
    form_intro: "{0} плагині, {1} нұсқасы. Файл мен кілтті таңдаңыз. Келесі беттерде растамайынша ештеңеге қол қойылмайды.",
    doc_label: "{0} құжаты: өзіңіз таңдайтын файл, ең көбі {1}",
    doc_placeholder: "Файлға жол",
    text_label: "{0} мәтіні (ең көбі {1} таңба)",
    choice_label: "{0} таңдауы",
    flag_label: "{0} параметрі",
    locale_label: "{0} тілі",
    store_label: "Кілттер қоймасы (PKCS#12, JKS)",
    store_placeholder: "Кілттер қоймасы файлына жол",
    continue_: "Жалғастыру",
    back: "Артқа",
    cancel: "Бас тарту",
    e_no_path: "{0} үшін файлды таңдаңыз.",
    e_unreadable: "{0} үшін файлды оқу мүмкін болмады.",
    e_too_big: "{0} үшін файл бұл әрекет қабылдайтыннан үлкен ({1}).",
    e_empty: "{0} үшін файл бос.",
    e_text_long: "{0} мәтіні {1} таңбадан ұзын.",
    e_no_store: "Кілттер қоймасының файлын көрсетіңіз.",
    busy: "Алдыңғы қадам әлі орындалуда. Күте тұрыңыз.",
    stale: "Орнатылған плагиндер жиыны өзгерді. Тізім қайта оқылды; әрекетті қайта таңдаңыз.",
    choose_one: "Таңдаңыз…",
    key_title: "Сіздің кілтіңіз",
    password_label: "Кілттер қоймасының құпиясөзі",
    open_store: "Қойманы ашу",
    choose_cert: "Сертификатты таңдаңыз",
    show_consent: "Нені рұқсат ететіндігін көрсету",
    no_password: "Құпиясөзді енгізіңіз.",
    wrong_password: "Қойма ашылмады: құпиясөз қате немесе бұл кілттер қоймасы емес.",
    store_unreadable: "Қойма файлын оқу мүмкін болмады.",
    expired: "жарамдылық мерзімі өткен",
    not_yet: "жарамдылық мерзімі әлі басталмаған",
    not_for_signing: "қол қоюға арналмаған",
    expired_refusal: "Бұл сертификатпен қол қоюға болмайды: оның мерзімі өткен.",
    not_yet_refusal: "Бұл сертификатпен қол қоюға болмайды: оның мерзімі әлі басталмаған.",
    not_for_signing_refusal: "Бұл сертификат қол қоюға арналмаған.",
    cert_row: "{0} ({1}){2}",
    consent_title: "Кілтіңізді пайдалануды растаңыз",
    consent_lead: "Жақтаудан басқа осы беттегі бәрін OpenNCALayer бағдарламасы жазды. Растасаңыз, кілтіңіз бір рет қана және тек осында сипатталғанға қол қояды.",
    c_operation: "Әрекет: {0}",
    c_plugin: "Плагин: {0}, {1} нұсқасы",
    c_package: "Плагин пакеті файлының SHA-256:",
    c_package_loose: "Плагиннің манифесі мен модулінің SHA-256:",
    c_uses: "Кілтіңізді пайдалану саны: {0}. Растау бір рет жұмыс істейді және есте сақталмайды.",
    c_network_none: "Желі: жоқ. Плагин ештеңені ешқайда жібере алмайды.",
    c_network_pki: "Желі: ұлттық PKI-дің тек мына серверлері: {0}. Плагин оларға құжатты немесе содан алынған деректерді жібере алады.",
    c_file: "Сіз таңдаған файл: {0}",
    c_text_signed: "{0} үшін сіз енгізген мәтін қол қойылады, төменде тізімделгендей дәл сол күйінде.",
    r_applied_no_reply: "Кілтіңіз қолданылды, бірақ плагин жауап бермеді және қате туралы хабарламады: қолтаңба жасалғаны бұл терезеге белгісіз.",
    c_size: "Көлемі: {0}",
    c_sha: "Файлдың SHA-256:",
    c_prehash: "Кілт OpenNCALayer есептеген файл дайджестіне қол қояды ({0}):",
    c_key_heading: "Қол қоятын кілт",
    c_alias: "Кілттер қоймасындағы аты: {0}",
    c_serial: "Сериялық нөмірі: {0}",
    c_subject: "Иесі (CN): {0}",
    c_no_subject: "Иесі (CN): көрсетілмеген",
    c_valid: "Жарамды: {0} дейін",
    c_fingerprint: "Сертификаттың SHA-256:",
    c_inputs: "Сіз енгізген мәндер, плагинге сол күйінде беріледі (рұқсат етілетін нәрсеге кірмейді):",
    c_input_line: "{0} = {1}",
    c_choice_line: "{0} таңдауы, плагин ұсынғандардың бірі: {1}",
    no_reason: "себебі хабарланбады",
    row_code: "Коды: {0}",
    e_text_bad: "{0} мәтінінде енгізілгендей көрсетуге болмайтын таңба бар (басқарушы, көрінбейтін немесе бағытты өзгертетін). Оны алып тастаңыз.",
    c_flag_yes: "иә",
    c_flag_no: "жоқ",
    c_ttl: "Растағаннан кейін плагинде кілтті пайдалану үшін {0} секунд бар; содан соң рұқсат мерзімі өтеді және қайта растау керек.",
    c_trust_note: "Төмендегі жақтауда плагиннің өз сөздері. Олар тексерілмеген және сіз рұқсат ететін нәрсеге кірмейді.",
    confirm_label: "{0} плагинімен қол қою",
    consent_cancel: "Бас тарту: қол қоймау",
    consent_arming: "Түйме бет шыққаннан кейін бір сәттен соң жұмыс істейді.",
    preparing: "Растау дайындалуда: плагин іске қосылмаған, кілтіңіз қолданылмайды.",
    consent_idle: "Растау беті тым ұзақ ашық тұрып, жабылды. Ештеңеге қол қойылмады, кілтіңіз қолданылмады.",
    key_idle: "Кілт беті тым ұзақ ашық тұрып, жабылды, құпиясөз ұмытылды. Ештеңеге қол қойылмады, кілтіңіз қолданылмады.",
    consent_invalid: "Бұл растауды қауіпсіз көрсету мүмкін емес: әрекеттің сипаттамасы мен дайындалған кілт қолданылуы сәйкес келмейді. Ештеңеге қол қойылмады.",
    running: "Плагин сіздің растауыңызбен жұмыс істеп тұр. Кілт дәл қазір қолданылуы мүмкін. Бас тарту оны тоқтауды сұрайды; нәтиже кілттің қолданылғанын адал айтады.",
    r_ok: "Плагин жауап қайтарды, кілтіңіз бір рет қолданылды. OpenNCALayer жауаптағы қолтаңбаны тексермеді.",
    r_applied_failed: "Кілтіңіз қолданылды, бірақ плагин дұрыс аяқталмады: {0}",
    r_unknown: "Кілтіңіздің қолданылғаны белгісіз: қолдану өзі туралы хабарлаған жоқ. Кілт қолданылған болуы мүмкін деп есептеңіз.",
    r_not_applied: "Ештеңеге қол қойылмады: кілтіңіз қолданылмады. {0}",
    r_cancelled_before: "Тоқтатылды: кілтіңіз қолданылмады.",
    r_lost: "Жұмыс ағыны сіз растағаннан кейін күтпеген жерден тоқтады. Кілтіңіздің қолданылғаны белгісіз.",
    r_cancel_slow: "Тоқтату сұралды, бірақ плагин әлі тоқтаған жоқ. Бұл беттен шығуға болады: плагин фонда аяқталады, ал кілтіңіздің қолданылғаны белгісіз.",
    row_key_applied: "Кілтті қолдану: орындалды",
    row_key_not_applied: "Кілтті қолдану: орындалмады",
    row_key_unknown: "Кілтті қолдану: белгісіз",
    row_operation: "Әрекет: {0}",
    row_plugin: "Плагин: {0}, {1} нұсқасы",
    row_reason: "Себебі: {0}",
    row_not_verified: "Жауаптағы қолтаңбаны OpenNCALayer тексерген жоқ.",
    reply_caption: "Плагиннің жауабы (оның өз мәтіні, тексерілмеген; алғашқы {0} таңба):",
    reply_cut: "… тағы {0} таңба көрсетілмеген.",
    no_save: "Нәтиже осында көрсетіледі және сақталмайды: бұл терезеде плагиндерді файлға шығару жоқ.",
    again: "Қайта дайындау",
    finish: "Тізімге",
    f_no_ticket: "кілтті қолдану жарияланған әрекетке жатпады",
    f_no_approval: "бұл кілт қолдануға рұқсат болмады",
    f_uses: "рұқсат дәл бір рет қолдануға жол бермейді",
    f_expired: "кілт қолданылмай тұрып рұқсат мерзімі өтті (ол растағаннан кейін қысқа уақыт жарамды): қайта растаңыз",
    f_operation_id: "рұқсат басқа іске қосу үшін берілген",
    f_identity: "рұқсат басқа плагин, пакет немесе нұсқа үшін берілген",
    f_operation: "рұқсат басқа әрекет үшін берілген",
    f_caller: "рұқсат басқа шақырушы үшін берілген",
    f_key: "рұқсат басқа кілт үшін берілген",
    f_action: "кілтті қолдану түрі мазмұнға сәйкес емес",
    f_kind: "плагин сіз рұқсат еткеннен басқа қолтаңба түрін сұрады",
    f_content: "плагин сіз рұқсат еткеннен басқа мазмұнға қол қоймақ болды",
    f_options: "плагин сіз рұқсат еткеннен басқа қолтаңба параметрлерін сұрады",
    f_already_used: "рұқсат етілген қолдану бұрын жұмсалған",
    f_undeclared: "плагин бұл әрекетті жарияламайды",
    f_certificate_changed: "кілттің сертификаты сіз рұқсат еткен сертификат емес",
    f_no_guard: "бұл бағдарламада плагиндерге арналған рұқсат қорғанысы жоқ",
    f_busy: "плагиннің басқа шақыруы орындалып жатыр: ол біткенде қайта растаңыз",
    f_replayed: "бұл рұқсат бұрын қолданылған",
    f_other: "кілтті қолдану қабылданбады",
    p_not_runnable: "Бұл әрекетті осы терезеде орындау мүмкін емес.",
    p_too_large: "Файл немесе мәтін бұл әрекет үшін тым үлкен.",
    p_value: "Сіз енгізген мәнді әрекет қабылдамайды.",
    p_key_unavailable: "Кілтті ашу мүмкін болмады: құпиясөзді және қойманы тексеріңіз.",
    p_cert_mismatch: "Қоймадағы сертификат тізімде көрсетілгенмен бірдей емес: қойма өзгерген.",
    p_unsupported_key: "Бұл кілттің сертификатын немесе алгоритмін осы әрекет үшін қолдануға болмайды.",
    p_no_key_use: "Бұл әрекет кілтті пайдаланбайды.",
    p_options: "Қолтаңба профилі үшін мәтін (мысалы, XPath) жарамсыз.",
    p_budget: "Құжат плагин терезесінің шектеулері үшін тым үлкен (немесе бағдарламаның жұмыс жады жетпейді). Кіші файлды таңдаңыз.",
    p_no_store: "Бұл құжатқа қол қою үшін уақытша сақтау орны жоқ. Ештеңеге қол қойылмады.",
    p_other: "Әрекетті дайындау мүмкін болмады.",
    s_reading: "Орнатылған плагиндер оқылуда…",
    s_preparing: "Растау дайындалуда…",
    s_waiting: "Сіздің растауыңыз күтілуде. Растағанша кілт қолданылмайды.",
    s_running: "Плагин жұмыс істеп тұр…",
};

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Locale; 3] = [Locale::Ru, Locale::Kk, Locale::En];
    /// Texts that are only placeholders: the same in every language.
    const NEUTRAL: [&str; 2] = ["c_input_line", "cert_row"];

    fn placeholders(text: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}') else {
                break;
            };
            found.push(rest[open..open + close + 1].to_owned());
            rest = &rest[open + close + 1..];
        }
        found.sort();
        found
    }

    fn cyrillic(text: &str) -> bool {
        text.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
    }

    #[test]
    fn every_text_exists_in_every_language_with_the_same_placeholders() {
        let ru = Texts::of(Locale::Ru).fields();
        let kk = Texts::of(Locale::Kk).fields();
        let en = Texts::of(Locale::En).fields();
        assert_eq!(ru.len(), en.len());
        assert!(ru.len() > 120, "the table is not the page's: {}", ru.len());
        for l in ALL {
            for (name, text) in Texts::of(l).fields() {
                assert!(!text.trim().is_empty(), "{name} is empty in {l:?}");
                assert!(
                    !text.contains("TODO") && !text.contains("todo"),
                    "{name} in {l:?}"
                );
            }
        }
        for ((name, ru_text), ((_, kk_text), (_, en_text))) in ru.iter().zip(kk.iter().zip(&en)) {
            let expected = placeholders(en_text);
            assert_eq!(placeholders(ru_text), expected, "{name}: ru placeholders");
            assert_eq!(placeholders(kk_text), expected, "{name}: kk placeholders");
        }
    }

    #[test]
    fn each_language_is_written_in_its_own_script() {
        for (name, text) in Texts::of(Locale::En).fields() {
            assert!(!cyrillic(text), "{name}: English holds Cyrillic: {text}");
        }
        for l in [Locale::Ru, Locale::Kk] {
            for (name, text) in Texts::of(l).fields() {
                if NEUTRAL.contains(&name) {
                    continue;
                }
                assert!(cyrillic(text), "{name} in {l:?} is not Cyrillic: {text}");
            }
        }
        // No language is a copy of another (a table filled by pasting).
        let ru = Texts::of(Locale::Ru).fields();
        let kk = Texts::of(Locale::Kk).fields();
        let en = Texts::of(Locale::En).fields();
        for (((name, r), (_, k)), (_, e)) in ru.iter().zip(&kk).zip(&en) {
            if NEUTRAL.contains(name) {
                continue;
            }
            assert_ne!(r, k, "{name}: the Kazakh text is the Russian one");
            assert_ne!(r, e, "{name}: the Russian text is the English one");
            assert_ne!(k, e, "{name}: the Kazakh text is the English one");
        }
    }

    #[test]
    fn the_button_that_confirms_names_the_action_in_every_language() {
        for l in ALL {
            let t = Texts::of(l);
            assert!(
                t.confirm_label.contains("{0}"),
                "{l:?}: names the operation"
            );
            for plain in ["OK", "Ok", "ОК", "Next", "Далее", "Продолжить", "Continue"]
            {
                assert_ne!(t.confirm_label, plain);
            }
            // The cancel button says what it does too.
            assert!(t.consent_cancel.len() > 6);
        }
    }
}
