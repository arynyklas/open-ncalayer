//! The pages of the tools that use no private key: verify, extend, extract and the timestamp
//! tools, on one shared page ([`ToolState`]). The page holds the documents (their paths and
//! sizes, never their bytes), what the tool is asked to do and where its results go; the work
//! runs on a worker through the SDK's batch ([`super::run_tool`]), and the report that comes
//! back is the SDK's own, shown as it is ([`crate::reports`]).
//!
//! The button that names the action is the user's approval of exactly the list and the
//! destination shown above it: nothing is read or written before it is pressed, and the list
//! cannot change while the batch runs (the page's fields wait).

use std::path::PathBuf;
use std::rc::Rc;

use oncl_flows::Locale;
use oncl_pki::key::HashAlg;
use slint::{ComponentHandle, ModelRc, SharedString, StandardListViewItem, VecModel};

use super::controller::{Job, JobError, MissingField};
use super::{
    Destination, Document, ExtendFormat, Level, Output, StampOptions, ToolSpec, VerifyFormat,
    VerifyOptions, Workspace, run_tool, start, with_open,
};
use crate::reports::controller::BatchView;
use crate::ui::ToolState;

/// How many documents a batch of a tool may hold.
const MAX_DOCUMENTS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tool {
    Verify = 0,
    Extend = 1,
    Extract = 2,
    Timestamp = 3,
}

impl Tool {
    fn of_section(section: i32) -> Option<Tool> {
        match section {
            2 => Some(Tool::Verify),
            3 => Some(Tool::Extend),
            4 => Some(Tool::Extract),
            5 => Some(Tool::Timestamp),
            _ => None,
        }
    }
}

/// The pages' state on the event loop: the documents of each tool.
#[derive(Default)]
pub(super) struct State {
    docs: [Vec<Document>; 4],
    /// The tool whose page is shown.
    tool: Option<usize>,
}

pub(super) fn connect(ui: &crate::ui::WorkspaceWindow) {
    let s = ui.global::<ToolState>();
    s.on_add_doc(|| with_open(add_doc));
    s.on_clear_docs(|| with_open(clear_docs));
    s.on_browse_doc(|| with_open(|open| browse(open, Target::First)));
    s.on_browse_second(|| with_open(|open| browse(open, Target::Second)));
    s.on_browse_folder(|| with_open(|open| browse(open, Target::Folder)));
    s.on_changed(|| with_open(render));
    s.on_run(|| with_open(run));
    ui.on_section_changed(|section| with_open(|open| selected(open, section)));
}

fn texts(open: &Rc<Workspace>) -> &'static ToolTexts {
    ToolTexts::of(open.locale.get())
}

fn current(open: &Rc<Workspace>) -> Option<Tool> {
    Tool::of_section(open.ui.get_section())
}

/// The sidebar picked a page: if it is one of these, its fields start from their defaults and
/// its documents are the ones this window gathered for it.
pub(super) fn selected(open: &Rc<Workspace>, section: i32) {
    let Some(tool) = Tool::of_section(section) else {
        return;
    };
    open.tools.borrow_mut().tool = Some(tool as usize);
    let ui = open.ui.global::<ToolState>();
    ui.set_format_index(0);
    ui.set_level_index(0);
    ui.set_destination_index(0);
    ui.set_destination_path("".into());
    ui.set_doc_path("".into());
    ui.set_second_path("".into());
    ui.set_show_advanced(false);
    ui.set_opt1("".into());
    ui.set_opt2("".into());
    ui.set_flag1(false);
    ui.set_flag2(false);
    clear_report(open);
    render(open);
}

/// Sets what the page shows for the tool and the format chosen: the labels, the lists, which
/// fields are there.
pub(super) fn render(open: &Rc<Workspace>) {
    let Some(tool) = current(open) else {
        return;
    };
    let t = texts(open);
    let ui = open.ui.global::<ToolState>();
    let format = ui.get_format_index();
    let level = ui.get_level_index();
    let list = |items: &[&str]| -> ModelRc<SharedString> {
        ModelRc::new(VecModel::from(
            items
                .iter()
                .map(|s| SharedString::from(*s))
                .collect::<Vec<_>>(),
        ))
    };
    let i = tool as usize;
    ui.set_title(t.titles[i].into());
    ui.set_hint(t.hints[i].into());
    ui.set_first_label(t.first_labels[i].into());
    // Defaults; each tool turns on what it uses.
    ui.set_formats(list(&[]));
    ui.set_show_level(false);
    ui.set_show_second(false);
    ui.set_show_destination(false);
    ui.set_has_advanced(false);
    ui.set_show_opt1(false);
    ui.set_show_opt2(false);
    ui.set_show_flag1(false);
    ui.set_show_flag2(false);
    ui.set_second_label(t.second_data.into());
    match tool {
        Tool::Verify => {
            ui.set_format_label(t.verify_format_label.into());
            ui.set_formats(list(&t.verify_formats));
            ui.set_level_label(t.verify_level_label.into());
            ui.set_levels(list(&t.verify_levels));
            ui.set_show_level(matches!(format, 0 | 1 | 3));
            ui.set_show_second(format == 0);
            ui.set_has_advanced(true);
            ui.set_show_flag1(true);
            ui.set_flag1_label(t.offline.into());
            match (format, level) {
                (1, 0) => {
                    ui.set_show_flag2(true);
                    ui.set_flag2_label(t.kalkan.into());
                }
                (2, _) => {
                    ui.set_show_flag2(true);
                    ui.set_flag2_label(t.timestamp_required.into());
                }
                _ => {}
            }
            if format == 5 {
                ui.set_show_opt1(true);
                ui.set_opt1_label(t.issuer.into());
                ui.set_show_opt2(true);
                ui.set_opt2_label(t.audience.into());
            }
        }
        Tool::Extend => {
            ui.set_format_label(t.extend_format_label.into());
            ui.set_formats(list(&t.extend_formats));
            ui.set_level_label(t.extend_level_label.into());
            ui.set_levels(list(&t.extend_levels));
            ui.set_show_level(true);
            ui.set_show_second(format == 0);
            ui.set_show_destination(true);
        }
        Tool::Extract => {
            ui.set_show_destination(true);
        }
        Tool::Timestamp => {
            ui.set_format_label(t.stamp_mode_label.into());
            ui.set_formats(list(&t.stamp_modes));
            ui.set_level_label(t.stamp_hash_label.into());
            ui.set_levels(list(&t.stamp_hashes));
            ui.set_show_level(true);
            ui.set_has_advanced(true);
            if format == 0 {
                ui.set_show_destination(true);
                ui.set_show_opt1(true);
                ui.set_opt1_label(t.tsa_url.into());
            } else {
                ui.set_show_second(true);
                ui.set_second_label(t.stamp_data.into());
                ui.set_show_opt1(true);
                ui.set_opt1_label(t.policy.into());
                ui.set_show_opt2(true);
                ui.set_opt2_label(t.max_age.into());
            }
        }
    }
    ui.set_action_label(
        match (tool, format) {
            (Tool::Verify, _) => t.act_verify,
            (Tool::Extend, _) => t.act_extend,
            (Tool::Extract, _) => t.act_extract,
            (Tool::Timestamp, 0) => t.act_stamp,
            (Tool::Timestamp, _) => t.act_stamp_check,
        }
        .into(),
    );
    ui.set_first_label(
        if tool == Tool::Timestamp && format == 1 {
            t.stamp_token
        } else {
            t.first_labels[i]
        }
        .into(),
    );
    let docs = &open.tools.borrow().docs[i];
    ui.set_docs(ModelRc::new(VecModel::from(
        docs.iter()
            .map(|d| StandardListViewItem::from(doc_line(open.locale.get(), d).as_str()))
            .collect::<Vec<_>>(),
    )));
}

fn doc_line(locale: Locale, d: &Document) -> String {
    let size = match std::fs::metadata(&d.path) {
        Ok(meta) => super::size(super::Texts::of(locale), meta.len()),
        Err(_) => "?".to_owned(),
    };
    match &d.second {
        Some(second) => format!("{} — {size} + {}", d.path.display(), second.display()),
        None => format!("{} — {size}", d.path.display()),
    }
}

fn error(open: &Rc<Workspace>, error: &JobError) {
    super::reject(open, open.ui.get_section(), error);
}

fn add_doc(open: &Rc<Workspace>) {
    let Some(tool) = current(open) else {
        return;
    };
    if open.ui.get_busy() {
        return;
    }
    let ui = open.ui.global::<ToolState>();
    let path = super::typed_path(ui.get_doc_path());
    if path.is_empty() {
        return error(open, &JobError::Input(MissingField::Path));
    }
    let second = ui
        .get_show_second()
        .then(|| super::typed_path(ui.get_second_path()))
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    let path = PathBuf::from(path);
    for p in std::iter::once(&path).chain(second.iter()) {
        match std::fs::metadata(p) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return error(open, &JobError::NotRegular),
            Err(e) => return error(open, &JobError::from(e)),
        }
    }
    {
        let mut state = open.tools.borrow_mut();
        let docs = &mut state.docs[tool as usize];
        if docs.len() >= MAX_DOCUMENTS {
            drop(state);
            return error(open, &JobError::Operation(oncl_core::ErrorCode::InputLimit));
        }
        docs.retain(|d| d.path != path);
        docs.push(Document { path, second });
    }
    open.ui.set_error_text("".into());
    ui.set_doc_path("".into());
    ui.set_second_path("".into());
    clear_report(open);
    render(open);
}

fn clear_docs(open: &Rc<Workspace>) {
    if open.ui.get_busy() {
        return;
    }
    if let Some(tool) = current(open) {
        open.tools.borrow_mut().docs[tool as usize].clear();
    }
    clear_report(open);
    render(open);
}

fn clear_report(open: &Rc<Workspace>) {
    let ui = open.ui.global::<ToolState>();
    ui.set_report_headline("".into());
    ui.set_report_tone(3);
    ui.set_report_rows(ModelRc::default());
}

#[derive(Clone, Copy)]
enum Target {
    First,
    Second,
    Folder,
}

/// «Обзор…»: the system dialog; the chosen path goes into the page's field.
fn browse(open: &Rc<Workspace>, target: Target) {
    let t = super::Texts::of(open.locale.get());
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(match target {
            Target::Folder => t.pick_folder_title,
            _ => t.pick_title,
        })
        .set_parent(&open.ui.window().window_handle());
    let picked = slint::spawn_local(async move {
        let path = match target {
            Target::Folder => dialog.pick_folder().await,
            _ => dialog.pick_file().await,
        };
        let Some(path) = path else {
            return;
        };
        let path = path.path().display().to_string();
        with_open(|open| {
            let ui = open.ui.global::<ToolState>();
            match target {
                Target::First => ui.set_doc_path(path.into()),
                Target::Second => ui.set_second_path(path.into()),
                Target::Folder => ui.set_destination_path(path.into()),
            }
        });
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the dialog");
    }
}

/// What the page asks for, read from its fields when the button is pressed.
fn read_choice(open: &Rc<Workspace>) -> Result<(ToolSpec, Destination), JobError> {
    let tool = current(open).ok_or(JobError::Worker)?;
    let ui = open.ui.global::<ToolState>();
    let (format, level) = (ui.get_format_index(), ui.get_level_index());
    let required = |l: i32| match l {
        1 => Level::B,
        2 => Level::T,
        3 => Level::Lt,
        _ => Level::Lta,
    };
    let spec = match tool {
        Tool::Verify => {
            let options = VerifyOptions {
                offline: ui.get_flag1(),
                issuer: if format == 5 {
                    ui.get_opt1().trim().to_owned()
                } else {
                    String::new()
                },
                audience: if format == 5 {
                    ui.get_opt2().trim().to_owned()
                } else {
                    String::new()
                },
                timestamp_required: format == 2 && ui.get_flag2(),
            };
            let verify = match (format, level) {
                (0, 0) => VerifyFormat::Cms,
                (0, l) => VerifyFormat::Cades(required(l)),
                (1, 0) if ui.get_flag2() => VerifyFormat::XmlKalkan,
                (1, 0) => VerifyFormat::Xml,
                (1, l) => VerifyFormat::Xades(required(l)),
                (2, _) => VerifyFormat::Wsse,
                (3, 0) => VerifyFormat::Pdf,
                (3, l) => VerifyFormat::Pades(required(l)),
                (4, _) => VerifyFormat::Jws,
                _ => VerifyFormat::Jwt,
            };
            ToolSpec::Verify(verify, options)
        }
        Tool::Extend => {
            let target = match level {
                0 => Level::T,
                1 => Level::Lt,
                _ => Level::Lta,
            };
            ToolSpec::Extend(match format {
                0 => ExtendFormat::Cms(target),
                1 => ExtendFormat::Xml(target),
                _ => ExtendFormat::Pdf(target),
            })
        }
        Tool::Extract => ToolSpec::Extract,
        Tool::Timestamp => {
            let algorithm = match level {
                1 => HashAlg::Gost34311,
                2 => HashAlg::Streebog512,
                _ => HashAlg::Sha256,
            };
            if format == 0 {
                ToolSpec::Stamp(StampOptions {
                    tsa_url: ui.get_opt1().trim().to_owned(),
                    algorithm,
                    ..StampOptions::default()
                })
            } else {
                let age = ui.get_opt2();
                let max_age = match age.trim() {
                    "" => 0,
                    text => text
                        .parse()
                        .map_err(|_| JobError::Operation(oncl_core::ErrorCode::InvalidInput))?,
                };
                ToolSpec::StampCheck(StampOptions {
                    algorithm,
                    policy: ui.get_opt1().trim().to_owned(),
                    max_age,
                    ..StampOptions::default()
                })
            }
        }
    };
    let writes = matches!(
        spec,
        ToolSpec::Extend(_) | ToolSpec::Extract | ToolSpec::Stamp(_)
    );
    let destination = if writes && ui.get_destination_index() == 1 {
        let folder = super::typed_path(ui.get_destination_path());
        if folder.is_empty() {
            return Err(JobError::Input(MissingField::Folder));
        }
        Destination::Folder(PathBuf::from(folder))
    } else {
        Destination::Beside
    };
    Ok((spec, destination))
}

fn run(open: &Rc<Workspace>) {
    let Some(tool) = current(open) else {
        return;
    };
    if open.ui.get_busy() {
        return;
    }
    let (spec, destination) = match read_choice(open) {
        Ok(choice) => choice,
        Err(e) => return error(open, &e),
    };
    let documents = open.tools.borrow().docs[tool as usize].clone();
    if documents.is_empty() {
        return error(open, &JobError::Input(MissingField::Path));
    }
    clear_report(open);
    start(open, Job::Tool, move |services, control| {
        let now = (services.clock)().unix_timestamp();
        let view = run_tool(
            &services.engine,
            &spec,
            &documents,
            &destination,
            now,
            control,
        )?;
        Ok(Output::Tool(view))
    });
}

/// The report of a run reaches its page.
pub(super) fn settled(
    open: &Rc<Workspace>,
    view: &BatchView,
) -> (crate::reports::controller::Tone, String) {
    let rendered = crate::reports::render(open.locale.get(), view);
    let ui = open.ui.global::<ToolState>();
    ui.set_report_headline(rendered.headline.as_str().into());
    ui.set_report_tone(crate::reports::tone_number(rendered.tone));
    ui.set_report_rows(super::report_rows(&rendered.rows));
    (rendered.tone, rendered.headline)
}

// ---- texts ----

struct ToolTexts {
    /// Per tool: verify, extend, extract, timestamp.
    titles: [&'static str; 4],
    hints: [&'static str; 4],
    first_labels: [&'static str; 4],
    second_data: &'static str,
    verify_format_label: &'static str,
    verify_formats: [&'static str; 6],
    verify_level_label: &'static str,
    verify_levels: [&'static str; 5],
    extend_format_label: &'static str,
    extend_formats: [&'static str; 3],
    extend_level_label: &'static str,
    extend_levels: [&'static str; 3],
    stamp_mode_label: &'static str,
    stamp_modes: [&'static str; 2],
    stamp_hash_label: &'static str,
    stamp_hashes: [&'static str; 3],
    stamp_token: &'static str,
    stamp_data: &'static str,
    offline: &'static str,
    kalkan: &'static str,
    timestamp_required: &'static str,
    issuer: &'static str,
    audience: &'static str,
    tsa_url: &'static str,
    policy: &'static str,
    max_age: &'static str,
    act_verify: &'static str,
    act_extend: &'static str,
    act_extract: &'static str,
    act_stamp: &'static str,
    act_stamp_check: &'static str,
}

impl ToolTexts {
    fn of(l: Locale) -> &'static ToolTexts {
        match l {
            Locale::Ru => &RU,
            Locale::Kk => &KK,
            Locale::En => &EN,
        }
    }
}

static RU: ToolTexts = ToolTexts {
    titles: [
        "Проверка подписей",
        "Продление подписей",
        "Извлечение содержимого",
        "Метки времени",
    ],
    hints: [
        "Проверка ничего не подписывает и не меняет. Отчёт разделяет «подпись действительна», «не удалось полностью проверить» и «недействительна»: только первое — подтверждение.",
        "К подписи добавляются метка времени и данные проверки (CAdES, XAdES, PAdES). Исходная подпись не меняется, результат пишется новым файлом; ключ не применяется.",
        "Содержимое достаётся из контейнера подписи как есть. Подпись при этом не проверяется: для проверки используйте «Проверка подписей».",
        "Получить метку времени для файла у службы времени или проверить готовую метку. Ключ не применяется.",
    ],
    first_labels: [
        "Файл подписи или подписанный документ",
        "Подписанный файл",
        "Контейнер подписи (.p7s, .p7m)",
        "Файл, для которого нужна метка времени",
    ],
    second_data: "Подписанные данные (только для откреплённой подписи)",
    verify_format_label: "Формат подписи",
    verify_formats: [
        "CMS / CAdES (файл подписи)",
        "XML (XMLDSig / XAdES)",
        "SOAP-сообщение (WS-Security)",
        "PDF (PAdES)",
        "JWS (JSON Web Signature)",
        "JWT (подписанный токен)",
    ],
    verify_level_label: "Требуемый уровень",
    verify_levels: [
        "Любая подпись, уровень не требуется",
        "Не ниже B",
        "Не ниже T (с меткой времени)",
        "Не ниже LT (с данными проверки)",
        "Не ниже LTA (для долгого хранения)",
    ],
    extend_format_label: "Формат подписи",
    extend_formats: ["CMS / CAdES", "XML / XAdES", "PDF / PAdES"],
    extend_level_label: "Целевой уровень",
    extend_levels: [
        "T: с меткой времени",
        "LT: с данными проверки",
        "LTA: для долгого хранения",
    ],
    stamp_mode_label: "Действие",
    stamp_modes: ["Получить метку времени", "Проверить метку времени"],
    stamp_hash_label: "Алгоритм хеширования",
    stamp_hashes: ["SHA-256", "ГОСТ Р 34.11-94", "ГОСТ Р 34.11-2012 (512)"],
    stamp_token: "Файл метки времени (.tst)",
    stamp_data: "Данные, которых касается метка (без них связь с документом не проверяется)",
    offline: "Без сети: статус отзыва не запрашивать (результат будет неполным)",
    kalkan: "Режим совместимости с Kalkan (прежний формат XML)",
    timestamp_required: "Метка времени в сообщении обязательна",
    issuer: "Ожидаемый издатель (iss)",
    audience: "Ожидаемый адресат (aud)",
    tsa_url: "Служба времени (пусто: национальная)",
    policy: "Политика метки (OID), если она обязательна",
    max_age: "Наибольший возраст метки, секунд (пусто: не проверять)",
    act_verify: "Проверить",
    act_extend: "Продлить",
    act_extract: "Извлечь содержимое",
    act_stamp: "Получить метку времени",
    act_stamp_check: "Проверить метку времени",
};

static KK: ToolTexts = ToolTexts {
    titles: [
        "Қолтаңбаларды тексеру",
        "Қолтаңбаларды ұзарту",
        "Мазмұнды шығару",
        "Уақыт белгілері",
    ],
    hints: [
        "Тексеру ештеңеге қол қоймайды және өзгертпейді. Есеп «қолтаңба жарамды», «толық тексеру мүмкін болмады» және «жарамсыз» дегенді ажыратады: тек біріншісі растау болып табылады.",
        "Қолтаңбаға уақыт белгісі мен тексеру деректері қосылады (CAdES, XAdES, PAdES). Бастапқы қолтаңба өзгермейді, нәтиже жаңа файлға жазылады; кілт қолданылмайды.",
        "Мазмұн қолтаңба контейнерінен сол күйінде алынады. Қолтаңба тексерілмейді: тексеру үшін «Қолтаңбаларды тексеру» бөлімін пайдаланыңыз.",
        "Файлға уақыт қызметінен уақыт белгісін алу немесе дайын белгіні тексеру. Кілт қолданылмайды.",
    ],
    first_labels: [
        "Қолтаңба файлы немесе қол қойылған құжат",
        "Қол қойылған файл",
        "Қолтаңба контейнері (.p7s, .p7m)",
        "Уақыт белгісі қажет файл",
    ],
    second_data: "Қол қойылған деректер (тек бөлек қолтаңба үшін)",
    verify_format_label: "Қолтаңба пішімі",
    verify_formats: [
        "CMS / CAdES (қолтаңба файлы)",
        "XML (XMLDSig / XAdES)",
        "SOAP хабарламасы (WS-Security)",
        "PDF (PAdES)",
        "JWS (JSON Web Signature)",
        "JWT (қол қойылған токен)",
    ],
    verify_level_label: "Қажетті деңгей",
    verify_levels: [
        "Кез келген қолтаңба, деңгей қажет емес",
        "B-дан төмен емес",
        "T-дан төмен емес (уақыт белгісімен)",
        "LT-дан төмен емес (тексеру деректерімен)",
        "LTA-дан төмен емес (ұзақ сақтауға)",
    ],
    extend_format_label: "Қолтаңба пішімі",
    extend_formats: ["CMS / CAdES", "XML / XAdES", "PDF / PAdES"],
    extend_level_label: "Мақсатты деңгей",
    extend_levels: [
        "T: уақыт белгісімен",
        "LT: тексеру деректерімен",
        "LTA: ұзақ сақтауға",
    ],
    stamp_mode_label: "Әрекет",
    stamp_modes: ["Уақыт белгісін алу", "Уақыт белгісін тексеру"],
    stamp_hash_label: "Хештеу алгоритмі",
    stamp_hashes: ["SHA-256", "ГОСТ Р 34.11-94", "ГОСТ Р 34.11-2012 (512)"],
    stamp_token: "Уақыт белгісінің файлы (.tst)",
    stamp_data: "Белгі қатысты деректер (оларсыз белгінің құжатпен байланысы тексерілмейді)",
    offline: "Желісіз: күшін жою күйін сұрамау (нәтиже толық болмайды)",
    kalkan: "Kalkan үйлесімділік режимі (бұрынғы XML пішімі)",
    timestamp_required: "Хабарламада уақыт белгісі міндетті",
    issuer: "Күтілетін шығарушы (iss)",
    audience: "Күтілетін алушы (aud)",
    tsa_url: "Уақыт қызметі (бос: ұлттық)",
    policy: "Белгі саясаты (OID), міндетті болса",
    max_age: "Белгінің ең үлкен жасы, секунд (бос: тексермеу)",
    act_verify: "Тексеру",
    act_extend: "Ұзарту",
    act_extract: "Мазмұнды шығару",
    act_stamp: "Уақыт белгісін алу",
    act_stamp_check: "Уақыт белгісін тексеру",
};

static EN: ToolTexts = ToolTexts {
    titles: [
        "Verify signatures",
        "Extend signatures",
        "Extract content",
        "Timestamps",
    ],
    hints: [
        "Verifying signs and changes nothing. The report keeps «the signature is valid», «could not be fully checked» and «invalid» apart: only the first is a confirmation.",
        "A time stamp and validation data are added to the signature (CAdES, XAdES, PAdES). The original signature is not changed and the result is written as a new file; no key is used.",
        "The content is taken out of the signature container as it is. The signature is not checked: use «Verify signatures» for that.",
        "Get a time stamp for a file from a time service, or check a time stamp you have. No key is used.",
    ],
    first_labels: [
        "Signature file or signed document",
        "Signed file",
        "Signature container (.p7s, .p7m)",
        "File to get a time stamp for",
    ],
    second_data: "Signed data (only for a detached signature)",
    verify_format_label: "Format of the signature",
    verify_formats: [
        "CMS / CAdES (signature file)",
        "XML (XMLDSig / XAdES)",
        "SOAP message (WS-Security)",
        "PDF (PAdES)",
        "JWS (JSON Web Signature)",
        "JWT (signed token)",
    ],
    verify_level_label: "Required level",
    verify_levels: [
        "Any signature, no level required",
        "At least B",
        "At least T (with a time stamp)",
        "At least LT (with validation data)",
        "At least LTA (for long-term archival)",
    ],
    extend_format_label: "Format of the signature",
    extend_formats: ["CMS / CAdES", "XML / XAdES", "PDF / PAdES"],
    extend_level_label: "Target level",
    extend_levels: [
        "T: with a time stamp",
        "LT: with validation data",
        "LTA: for long-term archival",
    ],
    stamp_mode_label: "Action",
    stamp_modes: ["Get a time stamp", "Check a time stamp"],
    stamp_hash_label: "Hash algorithm",
    stamp_hashes: ["SHA-256", "GOST R 34.11-94", "GOST R 34.11-2012 (512)"],
    stamp_token: "Time stamp file (.tst)",
    stamp_data: "The data the time stamp is of (without it the tie to a document is not checked)",
    offline: "No network: do not ask for revocation status (the result will be incomplete)",
    kalkan: "Kalkan compatibility mode (the earlier XML format)",
    timestamp_required: "A timestamp in the message is required",
    issuer: "Expected issuer (iss)",
    audience: "Expected audience (aud)",
    tsa_url: "Time service (empty: the national one)",
    policy: "Time stamp policy (OID), if it is required",
    max_age: "Oldest age of the time stamp, seconds (empty: not checked)",
    act_verify: "Verify",
    act_extend: "Extend",
    act_extract: "Extract the content",
    act_stamp: "Get a time stamp",
    act_stamp_check: "Check the time stamp",
};
