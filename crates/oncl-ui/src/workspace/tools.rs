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
    /// One list per tool (verify, extend, extract, timestamp) and one for checking time stamps,
    /// which takes tokens and not the documents getting one.
    docs: [Vec<Document>; 5],
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

/// Which list of documents the page works on: the tool's own; checking a time stamp has its own,
/// so that the files to be stamped are not checked as tokens.
fn slot(open: &Rc<Workspace>) -> usize {
    match current(open) {
        Some(Tool::Timestamp) if open.ui.global::<ToolState>().get_format_index() == 1 => 4,
        Some(tool) => tool as usize,
        None => 0,
    }
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
    ui.set_evidence_certificates("".into());
    ui.set_evidence_ocsp("".into());
    ui.set_evidence_crls("".into());
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
    ui.set_show_evidence(false);
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
            // LT and LTA (levels 1 and 2 of the list) of CAdES and PAdES need the files their
            // evidence is built from; XAdES fetches its own.
            ui.set_show_evidence(matches!(format, 0 | 2) && level >= 1);
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
    let docs = &open.tools.borrow().docs[slot(open)];
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
    if current(open).is_none() {
        return;
    }
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
        let docs = &mut state.docs[slot(open)];
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
    if current(open).is_some() {
        let at = slot(open);
        open.tools.borrow_mut().docs[at].clear();
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
            let extend = match format {
                0 => ExtendFormat::Cms(target),
                1 => ExtendFormat::Xml(target),
                _ => ExtendFormat::Pdf(target),
            };
            let evidence = if extend.needs_material() {
                super::Evidence::from_fields(
                    &ui.get_evidence_certificates(),
                    &ui.get_evidence_ocsp(),
                    &ui.get_evidence_crls(),
                )
            } else {
                super::Evidence::default()
            };
            ToolSpec::Extend(extend, evidence)
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
        ToolSpec::Extend(..) | ToolSpec::Extract | ToolSpec::Stamp(_)
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
    if current(open).is_none() {
        return;
    }
    if open.ui.get_busy() {
        return;
    }
    let (spec, destination) = match read_choice(open) {
        Ok(choice) => choice,
        Err(e) => return error(open, &e),
    };
    let documents = open.tools.borrow().docs[slot(open)].clone();
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
    policy: "Time stamp policy (OID), if it is required",
    max_age: "Oldest age of the time stamp, seconds (empty: not checked)",
    act_verify: "Verify",
    act_extend: "Extend",
    act_extract: "Extract the content",
    act_stamp: "Get a time stamp",
    act_stamp_check: "Check the time stamp",
};

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use std::path::Path;

    use oncl_token::Tokens;
    use slint::Model as _;

    use super::*;
    use crate::signing::testing::*;
    use crate::workspace::{
        DesktopEngineServices, Evidence, SignFormat, SignOptions, SignSpec, pump, test_workspace,
    };

    /// The sections of the sidebar, as the page's callback gets them.
    const VERIFY: i32 = 2;
    const EXTEND: i32 = 3;
    const EXTRACT: i32 = 4;
    const TIMESTAMP: i32 = 5;

    struct Page {
        w: World,
        ws: Rc<Workspace>,
    }

    fn page() -> Page {
        let w = world();
        let (engine, guard) = engine(&w);
        let services = DesktopEngineServices {
            engine: std::sync::Arc::new(engine),
            guard,
            tokens: Tokens::disabled(),
            clock: std::sync::Arc::new(now),
            settings_path: w.dir.path().join("settings.json"),
        };
        Page {
            ws: test_workspace(services),
            w,
        }
    }

    fn tool(p: &Page) -> ToolState<'_> {
        p.ws.ui.global::<ToolState>()
    }

    /// The sidebar picks `section`: the window's own property and callback, then the page's
    /// fields start from their defaults.
    fn select(p: &Page, section: i32) {
        p.ws.ui.set_section(section);
        p.ws.ui.invoke_section_changed(section);
    }

    fn until(what: &str, mut ready: impl FnMut() -> bool) {
        let start = Instant::now();
        loop {
            pump();
            if ready() {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "timed out: {what}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Adds a document through the page's own fields and button.
    fn add(p: &Page, path: &Path, second: Option<&Path>) {
        let t = tool(p);
        t.set_doc_path(path.display().to_string().into());
        if let Some(second) = second {
            assert!(t.get_show_second(), "the page asks for the second file");
            t.set_second_path(second.display().to_string().into());
        }
        t.invoke_add_doc();
    }

    /// Presses the action button and waits for the run to end.
    fn run_page(p: &Page) {
        tool(p).invoke_run();
        until("the run ends", || !p.ws.ui.get_busy());
    }

    fn rows(p: &Page) -> Vec<String> {
        tool(p)
            .get_report_rows()
            .iter()
            .map(|r| r.text.to_string())
            .collect()
    }

    /// The tones of the document rows (depth 0): 0 success, 1 caution, 2 failure, 3 neutral.
    fn item_tones(p: &Page) -> Vec<i32> {
        tool(p)
            .get_report_rows()
            .iter()
            .filter(|r| r.depth == 0)
            .map(|r| r.tone)
            .collect()
    }

    fn sign_cms(p: &Page, name: &str, content: &[u8]) -> (PathBuf, PathBuf) {
        let document = p.w.dir.path().join(name);
        std::fs::write(&document, content).unwrap();
        let (engine, guard) = engine(&p.w);
        let outcome = sign_confirmed(
            &engine,
            &guard,
            &p.w,
            std::slice::from_ref(&document),
            &SignSpec {
                format: SignFormat::Cms,
                options: SignOptions::default(),
            },
            &Destination::Beside,
        );
        assert!(matches!(outcome, crate::signing::runner::Outcome::Done(_)));
        let signature = p.w.dir.path().join(format!("{name}.p7s"));
        (document, signature)
    }

    /// The verify page, driven by its callbacks: a valid detached CMS is a success report, the
    /// banner, the document row and every check are there, the status line says done.
    #[test]
    fn the_verify_page_reports_a_valid_signature_as_success() {
        let p = page();
        let (document, signature) = sign_cms(&p, "a.txt", b"the document");
        select(&p, VERIFY);
        assert_eq!(tool(&p).get_title().as_str(), "Verify signatures");
        assert!(
            tool(&p).get_show_second(),
            "CMS verification takes the signed data"
        );
        add(&p, &signature, Some(&document));
        assert_eq!(tool(&p).get_docs().row_count(), 1);
        run_page(&p);
        let t = tool(&p);
        assert_eq!(t.get_report_tone(), 0, "{}", t.get_report_headline());
        assert_eq!(item_tones(&p), vec![0], "the document row is a success");
        assert!(rows(&p).len() > 3, "signer and check rows are there");
        assert_eq!(p.ws.ui.get_status_kind(), 2, "the status line says done");
        assert_eq!(p.ws.ui.get_error_text().as_str(), "");
    }

    /// Without the network the verdict is only «not fully checked»: the page styles it as a
    /// caution, never as done, and says why.
    #[test]
    fn an_offline_verification_is_a_caution_on_the_page_not_a_success() {
        let p = page();
        let (document, signature) = sign_cms(&p, "a.txt", b"the document");
        select(&p, VERIFY);
        add(&p, &signature, Some(&document));
        tool(&p).set_flag1(true);
        run_page(&p);
        let t = tool(&p);
        assert_eq!(t.get_report_tone(), 1, "{}", t.get_report_headline());
        assert_eq!(item_tones(&p), vec![1], "the document row is a caution");
        assert_eq!(p.ws.ui.get_status_kind(), 4, "a caution, not done");
    }

    /// A batch of three documents: a valid one, one verified against the wrong data, and one
    /// that disappears before the run. Each document has its own row, the banner is not «all
    /// valid», and the run itself worked (no error line).
    #[test]
    fn a_batch_with_bad_documents_shows_each_result_and_is_not_all_valid() {
        let p = page();
        let (document, signature) = sign_cms(&p, "a.txt", b"the document");
        let (_, other_signature) = sign_cms(&p, "b.txt", b"another document");
        let vanishing = p.w.dir.path().join("vanishing.p7s");
        std::fs::copy(&signature, &vanishing).unwrap();
        select(&p, VERIFY);
        add(&p, &signature, Some(&document));
        add(&p, &other_signature, Some(&document));
        add(&p, &vanishing, Some(&document));
        assert_eq!(tool(&p).get_docs().row_count(), 3);
        std::fs::remove_file(&vanishing).unwrap();
        run_page(&p);
        let t = tool(&p);
        assert_ne!(t.get_report_tone(), 0);
        assert_eq!(
            item_tones(&p),
            vec![0, 2, 2],
            "valid, invalid, and not done: one row each, in the order added"
        );
        assert_eq!(
            rows(&p).iter().filter(|r| r.contains("vanishing")).count(),
            1
        );
        assert_eq!(p.ws.ui.get_error_text().as_str(), "");
    }

    /// Clearing empties the list and the report; running an empty list says what is missing
    /// and runs nothing.
    #[test]
    fn running_without_documents_is_refused_and_clear_empties_the_page() {
        let p = page();
        let (document, signature) = sign_cms(&p, "a.txt", b"the document");
        select(&p, VERIFY);
        tool(&p).invoke_run();
        pump();
        assert!(!p.ws.ui.get_busy(), "nothing was started");
        assert!(!p.ws.ui.get_error_text().is_empty());
        assert_eq!(p.ws.ui.get_error_section(), VERIFY);
        add(&p, &signature, Some(&document));
        run_page(&p);
        assert!(!tool(&p).get_report_headline().is_empty());
        tool(&p).invoke_clear_docs();
        assert_eq!(tool(&p).get_docs().row_count(), 0);
        assert_eq!(tool(&p).get_report_headline().as_str(), "");
        assert_eq!(tool(&p).get_report_rows().row_count(), 0);
    }

    /// The fields of the page follow the choice: the second file only for CMS, the level list
    /// only where levels exist, evidence only for CAdES/PAdES LT and LTA, and the labels of the
    /// action change with the tool.
    #[test]
    fn the_fields_of_the_page_follow_the_format_and_the_level() {
        let p = page();
        select(&p, VERIFY);
        let t = tool(&p);
        for (format, level, second, level_list) in [
            (0, 0, true, true),
            (1, 0, false, true),
            (2, 0, false, false),
            (3, 0, false, true),
            (4, 0, false, false),
            (5, 0, false, false),
        ] {
            t.set_format_index(format);
            t.set_level_index(level);
            t.invoke_changed();
            assert_eq!(t.get_show_second(), second, "format {format}");
            assert_eq!(t.get_show_level(), level_list, "format {format}");
        }
        t.set_format_index(5);
        t.invoke_changed();
        assert!(
            t.get_show_opt1() && t.get_show_opt2(),
            "JWT asks for issuer and audience"
        );
        select(&p, EXTEND);
        let t = tool(&p);
        assert_eq!(t.get_action_label().as_str(), "Extend");
        for (format, level, evidence) in [
            (0, 0, false),
            (0, 1, true),
            (0, 2, true),
            (1, 1, false),
            (1, 2, false),
            (2, 1, true),
            (2, 2, true),
        ] {
            t.set_format_index(format);
            t.set_level_index(level);
            t.invoke_changed();
            assert_eq!(
                t.get_show_evidence(),
                evidence,
                "format {format} level {level}"
            );
        }
        select(&p, TIMESTAMP);
        let t = tool(&p);
        assert_eq!(t.get_action_label().as_str(), "Get a time stamp");
        t.set_format_index(1);
        t.invoke_changed();
        assert_eq!(t.get_action_label().as_str(), "Check the time stamp");
        assert!(t.get_show_second(), "checking asks for the data");
        select(&p, EXTRACT);
        assert_eq!(tool(&p).get_action_label().as_str(), "Extract the content");
    }

    /// Extending to LT through the page: without the evidence files the page says what is
    /// missing and writes nothing; with them it extends and the result verifies at LT.
    #[test]
    fn the_extend_page_needs_evidence_for_lt_and_then_extends() {
        let p = page();
        let text = p.w.dir.path().join("doc.txt");
        std::fs::write(&text, b"the document").unwrap();
        let (engine, guard) = engine(&p.w);
        let b = sign_confirmed(
            &engine,
            &guard,
            &p.w,
            std::slice::from_ref(&text),
            &SignSpec {
                format: SignFormat::Cades(Level::B),
                options: SignOptions::default(),
            },
            &Destination::Beside,
        );
        assert!(matches!(b, crate::signing::runner::Outcome::Done(_)));
        let signature = p.w.dir.path().join("doc.txt.p7s");
        select(&p, EXTEND);
        let t = tool(&p);
        t.set_format_index(0);
        t.set_level_index(1);
        t.invoke_changed();
        add(&p, &signature, Some(&text));
        run_page(&p);
        assert!(
            p.ws.ui.get_error_text().contains("validation data"),
            "{}",
            p.ws.ui.get_error_text()
        );
        assert!(!p.w.dir.path().join("doc.txt.extended.p7s").exists());
        let evidence = evidence_files(&p.w);
        let join = |files: &[PathBuf]| {
            files
                .iter()
                .map(|f| f.display().to_string())
                .collect::<Vec<_>>()
                .join(";")
        };
        t.set_evidence_certificates(join(&evidence.certificates).into());
        t.set_evidence_ocsp(join(&evidence.ocsp).into());
        run_page(&p);
        assert_eq!(t.get_report_tone(), 0, "{}", t.get_report_headline());
        assert!(p.w.dir.path().join("doc.txt.extended.p7s").exists());
    }

    /// The destination: «one folder» with no folder named is refused, with one the result goes
    /// there and not beside the document.
    #[test]
    fn the_destination_folder_of_the_extract_page_is_honoured() {
        let p = page();
        let text = p.w.dir.path().join("doc.txt");
        std::fs::write(&text, b"the exact content").unwrap();
        let (engine, guard) = engine(&p.w);
        let attached = sign_confirmed(
            &engine,
            &guard,
            &p.w,
            std::slice::from_ref(&text),
            &SignSpec {
                format: SignFormat::Cms,
                options: SignOptions {
                    attached: true,
                    ..SignOptions::default()
                },
            },
            &Destination::Beside,
        );
        assert!(matches!(attached, crate::signing::runner::Outcome::Done(_)));
        std::fs::remove_file(&text).unwrap();
        let out = p.w.dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        select(&p, EXTRACT);
        add(&p, &p.w.dir.path().join("doc.txt.p7m"), None);
        tool(&p).set_destination_index(1);
        tool(&p).invoke_run();
        pump();
        assert!(!p.ws.ui.get_busy(), "no folder: nothing started");
        assert!(
            p.ws.ui.get_error_text().contains("folder"),
            "{}",
            p.ws.ui.get_error_text()
        );
        tool(&p).set_destination_path(out.display().to_string().into());
        run_page(&p);
        assert_eq!(
            std::fs::read(out.join("doc.txt")).unwrap(),
            b"the exact content"
        );
        assert!(!text.exists(), "not beside the container");
        assert_eq!(
            tool(&p).get_report_tone(),
            3,
            "an extraction is neutral, never success"
        );
    }

    /// The time stamp page: get a token from the world's time service, then check it with its
    /// data (valid) and without (not a proof of any document).
    #[test]
    fn the_timestamp_page_gets_and_checks_a_token() {
        let p = page();
        let text = p.w.dir.path().join("doc.txt");
        std::fs::write(&text, b"stamp me").unwrap();
        select(&p, TIMESTAMP);
        add(&p, &text, None);
        tool(&p).set_opt1(format!("{ORIGIN}/tsa").into());
        run_page(&p);
        assert_eq!(
            tool(&p).get_report_tone(),
            0,
            "{}",
            tool(&p).get_report_headline()
        );
        let token = p.w.dir.path().join("doc.txt.tst");
        assert!(token.exists());
        select(&p, TIMESTAMP);
        tool(&p).set_format_index(1);
        tool(&p).invoke_changed();
        add(&p, &token, Some(&text));
        run_page(&p);
        assert_eq!(
            tool(&p).get_report_tone(),
            0,
            "{}",
            tool(&p).get_report_headline()
        );
        tool(&p).invoke_clear_docs();
        add(&p, &token, None);
        run_page(&p);
        assert_eq!(
            tool(&p).get_report_tone(),
            1,
            "no data: only not fully checked"
        );
        assert!(
            rows(&p)
                .iter()
                .any(|r| r.contains("tie to a document was not checked")),
            "{:?}",
            rows(&p)
        );
    }

    /// Sets the page's fields, presses nothing, and reads the spec the button would run.
    fn spec_of(
        p: &Page,
        section: i32,
        set: impl FnOnce(&ToolState<'_>),
    ) -> Result<(ToolSpec, Destination), JobError> {
        select(p, section);
        set(&tool(p));
        read_choice(&p.ws)
    }

    /// What the page's fields mean to the SDK: every format and level of every tool maps to its
    /// spec, and a field that belongs to another format never leaks into it.
    #[test]
    fn the_fields_of_the_page_map_to_the_spec_the_sdk_is_asked() {
        let p = page();
        let verify = |format: i32, level: i32, flag1: bool, flag2: bool, o1: &str, o2: &str| {
            spec_of(&p, VERIFY, |t| {
                t.set_format_index(format);
                t.set_level_index(level);
                t.set_flag1(flag1);
                t.set_flag2(flag2);
                t.set_opt1(o1.into());
                t.set_opt2(o2.into());
            })
            .unwrap()
            .0
        };
        let plain = VerifyOptions::default();
        for (format, level, expected) in [
            (0, 0, VerifyFormat::Cms),
            (0, 1, VerifyFormat::Cades(Level::B)),
            (0, 2, VerifyFormat::Cades(Level::T)),
            (0, 3, VerifyFormat::Cades(Level::Lt)),
            (0, 4, VerifyFormat::Cades(Level::Lta)),
            (1, 0, VerifyFormat::Xml),
            (1, 1, VerifyFormat::Xades(Level::B)),
            (1, 4, VerifyFormat::Xades(Level::Lta)),
            (2, 0, VerifyFormat::Wsse),
            (3, 0, VerifyFormat::Pdf),
            (3, 2, VerifyFormat::Pades(Level::T)),
            (3, 4, VerifyFormat::Pades(Level::Lta)),
            (4, 0, VerifyFormat::Jws),
        ] {
            assert_eq!(
                verify(format, level, false, false, "ignored", "ignored"),
                ToolSpec::Verify(expected, plain.clone()),
                "format {format} level {level}: hidden fields do not leak"
            );
        }
        // The fields that do belong to a format are taken.
        assert_eq!(
            verify(1, 0, false, true, "", ""),
            ToolSpec::Verify(VerifyFormat::XmlKalkan, plain.clone())
        );
        assert_eq!(
            verify(1, 2, false, true, "", ""),
            ToolSpec::Verify(VerifyFormat::Xades(Level::T), plain.clone()),
            "Kalkan mode is only for plain XML"
        );
        assert_eq!(
            verify(2, 0, false, true, "", ""),
            ToolSpec::Verify(
                VerifyFormat::Wsse,
                VerifyOptions {
                    timestamp_required: true,
                    ..plain.clone()
                }
            )
        );
        assert_eq!(
            verify(0, 0, true, false, "", ""),
            ToolSpec::Verify(
                VerifyFormat::Cms,
                VerifyOptions {
                    offline: true,
                    ..plain.clone()
                }
            )
        );
        assert_eq!(
            verify(5, 0, false, false, " the-issuer ", "the-audience"),
            ToolSpec::Verify(
                VerifyFormat::Jwt,
                VerifyOptions {
                    issuer: "the-issuer".into(),
                    audience: "the-audience".into(),
                    ..plain.clone()
                }
            )
        );
        // Extend: the target level and the evidence, which only LT and LTA of CAdES and PAdES take.
        let extend = |format: i32, level: i32, evidence: bool, destination: i32, folder: &str| {
            spec_of(&p, EXTEND, |t| {
                t.set_format_index(format);
                t.set_level_index(level);
                if evidence {
                    t.set_evidence_certificates("c1.der; c2.der".into());
                    t.set_evidence_ocsp("o.ocsp".into());
                    t.set_evidence_crls("r.crl".into());
                }
                t.set_destination_index(destination);
                t.set_destination_path(folder.into());
            })
        };
        let files = Evidence::from_fields("c1.der; c2.der", "o.ocsp", "r.crl");
        for (format, level, expected) in [
            (
                0,
                0,
                ToolSpec::Extend(ExtendFormat::Cms(Level::T), Evidence::default()),
            ),
            (
                0,
                1,
                ToolSpec::Extend(ExtendFormat::Cms(Level::Lt), files.clone()),
            ),
            (
                0,
                2,
                ToolSpec::Extend(ExtendFormat::Cms(Level::Lta), files.clone()),
            ),
            (
                1,
                0,
                ToolSpec::Extend(ExtendFormat::Xml(Level::T), Evidence::default()),
            ),
            (
                1,
                1,
                ToolSpec::Extend(ExtendFormat::Xml(Level::Lt), Evidence::default()),
            ),
            (
                1,
                2,
                ToolSpec::Extend(ExtendFormat::Xml(Level::Lta), Evidence::default()),
            ),
            (
                2,
                0,
                ToolSpec::Extend(ExtendFormat::Pdf(Level::T), Evidence::default()),
            ),
            (
                2,
                1,
                ToolSpec::Extend(ExtendFormat::Pdf(Level::Lt), files.clone()),
            ),
            (
                2,
                2,
                ToolSpec::Extend(ExtendFormat::Pdf(Level::Lta), files.clone()),
            ),
        ] {
            let (spec, destination) = extend(format, level, true, 0, "").unwrap();
            assert_eq!(spec, expected, "extend {format}/{level}");
            assert_eq!(destination, Destination::Beside);
        }
        assert_eq!(
            extend(0, 0, false, 1, "out").unwrap().1,
            Destination::Folder(PathBuf::from("out"))
        );
        assert_eq!(
            extend(0, 0, false, 1, "  ").err(),
            Some(JobError::Input(MissingField::Folder)),
            "«one folder» with no folder named"
        );
        // Extract and the destination; a tool that writes nothing ignores it.
        let (spec, destination) = spec_of(&p, EXTRACT, |t| {
            t.set_destination_index(1);
            t.set_destination_path("\"drive_C:\\out dir\"".into());
        })
        .unwrap();
        assert_eq!(spec, ToolSpec::Extract);
        assert_eq!(
            destination,
            Destination::Folder(PathBuf::from("drive_C:\\out dir"))
        );
        let (_, destination) = spec_of(&p, VERIFY, |t| {
            t.set_destination_index(1);
            t.set_destination_path("ignored".into());
        })
        .unwrap();
        assert_eq!(destination, Destination::Beside);
        // Timestamp: get, and check with a policy and an age.
        for (level, algorithm) in [
            (0, HashAlg::Sha256),
            (1, HashAlg::Gost34311),
            (2, HashAlg::Streebog512),
        ] {
            let (spec, _) = spec_of(&p, TIMESTAMP, |t| {
                t.set_format_index(0);
                t.set_level_index(level);
            })
            .unwrap();
            assert_eq!(
                spec,
                ToolSpec::Stamp(StampOptions {
                    algorithm,
                    ..StampOptions::default()
                })
            );
        }
        let (spec, _) = spec_of(&p, TIMESTAMP, |t| {
            t.set_format_index(1);
            t.set_opt1("1.2.3".into());
            t.set_opt2(" 300 ".into());
        })
        .unwrap();
        assert_eq!(
            spec,
            ToolSpec::StampCheck(StampOptions {
                policy: "1.2.3".into(),
                max_age: 300,
                ..StampOptions::default()
            })
        );
        let bad_age = spec_of(&p, TIMESTAMP, |t| {
            t.set_format_index(1);
            t.set_opt2("soon".into());
        });
        assert_eq!(
            bad_age.err(),
            Some(JobError::Operation(oncl_core::ErrorCode::InvalidInput))
        );
    }

    /// The Timestamp page with no answer from the time service: the report says a service did
    /// not answer (not that a file could not be read), as a failure; no file was written.
    #[test]
    fn the_timestamp_page_words_an_unreachable_service_as_the_network() {
        let w = world();
        let (engine, guard) = engine_without_tsa(&w);
        let services = DesktopEngineServices {
            engine: std::sync::Arc::new(engine),
            guard,
            tokens: Tokens::disabled(),
            clock: std::sync::Arc::new(now),
            settings_path: w.dir.path().join("settings.json"),
        };
        let p = Page {
            ws: test_workspace(services),
            w,
        };
        let text = p.w.dir.path().join("doc.txt");
        std::fs::write(&text, b"stamp me").unwrap();
        select(&p, TIMESTAMP);
        add(&p, &text, None);
        run_page(&p);
        assert_eq!(tool(&p).get_report_tone(), 2, "a failure");
        let rows = rows(&p);
        assert!(rows[0].contains("a service did not answer"), "{rows:?}");
        assert!(!rows[0].contains("read or written"), "{rows:?}");
        assert!(!p.w.dir.path().join("doc.txt.tst").exists());
    }
}
