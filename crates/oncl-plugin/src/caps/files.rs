//! `files`: a file the user opens or saves in the system dialogs, and a path the user
//! chooses for the plugin; `page_files`: files and folders a page names, each once the user
//! allows it in the session.

use super::keys::shown;
use super::{
    ConsentKind, DialogTurn, MAX_LINE, check_line, failed, invalid, limit, origin, source,
};
use crate::host::HostState;
use oncl_basics::{
    ConfirmPrompt, FileKind, FilePrompt, Locale, MAX_PAGE_FILE, PageFile, PageFileError,
    PathFilter, PathMode, PathPrompt, Prompt, SavePrompt, is_device_path, page_path,
    remember_chosen_path,
};
use oncl_pdk::abi::{
    Bytes, ChooseFileArgs, ChosenPath, FileMode, HostResult, OpenedFile, PagePathArgs, PageRead,
    PageWrite, PageWriteArgs, SaveArgs,
};
use oncl_pki::fsutil::{Access, write_atomically};
use std::path::{Path, PathBuf};

/// The most file types of a path chooser.
const MAX_FILTERS: usize = 16;
/// The most extensions of a path chooser's file type.
const MAX_FILTER_EXTENSIONS: usize = 16;
/// Longest extension of a path chooser's file type, in bytes.
const MAX_EXTENSION: usize = 16;
/// Longest file name `page_file_write` writes, in bytes.
const MAX_FILE_NAME: usize = 255;

/// `file_open`: a file the user chooses, at most [`MAX_PAGE_FILE`] bytes.
pub(crate) fn file_open(state: &mut HostState) -> HostResult<Option<OpenedFile>> {
    let prompt = FilePrompt {
        origin: origin(state),
        locale: state.call.locale,
        kind: FileKind::All,
        directory: None,
        source: Some(source(state)),
    };
    DialogTurn::hold();
    let path = match state.services.prompter.file(&prompt) {
        Prompt::Answer(path) => path,
        Prompt::Cancelled => return Ok(None),
    };
    let file = PageFile::read_chosen(&path).map_err(|e| match e {
        PageFileError::TooLarge => limit(format!("the file is over {MAX_PAGE_FILE} bytes")),
        PageFileError::NotFound => failed(format!("{} cannot be read", path.display())),
    })?;
    remember_chosen_path(&path);
    Ok(Some(OpenedFile {
        path: file.shown,
        data: Bytes::from(file.data),
    }))
}

/// `file_save`: the data written, through a temporary file, where the user chooses.
pub(crate) fn file_save(state: &mut HostState, args: SaveArgs) -> HostResult<Option<String>> {
    if args.data.len() as u64 > MAX_PAGE_FILE {
        return Err(limit(format!("the data is over {MAX_PAGE_FILE} bytes")));
    }
    check_line("the file name", &args.suggested_name, MAX_LINE)?;
    let suggested_name = Path::new(&args.suggested_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned();
    let prompt = SavePrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        suggested_name,
        directory: None,
    };
    DialogTurn::hold();
    let path = match state.services.prompter.save_file(&prompt) {
        Prompt::Answer(path) => path,
        Prompt::Cancelled => return Ok(None),
    };
    let text = path
        .to_str()
        .ok_or_else(|| failed("the chosen path is not Unicode"))?;
    if is_device_path(text) {
        return Err(failed(format!("{text} is not a file path")));
    }
    write_atomically(&path, &args.data, Access::Default)
        .map_err(|e| failed(format!("{}: {e}", path.display())))?;
    Ok(Some(text.to_owned()))
}

/// The chooser of `args`, checked: a title and file types within limits, extensions of
/// letters and digits (lowercased), a start folder only if a page may name it and it is a
/// folder.
fn path_prompt(state: &HostState, args: ChooseFileArgs) -> HostResult<PathPrompt> {
    if let Some(title) = &args.title {
        check_line("the title", title, MAX_LINE)?;
    }
    if args.filters.len() > MAX_FILTERS {
        return Err(invalid(format!("more than {MAX_FILTERS} file types")));
    }
    let mut filters = Vec::with_capacity(args.filters.len());
    for filter in args.filters {
        check_line("a file type's name", &filter.name, MAX_LINE)?;
        if filter.extensions.is_empty() || filter.extensions.len() > MAX_FILTER_EXTENSIONS {
            return Err(invalid(format!(
                "a file type has 1 to {MAX_FILTER_EXTENSIONS} extensions"
            )));
        }
        let mut extensions = Vec::with_capacity(filter.extensions.len());
        for ext in &filter.extensions {
            if ext.is_empty()
                || ext.len() > MAX_EXTENSION
                || !ext.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(invalid(format!(
                    "the extension {ext:?} is not 1 to {MAX_EXTENSION} letters and digits"
                )));
            }
            extensions.push(ext.to_ascii_lowercase());
        }
        filters.push(PathFilter {
            name: filter.name,
            extensions,
        });
    }
    let directory = args
        .initial_dir
        .as_deref()
        .and_then(page_path)
        .filter(|dir| dir.is_dir())
        .map(Path::to_path_buf);
    Ok(PathPrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        title: args.title,
        mode: match args.mode {
            FileMode::Open => PathMode::File,
            FileMode::Directory => PathMode::Directory,
        },
        filters,
        directory,
    })
}

/// `file_choose`: a file or folder the user chooses, its path and a file's size, nothing
/// read. A network path chosen becomes one pages may name.
pub(crate) fn file_choose(
    state: &mut HostState,
    args: ChooseFileArgs,
) -> HostResult<Option<ChosenPath>> {
    let prompt = path_prompt(state, args)?;
    DialogTurn::hold();
    let path = match state.services.prompter.path(&prompt) {
        Prompt::Answer(path) => path,
        Prompt::Cancelled => return Ok(None),
    };
    let text = path
        .to_str()
        .ok_or_else(|| failed("the chosen path is not Unicode"))?;
    if is_device_path(text) {
        return Err(failed(format!("{text} is not a file path")));
    }
    remember_chosen_path(&path);
    let size = std::fs::metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|meta| meta.len());
    Ok(Some(ChosenPath {
        path: text.to_owned(),
        size,
    }))
}

/// `file_open_ex`: a file the user chooses in the plugin's chooser, at most
/// [`MAX_PAGE_FILE`] bytes.
pub(crate) fn file_open_ex(
    state: &mut HostState,
    args: ChooseFileArgs,
) -> HostResult<Option<OpenedFile>> {
    if args.mode != FileMode::Open {
        return Err(invalid("file_open_ex opens a file, not a folder"));
    }
    let prompt = path_prompt(state, args)?;
    DialogTurn::hold();
    let path = match state.services.prompter.path(&prompt) {
        Prompt::Answer(path) => path,
        Prompt::Cancelled => return Ok(None),
    };
    let file = PageFile::read_chosen(&path).map_err(|e| match e {
        PageFileError::TooLarge => limit(format!("the file is over {MAX_PAGE_FILE} bytes")),
        PageFileError::NotFound => failed(format!("{} cannot be read", path.display())),
    })?;
    remember_chosen_path(&path);
    Ok(Some(OpenedFile {
        path: file.shown,
        data: Bytes::from(file.data),
    }))
}

/// Asks once per session whether the page may do `kind` with `path` (canonical), with
/// `text` (made of the origin, the plugin and the path shown); `true` if allowed now or
/// before.
fn consent(
    state: &mut HostState,
    kind: ConsentKind,
    path: PathBuf,
    text: fn(Locale, &str, &str, &str) -> String,
    shown_path: &Path,
) -> bool {
    let key = (kind, origin(state), path);
    if state.consents.contains(&key) {
        return true;
    }
    let prompt = ConfirmPrompt {
        origin: key.1.clone(),
        locale: state.call.locale,
        source: source(state),
        text: text(
            state.call.locale,
            &key.1,
            &source(state),
            &shown(shown_path),
        ),
    };
    DialogTurn::hold();
    if state.services.prompter.confirm(&prompt) != Prompt::Answer(true) {
        return false;
    }
    state.consents.insert(key);
    true
}

/// `page_file_read`: a file the page names, if a page may name it, it is a regular file
/// within [`MAX_PAGE_FILE`] and the user allows this page to read it (asked once per
/// session for each file). Nothing is read before the user allows it.
pub(crate) fn page_file_read(state: &mut HostState, args: PagePathArgs) -> HostResult<PageRead> {
    let Some(named) = page_path(&args.path) else {
        return Ok(PageRead::NotFound);
    };
    let Ok(meta) = std::fs::metadata(named) else {
        return Ok(PageRead::NotFound);
    };
    if !meta.is_file() {
        return Ok(PageRead::NotFound);
    }
    if meta.len() > MAX_PAGE_FILE {
        return Ok(PageRead::TooLarge);
    }
    let Ok(canonical) = std::fs::canonicalize(named) else {
        return Ok(PageRead::NotFound);
    };
    let shown_path = canonical.clone();
    if !consent(state, ConsentKind::Read, canonical, read_text, &shown_path) {
        return Ok(PageRead::Declined);
    }
    Ok(match PageFile::read(&args.path) {
        Ok(file) => PageRead::Ok(OpenedFile {
            path: file.shown,
            data: Bytes::from(file.data),
        }),
        Err(PageFileError::NotFound) => PageRead::NotFound,
        Err(PageFileError::TooLarge) => PageRead::TooLarge,
    })
}

/// `page_file_write`: `data` written, through a temporary file, as `name` in the folder the
/// page names, if a page may name it, `name` is a plain file name with an extension of the
/// manifest's `page_files_ext`, and the user allows this page to write into the folder
/// (asked once per session for each folder, showing the file's full path). An existing
/// file is replaced.
pub(crate) fn page_file_write(state: &mut HostState, args: PageWriteArgs) -> HostResult<PageWrite> {
    if args.data.len() as u64 > MAX_PAGE_FILE {
        return Err(limit(format!("the data is over {MAX_PAGE_FILE} bytes")));
    }
    if !is_plain_name(&args.name, &state.capabilities.page_files_ext) {
        return Ok(PageWrite::Invalid);
    }
    let Some(dir) = page_path(&args.dir) else {
        return Ok(PageWrite::Invalid);
    };
    if !dir.is_dir() {
        return Ok(PageWrite::Invalid);
    }
    let Ok(canonical) = std::fs::canonicalize(dir) else {
        return Ok(PageWrite::Invalid);
    };
    let target = canonical.join(&args.name);
    if !consent(state, ConsentKind::WriteDir, canonical, write_text, &target) {
        return Ok(PageWrite::Declined);
    }
    write_atomically(&target, &args.data, Access::Default)
        .map_err(|e| failed(format!("{}: {e}", shown(&target))))?;
    Ok(PageWrite::Written(shown(&target)))
}

/// Whether `name` is a file name `page_file_write` writes: no separators, control
/// characters or reserved Windows characters and names, not starting with `.` nor ending
/// with `.` or a space, and an extension of `extensions` (compared without case).
fn is_plain_name(name: &str, extensions: &[String]) -> bool {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if name.is_empty()
        || name.len() > MAX_FILE_NAME
        || name.starts_with('.')
        || name.ends_with(['.', ' '])
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
    {
        return false;
    }
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    let stem = name.split('.').next().unwrap_or_default();
    !RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem.trim_end()))
        && extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
}

/// The question that lets a page read a file.
fn read_text(locale: Locale, origin: &str, plugin: &str, path: &str) -> String {
    match locale {
        Locale::Ru => format!(
            "Сайт {origin} через плагин «{plugin}» просит прочитать файл:\n{path}\n\nРазрешить?"
        ),
        Locale::Kk => format!(
            "{origin} сайты «{plugin}» плагині арқылы файлды оқуды сұрайды:\n{path}\n\nРұқсат етесіз бе?"
        ),
        Locale::En => format!(
            "The site {origin} asks, through the plugin “{plugin}”, to read the file:\n{path}\n\nAllow?"
        ),
    }
}

/// The question that lets a page write files into a folder, naming the first file.
fn write_text(locale: Locale, origin: &str, plugin: &str, path: &str) -> String {
    match locale {
        Locale::Ru => format!(
            "Сайт {origin} через плагин «{plugin}» просит записать файл (и другие файлы в эту папку):\n{path}\n\nРазрешить?"
        ),
        Locale::Kk => format!(
            "{origin} сайты «{plugin}» плагині арқылы файлды (және осы папкаға басқа файлдарды) жазуды сұрайды:\n{path}\n\nРұқсат етесіз бе?"
        ),
        Locale::En => format!(
            "The site {origin} asks, through the plugin “{plugin}”, to write the file (and other files in this folder):\n{path}\n\nAllow?"
        ),
    }
}
