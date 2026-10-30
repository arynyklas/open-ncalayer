//! `files`: a file the user opens or saves in the system dialogs.

use super::{DialogTurn, MAX_LINE, check_line, failed, limit, origin, source};
use crate::host::HostState;
use oncl_basics::{
    FileKind, FilePrompt, MAX_PAGE_FILE, PageFile, PageFileError, Prompt, SavePrompt,
    is_device_path, remember_chosen_path,
};
use oncl_pdk::abi::{Bytes, HostResult, OpenedFile, SaveArgs};
use oncl_pki::fsutil::{Access, write_atomically};
use std::path::Path;

/// `file_open`: a file the user chooses, at most [`MAX_PAGE_FILE`] bytes.
pub(crate) fn file_open(state: &mut HostState) -> HostResult<Option<OpenedFile>> {
    let prompt = FilePrompt {
        origin: origin(state),
        locale: state.call.locale,
        kind: FileKind::All,
        directory: None,
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
