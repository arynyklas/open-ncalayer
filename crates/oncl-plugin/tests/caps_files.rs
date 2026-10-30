//! Paths the user chooses for a plugin (`file_choose`, `file_open_ex`) and files a page
//! names (`page_file_read`, `page_file_write`): page paths only under the page-path rules,
//! each file or folder once the user allows it in the session.

mod common;

use common::*;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{PathMode, page_path};
use oncl_pdk::abi::{
    self, Bytes, ChooseFileArgs, ChosenPath, ErrorCode, FileFilter, FileMode, HostResult, Import,
    OpenedFile, PagePathArgs, PageRead, PageWrite, PageWriteArgs,
};
use oncl_plugin::{Engine, HostServices, Instance, LoadError};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ORIGIN: &str = "https://docs.example.kz";

fn services_of(prompter: &Arc<ScriptedPrompter>) -> HostServices {
    services_with(Arc::clone(prompter), Arc::new(Offline))
}

fn instance(caps: &str, services: &HostServices, calls: &[(Import, Vec<u8>)]) -> Instance {
    Engine::new()
        .compile(&manifest(caps), &wasm(&probe(calls)))
        .unwrap()
        .instantiate(services, session(1))
        .unwrap()
}

fn call<T: DeserializeOwned>(instance: &mut Instance) -> HostResult<T> {
    probe_result(
        instance
            .process("{}", &from(ORIGIN))
            .unwrap()
            .text()
            .unwrap(),
    )
}

fn run<T: DeserializeOwned>(
    caps: &str,
    prompter: &Arc<ScriptedPrompter>,
    calls: &[(Import, Vec<u8>)],
) -> HostResult<T> {
    call(&mut instance(caps, &services_of(prompter), calls))
}

fn choose(mode: FileMode) -> ChooseFileArgs {
    ChooseFileArgs {
        mode,
        title: None,
        filters: Vec::new(),
        initial_dir: None,
    }
}

fn text(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

#[test]
fn choose_returns_path_and_size_without_reading() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("doc.pdf");
    std::fs::write(&file, b"12345").unwrap();
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Path(file.clone())]));
    let chosen: Option<ChosenPath> = run(
        "files = true",
        &prompter,
        &[(Import::FileChoose, abi::encode(&choose(FileMode::Open)))],
    )
    .unwrap();
    assert_eq!(
        chosen,
        Some(ChosenPath {
            path: text(&file),
            size: Some(5)
        })
    );
    let prompt = &prompter.path_prompts()[0];
    assert_eq!(prompt.mode, PathMode::File);
    assert_eq!(prompt.origin, ORIGIN);
    assert_eq!(prompt.source, "Тестовый плагин");
    // Cancelled.
    let none = Arc::new(ScriptedPrompter::new(vec![Step::CancelPath]));
    let chosen: Option<ChosenPath> = run(
        "files = true",
        &none,
        &[(Import::FileChoose, abi::encode(&choose(FileMode::Open)))],
    )
    .unwrap();
    assert_eq!(chosen, None);
}

#[test]
fn choose_directory_mode() {
    let dir = tempfile::tempdir().unwrap();
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Path(
        dir.path().to_path_buf(),
    )]));
    let chosen: Option<ChosenPath> = run(
        "files = true",
        &prompter,
        &[(
            Import::FileChoose,
            abi::encode(&choose(FileMode::Directory)),
        )],
    )
    .unwrap();
    assert_eq!(
        chosen,
        Some(ChosenPath {
            path: text(dir.path()),
            size: None
        })
    );
    assert_eq!(prompter.path_prompts()[0].mode, PathMode::Directory);
}

#[test]
fn choose_remembers_network_path() {
    let network = if cfg!(windows) {
        r"\\server.invalid\share\chosen-by-plugin.p12"
    } else {
        "//server.invalid/share/chosen-by-plugin.p12"
    };
    assert!(page_path(network).is_none());
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Path(PathBuf::from(
        network,
    ))]));
    let chosen: Option<ChosenPath> = run(
        "files = true",
        &prompter,
        &[(Import::FileChoose, abi::encode(&choose(FileMode::Open)))],
    )
    .unwrap();
    assert_eq!(chosen.unwrap().path, network);
    assert!(page_path(network).is_some());
}

#[test]
fn open_ex_filters_and_title_reach_dialog() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a.cms");
    std::fs::write(&file, b"cms").unwrap();
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Path(file.clone())]));
    let args = ChooseFileArgs {
        mode: FileMode::Open,
        title: Some("Выберите подпись".to_owned()),
        filters: vec![FileFilter {
            name: "CMS".to_owned(),
            extensions: vec!["cms".to_owned(), "P7S".to_owned()],
        }],
        initial_dir: Some(text(dir.path())),
    };
    let opened: Option<OpenedFile> = run(
        "files = true",
        &prompter,
        &[(Import::FileOpenEx, abi::encode(&args))],
    )
    .unwrap();
    let opened = opened.unwrap();
    assert_eq!(opened.data.as_slice(), b"cms");
    assert_eq!(opened.path, text(&file));
    let prompt = &prompter.path_prompts()[0];
    assert_eq!(prompt.title.as_deref(), Some("Выберите подпись"));
    assert_eq!(prompt.filters[0].name, "CMS");
    assert_eq!(prompt.filters[0].extensions, ["cms", "p7s"]);
    assert_eq!(prompt.directory.as_deref(), Some(dir.path()));
    // A folder cannot be opened as a file.
    let folder: HostResult<Option<OpenedFile>> = run(
        "files = true",
        &prompter,
        &[(
            Import::FileOpenEx,
            abi::encode(&choose(FileMode::Directory)),
        )],
    );
    assert_eq!(folder.unwrap_err().code, ErrorCode::Invalid);
}

fn read_args(path: &str) -> (Import, Vec<u8>) {
    (
        Import::PageFileRead,
        abi::encode(&PagePathArgs {
            path: path.to_owned(),
        }),
    )
}

const PAGE_FILES: &str = "page_files = true\npage_files_ext = [\"cms\"]";

#[test]
fn page_read_consent_once() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("in.xml");
    std::fs::write(&file, b"<a/>").unwrap();
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: true }]));
    let services = services_of(&prompter);
    let mut instance = instance(PAGE_FILES, &services, &[read_args(&text(&file))]);
    for _ in 0..2 {
        let read: PageRead = call(&mut instance).unwrap();
        match read {
            PageRead::Ok(opened) => assert_eq!(opened.data.as_slice(), b"<a/>"),
            other => panic!("{other:?}"),
        }
    }
    // Asked once, with the site, the plugin and the file.
    let asked = prompter.confirm_prompts();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].text.contains(ORIGIN), "{}", asked[0].text);
    assert!(asked[0].text.contains("in.xml"), "{}", asked[0].text);
    // A new session asks again; no is no.
    let no = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: false }]));
    let read: PageRead = run(PAGE_FILES, &no, &[read_args(&text(&file))]).unwrap();
    assert_eq!(read, PageRead::Declined);
    // Missing: no question.
    let missing: PageRead =
        run(PAGE_FILES, &no, &[read_args(&text(&dir.path().join("x")))]).unwrap();
    assert_eq!(missing, PageRead::NotFound);
    assert_eq!(no.confirm_prompts().len(), 1);
}

#[test]
fn page_read_device_and_unchosen_network_denied() {
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: true }]));
    let mut paths = vec![if cfg!(windows) {
        r"\\server.invalid\share\never-chosen.cms"
    } else {
        "//server.invalid/share/never-chosen.cms"
    }];
    if cfg!(windows) {
        paths.push(r"\\.\pipe\oncl-test");
        paths.push(r"\\?\GLOBALROOT\Device\Null");
    }
    for path in paths {
        let read: PageRead = run(PAGE_FILES, &prompter, &[read_args(path)]).unwrap();
        assert_eq!(read, PageRead::NotFound, "{path}");
    }
    // A folder.
    let dir = tempfile::tempdir().unwrap();
    let read: PageRead = run(PAGE_FILES, &prompter, &[read_args(&text(dir.path()))]).unwrap();
    assert_eq!(read, PageRead::NotFound);
    assert!(prompter.confirm_prompts().is_empty());
    // Without page_files the plugin does not load.
    let refused =
        Engine::new().compile(&manifest("files = true"), &wasm(&probe(&[read_args("x")])));
    assert!(
        matches!(refused, Err(LoadError::Undeclared(_))),
        "{:?}",
        refused.err()
    );
}

fn write_args(dir: &str, name: &str, data: &[u8]) -> (Import, Vec<u8>) {
    (
        Import::PageFileWrite,
        abi::encode(&PageWriteArgs {
            dir: dir.to_owned(),
            name: name.to_owned(),
            data: Bytes::from(data.to_vec()),
        }),
    )
}

#[test]
fn page_write_extension_and_name_rules() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("plain.txt");
    std::fs::write(&file, b"x").unwrap();
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: true }]));
    let d = text(dir.path());
    let cases = [
        (d.as_str(), "a/b.cms"),
        (d.as_str(), r"a\b.cms"),
        (d.as_str(), ".."),
        (d.as_str(), "..cms"),
        (d.as_str(), "x.exe"),
        (d.as_str(), "x"),
        (d.as_str(), ".cms"),
        (d.as_str(), ""),
        (d.as_str(), "a.cms\0"),
    ];
    for (dir, name) in cases {
        let written: PageWrite =
            run(PAGE_FILES, &prompter, &[write_args(dir, name, b"1")]).unwrap();
        assert_eq!(written, PageWrite::Invalid, "{name:?}");
    }
    // Not a folder, or no such folder.
    for not_dir in [text(&file), text(&dir.path().join("none"))] {
        let written: PageWrite = run(
            PAGE_FILES,
            &prompter,
            &[write_args(&not_dir, "a.cms", b"1")],
        )
        .unwrap();
        assert_eq!(written, PageWrite::Invalid, "{not_dir}");
    }
    assert!(prompter.confirm_prompts().is_empty());
    // The extension compares without case.
    let written: PageWrite = run(PAGE_FILES, &prompter, &[write_args(&d, "a.CMS", b"1")]).unwrap();
    assert!(matches!(written, PageWrite::Written(_)), "{written:?}");
}

#[test]
fn page_write_consent_shows_full_path() {
    let dir = tempfile::tempdir().unwrap();
    let d = text(dir.path());
    let no = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: false }]));
    let written: PageWrite = run(PAGE_FILES, &no, &[write_args(&d, "sig.cms", b"1")]).unwrap();
    assert_eq!(written, PageWrite::Declined);
    assert!(!dir.path().join("sig.cms").exists());
    let shown = &no.confirm_prompts()[0].text;
    let full = dir.path().join("sig.cms");
    assert!(
        shown.contains(&*full.file_name().unwrap().to_string_lossy()),
        "{shown}"
    );
    assert!(shown.contains(ORIGIN), "{shown}");

    // Yes once: later files of the folder in the session are written without asking.
    let yes = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: true }]));
    let services = services_of(&yes);
    let mut first = instance(PAGE_FILES, &services, &[write_args(&d, "a.cms", b"A")]);
    let written: PageWrite = call(&mut first).unwrap();
    let PageWrite::Written(path) = written else {
        panic!("{written:?}")
    };
    assert_eq!(std::fs::read(&path).unwrap(), b"A");
    assert!(call::<PageWrite>(&mut first).is_ok());
    assert_eq!(yes.confirm_prompts().len(), 1);
}

#[test]
fn page_write_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let d = text(dir.path());
    let target = dir.path().join("out.cms");
    std::fs::write(&target, b"old contents").unwrap();
    let prompter = Arc::new(ScriptedPrompter::new(vec![Step::Confirm { yes: true }]));
    let written: PageWrite =
        run(PAGE_FILES, &prompter, &[write_args(&d, "out.cms", b"new")]).unwrap();
    assert!(matches!(written, PageWrite::Written(_)));
    // Overwritten, with nothing else left in the folder.
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["out.cms"]);
}
