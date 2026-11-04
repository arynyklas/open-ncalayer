//! `oncl-server install-file`: real processes. Files it installs are accepted by `serve`
//! (the private-file rules), and every unsafe name, overwrite or oversized input is refused
//! without leaving a file or printing the bytes.
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_oncl-server");

fn install(directory: &Path, name: &str, stdin: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(["install-file", "--directory"])
        .arg(directory)
        .args(["--name", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let bytes = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = input.write_all(&bytes);
    });
    let output = child.wait_with_output().unwrap();
    let _ = writer.join();
    output
}

#[test]
fn an_installed_config_is_accepted_by_serve() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("operator");
    let config = b"enabled = false\n";
    let out = install(&directory, "server.toml", config);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(directory.join("server.toml")).unwrap(),
        config
    );
    let served = Command::new(BIN)
        .args(["serve", "--config"])
        .arg(directory.join("server.toml"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(served.status.success());
    assert!(String::from_utf8_lossy(&served.stdout).contains("disabled: no listener"));
    // The same file written by anything else is refused: that is why the command exists.
    std::fs::write(temporary.path().join("plain.toml"), config).unwrap();
    let plain = Command::new(BIN)
        .args(["serve", "--config"])
        .arg(temporary.path().join("plain.toml"))
        .output()
        .unwrap();
    assert!(!plain.status.success());
}

#[test]
fn an_existing_file_is_never_overwritten() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("operator");
    assert!(install(&directory, "a.p12", b"first").status.success());
    let second = install(&directory, "a.p12", b"second");
    assert!(!second.status.success());
    assert_eq!(std::fs::read(directory.join("a.p12")).unwrap(), b"first");
}

#[test]
fn unsafe_names_are_refused_and_create_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("operator");
    for name in [
        "..\\x",
        "../x",
        "sub/x",
        "..",
        ".",
        "a:stream",
        "C:x",
        "NUL",
        "con.txt",
        "COM1",
        "lpt9.p12",
        "trailing.",
        "",
        "a b",
        "aux.txt",
        "trailing ",
        "\\\\server\\share\\x",
        "x/..",
        "PROGRA~1",
        "\\\\?\\UNC\\server\\x",
        "name\u{e9}",
    ] {
        let out = install(&directory, name, b"SECRET-MATERIAL");
        assert!(!out.status.success(), "{name:?} was accepted");
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(!text.contains("SECRET-MATERIAL"), "{name:?}: {text}");
    }
    // Nothing is created, not even the directory.
    assert!(!directory.exists());
    assert!(!temporary.path().join("x").exists());
}

#[test]
fn an_oversized_input_is_refused_and_leaves_no_file() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("operator");
    let big = vec![b'S'; oncl_server::install::MAX_INSTALL_BYTES + 1];
    let out = install(&directory, "big.p12", &big);
    assert!(!out.status.success());
    assert!(!directory.join("big.p12").exists());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("SSSS"));
}

#[test]
fn an_input_file_is_read_like_stdin() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source.bin");
    std::fs::write(&source, b"from a file").unwrap();
    let directory = temporary.path().join("operator");
    let out = Command::new(BIN)
        .args(["install-file", "--directory"])
        .arg(&directory)
        .args(["--name", "k.p12", "--input"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::read(directory.join("k.p12")).unwrap(),
        b"from a file"
    );
}

#[test]
fn a_refusal_never_removes_or_changes_an_existing_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("operator");
    assert!(install(&directory, "keep.p12", b"kept").status.success());
    assert!(!install(&directory, "a b", b"x").status.success());
    assert_eq!(std::fs::read(directory.join("keep.p12")).unwrap(), b"kept");
}

#[test]
fn an_existing_empty_directory_is_left_as_it_was() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("operator");
    assert!(install(&directory, "first.p12", b"x").status.success());
    std::fs::remove_file(directory.join("first.p12")).unwrap();
    assert!(!install(&directory, "a b", b"x").status.success());
    assert!(directory.is_dir());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
}
