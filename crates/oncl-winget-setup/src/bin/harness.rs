//! The harness of the installer entry's tests: real processes standing in for what the entry
//! talks to (see `harness/windows.rs`). It is not the installer and is never shipped.

#[cfg(windows)]
#[path = "harness/windows.rs"]
mod windows;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    windows::main()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("the harness of the installer entry's tests works on Windows only");
    std::process::ExitCode::from(64)
}
