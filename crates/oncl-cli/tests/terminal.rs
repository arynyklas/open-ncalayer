//! `--secret-interactive` on a real terminal: a Windows ConPTY pseudoconsole
//! hosts the actual `oncl` process. Keystrokes are written to the pseudoconsole's
//! input; everything the terminal displays is read back from its output. A control
//! program that does echo proves the harness would show typed characters.
#![cfg(windows)]
mod support;
use std::{
    fs::File,
    io::{Read, Write},
    os::windows::io::{FromRawHandle, RawHandle},
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use support::*;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON},
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
            GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROCESS_INFORMATION, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
            WaitForSingleObject,
        },
    },
};

const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;

struct Pty {
    pseudo: HPCON,
    input: Arc<Mutex<File>>,
    screen: Arc<Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    process: HANDLE,
}
impl Pty {
    /// Starts `command_line` attached to a fresh pseudoconsole.
    fn start(command_line: &str) -> Pty {
        Self::start_flags(command_line, 1)
    }
    fn start_flags(command_line: &str, flags: u32) -> Pty {
        let (mut in_read, mut in_write, mut out_read, mut out_write) =
            (0 as HANDLE, 0 as HANDLE, 0 as HANDLE, 0 as HANDLE);
        let mut pseudo: HPCON = 0;
        // SAFETY: plain Win32 calls with valid out-pointers; every handle is closed below.
        unsafe {
            assert_ne!(
                CreatePipe(&mut in_read, &mut in_write, std::ptr::null(), 0),
                0
            );
            assert_ne!(
                CreatePipe(&mut out_read, &mut out_write, std::ptr::null(), 0),
                0
            );
            let hr = CreatePseudoConsole(
                COORD { X: 120, Y: 30 },
                in_read,
                out_write,
                flags,
                &mut pseudo,
            );
            assert_eq!(hr, 0, "CreatePseudoConsole failed: {hr:#x}");
            CloseHandle(in_read);
            CloseHandle(out_write);
        }
        // SAFETY: attribute list sized by the documented two-call protocol.
        let (process, _list_storage) = unsafe {
            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
            let mut storage = vec![0u8; size];
            let list = storage.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
            assert_ne!(InitializeProcThreadAttributeList(list, 1, 0, &mut size), 0);
            assert_ne!(
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    pseudo as *const _,
                    std::mem::size_of::<HPCON>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ),
                0
            );
            let mut startup: STARTUPINFOEXW = std::mem::zeroed();
            startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            // Without explicit invalid standard handles the child inherits the test
            // process's redirected stdio instead of the pseudoconsole.
            startup.StartupInfo.dwFlags = 0x0000_0100; // STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
            startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
            startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
            startup.lpAttributeList = list;
            let mut line: Vec<u16> = command_line.encode_utf16().chain(Some(0)).collect();
            let mut info: PROCESS_INFORMATION = std::mem::zeroed();
            let created = CreateProcessW(
                std::ptr::null(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                &startup.StartupInfo,
                &mut info,
            );
            assert_ne!(
                created,
                0,
                "CreateProcessW failed: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(info.hThread);
            DeleteProcThreadAttributeList(list);
            (info.hProcess, storage)
        };
        // SAFETY: the handles are owned here and ownership moves into the Files.
        let input = Arc::new(Mutex::new(unsafe {
            File::from_raw_handle(in_write as RawHandle)
        }));
        let mut output = unsafe { File::from_raw_handle(out_read as RawHandle) };
        let screen = Arc::new(Mutex::new(Vec::new()));
        let (shown, answer) = (screen.clone(), input.clone());
        let reader = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            let mut answered = 0;
            while let Ok(n) = output.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut screen = shown.lock().unwrap();
                screen.extend_from_slice(&chunk[..n]);
                // ConPTY asks the host for the cursor position; a terminal answers.
                let requests = screen.windows(4).filter(|w| *w == b"\x1b[6n").count();
                drop(screen);
                while answered < requests {
                    let _ = answer.lock().unwrap().write_all(b"\x1b[1;1R");
                    answered += 1;
                }
            }
        });
        Pty {
            pseudo,
            input,
            screen,
            reader: Some(reader),
            process,
        }
    }
    fn type_keys(&self, keys: &[u8]) {
        let mut input = self.input.lock().unwrap();
        input.write_all(keys).unwrap();
        input.flush().unwrap();
    }
    fn screen(&self) -> Vec<u8> {
        self.screen.lock().unwrap().clone()
    }
    fn wait_for(&self, needle: &str, seconds: u64) {
        let start = Instant::now();
        while !String::from_utf8_lossy(&self.screen()).contains(needle) {
            assert!(
                start.elapsed() < Duration::from_secs(seconds),
                "never displayed {needle:?}; screen: {:?}",
                String::from_utf8_lossy(&self.screen())
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    /// Waits for the process, closes the pseudoconsole, and returns the exit code
    /// and everything the terminal displayed.
    fn finish(mut self, seconds: u64) -> (u32, String) {
        // SAFETY: valid owned process handle.
        let waited = unsafe { WaitForSingleObject(self.process, (seconds * 1000) as u32) };
        let mut code = 0u32;
        if waited != 0 {
            // SAFETY: valid owned process handle; a hung child must not leak.
            unsafe { TerminateProcess(self.process, 99) };
        }
        // SAFETY: valid owned handle and out-pointer.
        unsafe {
            GetExitCodeProcess(self.process, &mut code);
            CloseHandle(self.process);
        }
        assert_eq!(
            waited,
            0,
            "child did not exit; screen: {:?}",
            String::from_utf8_lossy(&self.screen())
        );
        self.process = 0 as HANDLE;
        // SAFETY: closes the pseudoconsole exactly once; the output pipe then reaches EOF.
        unsafe { ClosePseudoConsole(self.pseudo) };
        self.pseudo = 0;
        self.reader.take().unwrap().join().unwrap();
        let screen = String::from_utf8_lossy(&self.screen()).into_owned();
        assert_no_secret_bytes("terminal screen", screen.as_bytes());
        (code, screen)
    }
}

impl Drop for Pty {
    /// Cleans up on any early panic: terminate the child, close the handles,
    /// close the pseudoconsole (which ends the reader thread) and join it.
    fn drop(&mut self) {
        if self.process != 0 as HANDLE {
            // SAFETY: owned, still-open process handle (finish() zeroes it).
            unsafe {
                TerminateProcess(self.process, 99);
                CloseHandle(self.process);
            }
            self.process = 0 as HANDLE;
        }
        if self.pseudo != 0 {
            // SAFETY: owned pseudoconsole closed exactly once.
            unsafe { ClosePseudoConsole(self.pseudo) };
            self.pseudo = 0;
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn inspect_command(w: &World) -> String {
    format!(
        "\"{}\" inspect --profile container --input \"{}\" --alias {} --secret-interactive --json",
        env!("CARGO_BIN_EXE_oncl"),
        w.rsa_key.display(),
        w.pki.rsa.alias
    )
}
#[test]
fn control_a_terminal_program_that_echoes_shows_typed_characters_in_the_harness() {
    // `set /p` reads a line with echo on: the harness must display the sentinel.
    let pty = Pty::start("cmd.exe /d /c \"set /p v=echo-control: \"");
    pty.wait_for("echo-control:", 20);
    pty.type_keys(b"ECHOSENTINEL\r");
    let (_, screen) = pty.finish(20);
    assert!(
        screen.contains("ECHOSENTINEL"),
        "harness cannot observe echo: {screen:?}"
    );
}
#[test]
fn interactive_secret_is_read_without_echo_and_the_console_mode_is_restored() {
    // The console-mode probe needs Python; its absence is a failure, not a skip.
    assert!(
        Command::new("python").arg("--version").output().is_ok(),
        "python is required for the console-mode probe"
    );
    let w = world();
    // The probe prints the console input mode before and after; oncl runs between.
    let probe = "python -c \"import ctypes;m=ctypes.c_uint32();ctypes.windll.kernel32.GetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-10),ctypes.byref(m));print('MODE=%x'%m.value)\"";
    let line = format!(
        "cmd.exe /d /c \"{probe} & {} & echo EXIT=%errorlevel% & {probe}\"",
        inspect_command(&w)
    );
    let pty = Pty::start(&line);
    pty.wait_for("input hidden", 60);
    let typed = PASSWORD.as_bytes();
    pty.type_keys(typed);
    pty.type_keys(b"\r");
    let (code, screen) = pty.finish(60);
    assert_eq!(code, 0, "{screen:?}");
    assert!(
        !screen.contains(PASSWORD) && !screen.contains("synthetic"),
        "the typed secret was echoed to the terminal: {screen:?}"
    );
    assert!(screen.contains("EXIT=0"), "{screen:?}");
    assert!(
        screen.contains("\"entries\""),
        "the typed secret opened the container: {screen:?}"
    );
    let modes: Vec<&str> = screen
        .match_indices("MODE=")
        .map(|(i, _)| {
            let rest = &screen[i..];
            let end = rest[5..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .map_or(rest.len(), |n| n + 5);
            &rest[..end]
        })
        .collect();
    assert_eq!(modes.len(), 2, "{screen:?}");
    assert_eq!(
        modes[0], modes[1],
        "console mode restored exactly: {screen:?}"
    );
    eprintln!("CONSOLE_MODE before={} after={}", modes[0], modes[1]);
    let mode = u32::from_str_radix(modes[0].trim_start_matches("MODE="), 16).unwrap();
    assert_ne!(
        mode & 0x4,
        0,
        "ENABLE_ECHO_INPUT is back on after oncl: {screen:?}"
    );
}
#[test]
fn wrong_interactive_secret_and_ctrl_c_fail_closed_and_stay_silent() {
    let w = world();
    // A wrong password fails closed (exit 1) and is never shown.
    let pty = Pty::start(&inspect_command(&w));
    pty.wait_for("input hidden", 60);
    pty.type_keys(b"WRONGSENTINEL\r");
    let (code, screen) = pty.finish(60);
    assert_eq!(code, 1, "{screen:?}");
    assert!(!screen.contains("WRONGSENTINEL"), "{screen:?}");
    assert!(!screen.contains("\"entries\""), "{screen:?}");
    // Ctrl-C at the prompt cancels (130) without echoing the partial secret.
    let pty = Pty::start(&inspect_command(&w));
    pty.wait_for("input hidden", 60);
    pty.type_keys(b"PARTIALSENTINEL");
    pty.type_keys(b"\x03");
    let (code, screen) = pty.finish(60);
    assert_eq!(code, 130, "{screen:?}");
    assert!(!screen.contains("PARTIALSENTINEL"), "{screen:?}");
}
