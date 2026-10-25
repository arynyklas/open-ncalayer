//! `nmhost`: the native messaging host of OpenNCALayer (roadmap D27).
//!
//! The browser starts it for the extension's `runtime.connectNative` and talks to it over
//! stdio. The relay reads `nmhost.json` next to its executable, reaches the daemon over local
//! IPC (starting it when none listens) and moves frames between the two without parsing
//! them. It lives outside the application directory, so updates never replace it under a
//! running browser.

mod relay;
mod spawn;

fn main() {
    // The browser passes the extension origin and `--parent-window=…` (Chromium) or the
    // manifest path and the extension id (Firefox): nothing the relay needs.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    eprintln!(
        "nmhost {}: browser arguments {args:?} ignored",
        relay::VERSION
    );
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("nmhost: cannot start the async runtime: {e}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(relay::run());
    // Exit without dropping the runtime: its shutdown would wait for the blocking read of
    // stdin, which may never end.
    std::process::exit(i32::from(code));
}
