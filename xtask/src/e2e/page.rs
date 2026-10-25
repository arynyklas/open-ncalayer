//! The servers of the e2e run: the scenario page over plain HTTP and a stand-in for the
//! original NCALayer. Both serve on background threads until the xtask exits.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use anyhow::Context;
use tungstenite::Message;

/// The scenario page (`xtask/assets/e2e/index.html`).
pub const INDEX_HTML: &str = include_str!("../../assets/e2e/index.html");

/// Port of the stand-in original NCALayer (`ws://127.0.0.1:13600/`).
pub const ORIGINAL_PORT: u16 = 13600;

/// What the stand-in original says first on every connection.
pub const ORIGINAL_GREETING: &str = r#"{"result":{"version":"fake-original"}}"#;

/// Serves [`INDEX_HTML`] at `http://127.0.0.1:<port>/`; the port.
pub fn serve_page() -> anyhow::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("binding the page server")?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = answer_http(stream);
            });
        }
    });
    Ok(port)
}

/// Answers one HTTP request: the page for `/` and `/index.html`, 404 for anything else.
fn answer_http(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Skip the headers; the requests are bodyless GETs.
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim_end().is_empty() {
            break;
        }
    }
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let (status, content_type, body) = match path {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", INDEX_HTML),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found"),
    };
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

/// The stand-in original NCALayer on `ws://127.0.0.1:13600/`: greets every connection with
/// [`ORIGINAL_GREETING`] and reads until it closes.
pub fn serve_original() -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", ORIGINAL_PORT))
        .with_context(|| format!("binding 127.0.0.1:{ORIGINAL_PORT} for the stand-in original"))?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let Ok(mut socket) = tungstenite::accept(stream) else {
                    return;
                };
                if socket.send(Message::text(ORIGINAL_GREETING)).is_err() {
                    return;
                }
                while socket.read().is_ok() {}
            });
        }
    });
    Ok(())
}
