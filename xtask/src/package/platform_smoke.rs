//! The behaviour smoke of the standalone packages: what a user does with the archives they
//! downloaded, in a clean directory, without a GUI. The archives are UNPACKED into a fresh
//! directory and the unpacked programs are started; nothing of the workspace's build output
//! is used except the synthetic test PKI of `fixtures/synthetic/`, which is an input and
//! never in a package.
//!
//! 1. `oncl --version`, `oncl hash` of a file and of stdin against an independent digest,
//!    `oncl verify` refusing a file that is not a signature.
//! 2. `oncl-server` without a subcommand and `serve` with the shipped example configuration
//!    (the API disabled): both print/say nothing about a listener and end by themselves
//!    while their stdin stays open, and the operating system lists no listening socket on
//!    the configured port and refuses a connection to it.
//! 3. The operator opts in: a token from `oncl-server token-create`, a named synthetic RSA
//!    key, loopback OCSP/CRL of a synthetic PKI, the example configuration with those
//!    settings and `--enable-api`. The OS lists the one loopback listener of the server
//!    process; `oncl --endpoint` signs through it (CMS), the audit journal exists, `oncl
//!    verify` against the same PKI says `Valid` and `extract` returns the document.
//! 4. A newline on the control pipe stops the server cleanly; the port is closed again.

use std::ffi::OsStr;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use der::Encode as _;
use oncl_pki::crl::MockCrl;
use oncl_pki::http::{GetOptions, HttpRequest, HttpTransport as _};
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::private_fs::PrivateDirectory;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_update::Version;
use sha2::{Digest as _, Sha256};

use super::platform::{Flavor, Os, Product, unpack};

/// The password of the synthetic container the smoke creates for its named key.
const CONTAINER_PASSWORD: &str = "smoke-container-password";
/// The name of the operator key the client signs with.
const KEY_NAME: &str = "smoke-key";

/// Whether this host can start programs of `flavor`.
pub fn runnable(flavor: &Flavor) -> bool {
    match flavor.os {
        Os::Windows => cfg!(windows),
        Os::Linux => cfg!(all(target_os = "linux", target_arch = "x86_64")),
        Os::Macos => cfg!(target_os = "macos"),
    }
}

/// Unpacks the `archives` (the archives of [`Product::ALL`] in that order) under `work` and
/// runs the whole smoke from there. Says so, and does nothing else, when this host cannot
/// start `flavor`.
///
/// # Errors
///
/// Any step fails; the message has the program's output.
pub fn run(
    root: &Path,
    flavor: &Flavor,
    version: &Version,
    archives: &[PathBuf],
    work: &Path,
) -> anyhow::Result<()> {
    if !runnable(flavor) {
        println!(
            "smoke of {}: NOT executed, this host cannot start {} programs",
            flavor.name, flavor.name
        );
        return Ok(());
    }
    let unpacked = work.join("unpacked");
    let mut dirs = Vec::new();
    for (product, archive) in Product::ALL.into_iter().zip(archives) {
        let dir = unpack(archive, flavor.os, &unpacked.join(product.name()))?;
        dirs.push(dir.join(product.exe(flavor.os)));
    }
    let [cli, server] = dirs.as_slice() else {
        bail!("the smoke takes the archives of oncl and oncl-server");
    };
    let example = std::fs::read_to_string(
        server
            .parent()
            .context("the unpacked server has no directory")?
            .join("server.example.toml"),
    )
    .context("reading the unpacked server.example.toml")?;
    let smoke_work = work.join("smoke");
    std::fs::create_dir_all(&smoke_work)?;
    // The client stages what it downloads (OCSP, CRL) in its working directory unless told
    // otherwise, and on Unix refuses one that others can reach: run it from a private one.
    let client = smoke_work.join("client");
    PrivateDirectory::create(&client).context("creating the client's private directory")?;
    let smoke = Smoke {
        root,
        cli,
        server,
        version,
        example: &example,
        work: &smoke_work,
        client: &client,
    };
    smoke.client_basics()?;
    smoke.disabled()?;
    smoke.enabled()?;
    println!(
        "smoke of {}: the unpacked packages hash, verify, stay silent when disabled, sign through \
         the opted-in loopback server and stop cleanly",
        flavor.name
    );
    Ok(())
}

struct Smoke<'a> {
    root: &'a Path,
    cli: &'a Path,
    server: &'a Path,
    version: &'a Version,
    /// The text of the unpacked `server.example.toml`.
    example: &'a str,
    work: &'a Path,
    /// The working directory of the client: private.
    client: &'a Path,
}

/// What a finished program printed and exited with.
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn ensure_code(&self, expected: i32, what: &str) -> anyhow::Result<()> {
        ensure!(
            self.code == expected,
            "{what}: exit {}, expected {expected}\nstdout: {}\nstderr: {}",
            self.code,
            self.stdout,
            self.stderr
        );
        Ok(())
    }

    fn json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::from_str(&self.stdout)
            .with_context(|| format!("not JSON: {}\nstderr: {}", self.stdout, self.stderr))
    }
}

/// Runs `command` with `stdin` as its input, at most `limit`.
fn exec(command: &mut Command, stdin: &[u8], limit: Duration) -> anyhow::Result<Out> {
    let shown = format!("{command:?}");
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {shown}"))?;
    let mut input = child.stdin.take().context("stdin")?;
    let bytes = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = input.write_all(&bytes);
    });
    let mut stdout = child.stdout.take().context("stdout")?;
    let mut stderr = child.stderr.take().context("stderr")?;
    let out_reader = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stdout.read_to_end(&mut text);
        text
    });
    let err_reader = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        text
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{shown} did not end in {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
    Ok(Out {
        code: status.code().unwrap_or(-1),
        stdout: text(out_reader.join().unwrap_or_default()),
        stderr: text(err_reader.join().unwrap_or_default()),
    })
}

const SHORT: Duration = Duration::from_secs(120);

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// A TCP port that is free now on the loopback.
fn free_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Whether something accepts a connection at `address`.
fn accepts(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok()
}

/// A TCP socket in the LISTEN state, from the operating system's table.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Listener {
    address: IpAddr,
    port: u16,
    /// Only where the table names the process (Windows).
    pid: Option<u32>,
}

/// The listening TCP sockets of the host, from the OS (`netstat -ano` on Windows,
/// `/proc/net/tcp*` on Linux, `netstat -an` on macOS).
fn listeners() -> anyhow::Result<Vec<Listener>> {
    if cfg!(windows) {
        let out = Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .context("running netstat")?;
        ensure!(out.status.success(), "netstat: {}", out.status);
        Ok(parse_netstat_windows(&String::from_utf8_lossy(&out.stdout)))
    } else if cfg!(target_os = "linux") {
        let mut found = Vec::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let text = std::fs::read_to_string(table).with_context(|| table.to_owned())?;
            found.extend(parse_proc_net_tcp(&text));
        }
        Ok(found)
    } else {
        let out = Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .context("running netstat")?;
        ensure!(out.status.success(), "netstat: {}", out.status);
        Ok(parse_netstat_bsd(&String::from_utf8_lossy(&out.stdout)))
    }
}

fn split_address(text: &str, separator: char) -> Option<(IpAddr, u16)> {
    let (host, port) = text.rsplit_once(separator)?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let address = if host == "*" {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    } else {
        host.parse().ok()?
    };
    Some((address, port))
}

/// `TCP  127.0.0.1:13579  0.0.0.0:0  LISTENING  1234`.
fn parse_netstat_windows(text: &str) -> Vec<Listener> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [proto, local, _, state, pid] = fields.as_slice() else {
                return None;
            };
            if *proto != "TCP" || *state != "LISTENING" {
                return None;
            }
            let (address, port) = split_address(local, ':')?;
            Some(Listener {
                address,
                port,
                pid: pid.parse().ok(),
            })
        })
        .collect()
}

/// `tcp4  0  0  127.0.0.1.13579  *.*  LISTEN`.
fn parse_netstat_bsd(text: &str) -> Vec<Listener> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if !fields.first()?.starts_with("tcp") || fields.last() != Some(&"LISTEN") {
                return None;
            }
            let (address, port) = split_address(fields.get(3)?, '.')?;
            Some(Listener {
                address,
                port,
                pid: None,
            })
        })
        .collect()
}

/// `  0: 0100007F:CB1F 00000000:0000 0A ...` (state 0A is LISTEN); IPv4 and IPv6.
fn parse_proc_net_tcp(text: &str) -> Vec<Listener> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(3) != Some(&"0A") {
                return None;
            }
            let (host, port) = fields.get(1)?.split_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            let address = match host.len() {
                8 => IpAddr::from(
                    u32::from_str_radix(host, 16)
                        .ok()?
                        .swap_bytes()
                        .to_be_bytes(),
                ),
                32 => {
                    let mut octets = [0_u8; 16];
                    for (i, chunk) in octets.chunks_mut(4).enumerate() {
                        let word = u32::from_str_radix(&host[i * 8..i * 8 + 8], 16).ok()?;
                        chunk.copy_from_slice(&word.swap_bytes().to_be_bytes());
                    }
                    IpAddr::from(octets)
                }
                _ => return None,
            };
            Some(Listener {
                address,
                port,
                pid: None,
            })
        })
        .collect()
}

/// The sockets listening on `port` (any address).
fn on_port(port: u16) -> anyhow::Result<Vec<Listener>> {
    Ok(listeners()?
        .into_iter()
        .filter(|listener| listener.port == port)
        .collect())
}

/// A started `oncl-server`, killed on drop.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Server {
    fn start(server: &Path, args: &[&OsStr]) -> anyhow::Result<Self> {
        let mut child = Command::new(server)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {}", server.display()))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().context("stdout")?;
        let mut stderr = child.stderr.take().context("stderr")?;
        let (sender, lines) = channel();
        let err_sender = sender.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            for line in text.lines() {
                let _ = err_sender.send(format!("stderr: {line}"));
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
        })
    }

    /// The next line of output containing `needle`, within `limit`; the lines before it.
    fn expect_line(&self, needle: &str, limit: Duration) -> anyhow::Result<(String, Vec<String>)> {
        let deadline = Instant::now() + limit;
        let mut seen = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return Ok((line, seen)),
                Ok(line) => seen.push(line),
                Err(_) => bail!("no {needle:?} from the server in {limit:?}; saw {seen:?}"),
            }
        }
    }

    /// Waits for the process to end by itself and returns its exit code.
    fn wait(&mut self, limit: Duration) -> anyhow::Result<i32> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status.code().unwrap_or(-1));
            }
            ensure!(
                Instant::now() < deadline,
                "the server did not end in {limit:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Everything printed so far.
    fn drain(&self) -> Vec<String> {
        self.lines.try_iter().collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Already ended if these fail.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn path_str(path: &Path) -> anyhow::Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

impl Smoke<'_> {
    fn oncl(&self, args: &[&str]) -> anyhow::Result<Out> {
        exec(
            Command::new(self.cli).current_dir(self.client).args(args),
            b"",
            SHORT,
        )
    }

    fn client_basics(&self) -> anyhow::Result<()> {
        let printed = self.oncl(&["--version"])?;
        printed.ensure_code(0, "oncl --version")?;
        ensure!(
            printed.stdout.contains(&self.version.to_string()),
            "oncl --version printed {:?}, not the version {}",
            printed.stdout,
            self.version
        );
        let printed = exec(Command::new(self.server).arg("--version"), b"", SHORT)?;
        printed.ensure_code(0, "oncl-server --version")?;
        ensure!(
            printed.stdout.contains(&self.version.to_string()),
            "oncl-server --version printed {:?}, not the version {}",
            printed.stdout,
            self.version
        );

        let document: Vec<u8> = (0..70_000_u32)
            .flat_map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes())
            .collect();
        let expected = hex(&Sha256::digest(&document));
        let file = self.work.join("document.bin");
        std::fs::write(&file, &document)?;
        let hashed = self.oncl(&[
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path_str(&file)?,
            "--json",
        ])?;
        hashed.ensure_code(0, "oncl hash")?;
        ensure!(
            hashed.json()?["digest"] == expected.as_str(),
            "oncl hash gave {}, an independent SHA-256 gives {expected}",
            hashed.stdout
        );
        let piped = exec(
            Command::new(self.cli).current_dir(self.client).args([
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                "-",
            ]),
            b"abc",
            SHORT,
        )?;
        piped.ensure_code(0, "oncl hash from stdin")?;
        ensure!(
            piped
                .stdout
                .contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "oncl hash of abc: {}",
            piped.stdout
        );
        // A file that is not a signature is refused, never reported valid.
        let refused = self.oncl(&["verify", "--profile", "cms", "--input", path_str(&file)?])?;
        ensure!(
            refused.code == 1 && refused.stderr.contains("InvalidInput"),
            "oncl verify of a non-signature: exit {}, not the refusal InvalidInput\n{}{}",
            refused.code,
            refused.stdout,
            refused.stderr
        );
        println!(
            "oncl {}: version, hash (file and stdin), verify refusal: ok",
            self.version
        );
        Ok(())
    }

    /// A fresh private operator directory with the example configuration (and `edit`'s
    /// changes to it) as `server.toml`.
    fn operator(
        &self,
        name: &str,
        edit: impl FnOnce(&mut toml::Table) -> anyhow::Result<()>,
    ) -> anyhow::Result<(PathBuf, PrivateDirectory)> {
        let path = self.work.join(name);
        let directory = PrivateDirectory::create(&path)
            .with_context(|| format!("creating the private directory {}", path.display()))?;
        let mut table: toml::Table = self.example.parse().context("the example configuration")?;
        edit(&mut table)?;
        directory
            .create_file("server.toml")?
            .write_all(toml::to_string(&table)?.as_bytes())?;
        Ok((path, directory))
    }

    fn disabled(&self) -> anyhow::Result<()> {
        // No subcommand: nothing starts.
        let bare = exec(&mut Command::new(self.server), b"", SHORT)?;
        bare.ensure_code(0, "oncl-server without a subcommand")?;
        ensure!(
            !bare.stdout.contains("listening"),
            "oncl-server without a subcommand says it listens: {}",
            bare.stdout
        );
        // The example, verbatim apart from its location: the default is "off".
        let (verbatim, _) = self.operator("operator-example", |_| Ok(()))?;
        let mut server = Server::start(
            self.server,
            &[
                "serve".as_ref(),
                "--config".as_ref(),
                verbatim.join("server.toml").as_os_str(),
                "--shutdown-stdin".as_ref(),
            ],
        )?;
        // The control pipe is still open: a listening service would wait for it.
        let code = server.wait(Duration::from_secs(30))?;
        ensure!(
            code == 0,
            "serve with the example: exit {code}: {:?}",
            server.drain()
        );
        let said = server.drain().join("\n");
        ensure!(
            said.contains("disabled: no listener") && !said.contains("listening"),
            "serve with the example said: {said}"
        );
        // The same on a port of our choice, which the OS must then show closed.
        let port = free_port()?;
        let (tweaked, _) = self.operator("operator-disabled", |table| {
            table.insert("bind".into(), format!("127.0.0.1:{port}").into());
            Ok(())
        })?;
        let mut server = Server::start(
            self.server,
            &[
                "serve".as_ref(),
                "--config".as_ref(),
                tweaked.join("server.toml").as_os_str(),
                "--shutdown-stdin".as_ref(),
            ],
        )?;
        let code = server.wait(Duration::from_secs(30))?;
        ensure!(
            code == 0,
            "serve (disabled): exit {code}: {:?}",
            server.drain()
        );
        let found = on_port(port)?;
        ensure!(
            found.is_empty(),
            "the disabled server left listeners: {found:?}"
        );
        ensure!(
            !accepts(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
            "a connection to the disabled server's port succeeded"
        );
        println!("oncl-server disabled: exits by itself, no listener on port {port}: ok");
        Ok(())
    }

    fn enabled(&self) -> anyhow::Result<()> {
        let pki = Responder::start()?;
        let port = free_port()?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let audit = self.work.join("audit");
        let scratch = self.work.join("scratch");
        // Neither exists: the server creates its journal and scratch directories itself, and
        // refuses an existing, empty audit directory as a journal it cannot trust.

        // The operator's private directory: the token comes from the real subcommand, the
        // key container and its password are written through the private-file API, as a
        // Windows operator's files have to be.
        let operator = self.work.join("operator-enabled");
        let private = PrivateDirectory::create(&operator)?;
        let created = exec(
            Command::new(self.server)
                .args(["token-create", "--directory"])
                .arg(&operator)
                .args(["--name", "client.token"]),
            b"",
            SHORT,
        )?;
        created.ensure_code(0, "oncl-server token-create")?;
        let verifier = created
            .stdout
            .trim()
            .strip_prefix("verifier=")
            .filter(|verifier| verifier.len() == 64)
            .with_context(|| format!("token-create printed {:?}", created.stdout))?
            .to_owned();
        let token = std::fs::read_to_string(operator.join("client.token"))
            .context("the created token file")?;
        ensure!(
            !created.stdout.contains(token.trim()) && !created.stderr.contains(token.trim()),
            "token-create printed the token"
        );

        let leaf = pki.leaf("user-rsa-sign")?;
        private
            .create_file("signer.p12")?
            .write_all(&container(&leaf, CONTAINER_PASSWORD)?)?;
        private
            .create_file("signer.password")?
            .write_all(CONTAINER_PASSWORD.as_bytes())?;
        let trust = self.work.join("trust");
        std::fs::create_dir_all(&trust)?;
        let root_cert = trust.join("root.cer");
        let inter_cert = trust.join("inter.cer");
        std::fs::copy(
            self.root.join("fixtures/synthetic/root-gost2015.cer"),
            &root_cert,
        )?;
        std::fs::write(
            &inter_cert,
            pki.inter
                .cert
                .to_der()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )?;

        let text = |path: &Path| path_str(path).map(|path| toml::Value::String(path.to_owned()));
        let config = {
            let mut table: toml::Table =
                self.example.parse().context("the example configuration")?;
            ensure!(
                table.get("enabled") == Some(&toml::Value::Boolean(false)),
                "the shipped example is not disabled"
            );
            table.insert("bind".into(), address.to_string().into());
            table.insert("audit_directory".into(), text(&audit)?);
            table.insert("scratch_directory".into(), text(&scratch)?);
            let mut token_table = toml::Table::new();
            token_table.insert("id".into(), "smoke-client".into());
            token_table.insert("verifier".into(), verifier.into());
            token_table.insert(
                "actions".into(),
                toml::Value::Array(
                    ["hash", "sign", "verify", "extract"]
                        .map(|action| toml::Value::String(action.into()))
                        .into(),
                ),
            );
            token_table.insert(
                "keys".into(),
                toml::Value::Array(vec![toml::Value::String(KEY_NAME.into())]),
            );
            table.insert(
                "tokens".into(),
                toml::Value::Array(vec![token_table.into()]),
            );
            let mut key = toml::Table::new();
            key.insert("source".into(), "file".into());
            key.insert("name".into(), KEY_NAME.into());
            key.insert("path".into(), text(&operator.join("signer.p12"))?);
            key.insert("alias".into(), leaf.alias.clone().into());
            let mut secret = toml::Table::new();
            secret.insert("directory".into(), text(&operator)?);
            secret.insert("name".into(), "signer.password".into());
            key.insert("secret".into(), secret.into());
            table.insert("keys".into(), toml::Value::Array(vec![key.into()]));
            let mut pki_table = toml::Table::new();
            pki_table.insert(
                "anchors".into(),
                toml::Value::Array(vec![text(&root_cert)?]),
            );
            pki_table.insert(
                "intermediates".into(),
                toml::Value::Array(vec![text(&inter_cert)?]),
            );
            let mut endpoint = toml::Table::new();
            endpoint.insert("origin".into(), pki.origin.clone().into());
            endpoint.insert(
                "addresses".into(),
                toml::Value::Array(vec![pki.address.to_string().into()]),
            );
            pki_table.insert(
                "endpoints".into(),
                toml::Value::Array(vec![endpoint.into()]),
            );
            table.insert("pki".into(), pki_table.into());
            toml::to_string(&table)?
        };
        private
            .create_file("server.toml")?
            .write_all(config.as_bytes())?;

        let mut server = Server::start(
            self.server,
            &[
                "serve".as_ref(),
                "--config".as_ref(),
                operator.join("server.toml").as_os_str(),
                "--enable-api".as_ref(),
                "--shutdown-stdin".as_ref(),
            ],
        )?;
        let (line, _) = server.expect_line("listening", Duration::from_secs(60))?;
        ensure!(
            line.trim() == format!("listening {address}"),
            "the server says {line:?}, expected a listener on {address} only"
        );
        let found = on_port(port)?;
        ensure!(
            found.len() == 1
                && found[0].address == IpAddr::from(Ipv4Addr::LOCALHOST)
                && found[0].pid.is_none_or(|pid| pid == server.child.id()),
            "expected exactly the server's loopback listener on {port}, the OS lists {found:?}"
        );

        // A real signature through the unpacked client and the unpacked server.
        let document = self.work.join("document.bin");
        let signature = self.work.join("document.p7s");
        let endpoint = format!("http://{address}");
        let token_file = operator.join("client.token");
        let signed = self.oncl(&[
            "--endpoint",
            &endpoint,
            "--token-file",
            path_str(&token_file)?,
            "sign",
            "--profile",
            "cms",
            "--key-name",
            KEY_NAME,
            "--authorize",
            "--input",
            path_str(&document)?,
            "--output",
            path_str(&signature)?,
            "--json",
        ])?;
        signed.ensure_code(0, "oncl sign through oncl-server")?;
        let report = signed.json()?;
        ensure!(
            report["code"] == "Completed" && report["applied"] == "Applied",
            "the sign report: {}",
            signed.stdout
        );
        let bytes = std::fs::read(&signature).context("the signature the server made")?;
        ensure!(bytes.len() > 256, "the signature has {} bytes", bytes.len());
        ensure!(
            !signed.stdout.contains(token.trim()) && !signed.stderr.contains(token.trim()),
            "the client printed the token"
        );

        // The same signature checked here, against the same synthetic PKI.
        let verified = self.oncl(&[
            "verify",
            "--profile",
            "cms",
            "--input",
            path_str(&signature)?,
            "--root",
            path_str(&root_cert)?,
            "--intermediate",
            path_str(&inter_cert)?,
            "--pki-endpoint",
            &pki.origin,
            "--json",
        ])?;
        verified
            .ensure_code(0, "oncl verify of the server's signature")
            .with_context(|| {
                format!(
                    "the PKI responder saw {:?}",
                    pki.seen.lock().map(|l| l.clone())
                )
            })?;
        ensure!(
            verified.json()?["verdict"] == "Valid",
            "the verdict: {}",
            verified.stdout
        );
        let extracted = self.work.join("extracted.bin");
        let result = self.oncl(&[
            "extract",
            "--input",
            path_str(&signature)?,
            "--output",
            path_str(&extracted)?,
        ])?;
        result.ensure_code(0, "oncl extract")?;
        ensure!(
            std::fs::read(&extracted)? == std::fs::read(&document)?,
            "the extracted content is not the signed document"
        );

        // Without the token the same request is refused.
        let refused = self.oncl(&[
            "--endpoint",
            &endpoint,
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path_str(&document)?,
        ])?;
        ensure!(
            refused.code != 0,
            "a request without a token was served: {}",
            refused.stdout
        );

        // Clean shutdown over the control pipe; the port closes.
        let stdin = server.stdin.as_mut().context("the control pipe")?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        server.expect_line(
            "stopped: owned listener and workers released",
            Duration::from_secs(60),
        )?;
        let code = server.wait(Duration::from_secs(60))?;
        ensure!(
            code == 0,
            "the server stopped with exit {code}: {:?}",
            server.drain()
        );
        ensure!(
            on_port(port)?.is_empty() && !accepts(address),
            "the port is still open after the shutdown"
        );
        let journal = std::fs::read_dir(&audit)?.count();
        ensure!(
            journal > 0,
            "the audit directory is empty after a signature"
        );
        drop(pki);
        println!(
            "oncl-server enabled on {address}: one loopback listener, signed {} bytes through \
             oncl --endpoint (verified Valid, extracted), {journal} audit file(s), clean stop: ok",
            bytes.len()
        );
        Ok(())
    }
}

// ---- the synthetic PKI with loopback OCSP and CRL -----------------------------------

fn raw(name: &str) -> anyhow::Result<KeyEntry> {
    let fixture = oncl_testkit::synthetic(name);
    let file = &fixture.path;
    let bytes = std::fs::read(file).with_context(|| file.display().to_string())?;
    oncl_pki::pkcs12::load(&bytes, &fixture.password)
        .map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?
        .into_iter()
        .next()
        .with_context(|| format!("{} holds no key", file.display()))
}

/// `input` (a DER GeneralName or a sequence of them) with every URI replaced by `url`.
fn uris(input: &[u8], url: &[u8]) -> anyhow::Result<Vec<u8>> {
    use der::{Decode as _, Reader as _, SliceReader};
    let any = der::asn1::AnyRef::from_der(input).map_err(|e| anyhow::anyhow!("{e}"))?;
    let tag = input[0];
    let body = if tag == 0x86 {
        url.to_vec()
    } else if tag & 0x20 != 0 {
        let mut reader = SliceReader::new(any.value()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut body = Vec::new();
        while !reader.is_finished() {
            let part = reader.tlv_bytes().map_err(|e| anyhow::anyhow!("{e}"))?;
            body.extend(uris(part, url)?);
        }
        body
    } else {
        any.value().to_vec()
    };
    let mut result = vec![tag];
    if body.len() < 128 {
        result.push(u8::try_from(body.len())?);
    } else {
        let length: Vec<u8> = body
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        result.push(0x80 | u8::try_from(length.len())?);
        result.extend(length);
    }
    result.extend(body);
    Ok(result)
}

/// `entry`'s certificate reissued by `issuer` with its OCSP and CRL locations at `origin`.
fn with_status_locations(
    entry: &KeyEntry,
    issuer: &KeyEntry,
    origin: &str,
    crl: &str,
) -> anyhow::Result<KeyEntry> {
    const OCSP: &str = "1.3.6.1.5.5.7.1.1";
    const CRL: &str = "2.5.29.31";
    let mut entry = entry.clone();
    let mut spec = TestCertSpec::from_cert(&entry.cert);
    let template = TestCertSpec::from_cert(&raw("inter-user-gost2015-sign")?.cert);
    spec.extensions
        .retain(|e| !matches!(e.extn_id.to_string().as_str(), OCSP | CRL));
    spec.extensions.extend(
        template
            .extensions
            .into_iter()
            .filter(|e| matches!(e.extn_id.to_string().as_str(), OCSP | CRL)),
    );
    for extension in &mut spec.extensions {
        let path = match extension.extn_id.to_string().as_str() {
            OCSP => Some("/ocsp".to_owned()),
            CRL => Some(format!("/{crl}.crl")),
            _ => None,
        };
        if let Some(path) = path {
            extension.extn_value = der::asn1::OctetString::new(uris(
                extension.extn_value.as_bytes(),
                format!("{origin}{path}").as_bytes(),
            )?)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }
    entry.cert = issue_cert(issuer, spec);
    Ok(entry)
}

/// A PKCS#12 container of `entry` under `password`, with fresh random salts.
fn container(entry: &KeyEntry, password: &str) -> anyhow::Result<Vec<u8>> {
    oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry
                .key
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .to_vec(),
            cert_der: Some(entry.cert.to_der().map_err(|e| anyhow::anyhow!("{e}"))?),
        }],
        &[],
        password,
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |bytes| getrandom::fill(bytes).expect("the operating system's random source"),
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))
}

/// The synthetic chain (`root-gost2015` → `inter-gost2015`) with a loopback responder for
/// OCSP and CRLs whose answers are fresh at the real time.
struct Responder {
    address: SocketAddr,
    origin: String,
    inter: KeyEntry,
    /// `METHOD path -> status` of every request answered, for the failure message.
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Responder {
    fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let origin = format!("http://{address}");
        let now = time::OffsetDateTime::now_utc();
        let root = raw("root-gost2015.key")?;
        let inter = with_status_locations(&raw("inter-gost2015.key")?, &root, &origin, "root")?;
        let ocsp = Arc::new(MockOcsp::new(raw("ocsp-gost2015")?).with_now(now));
        let crl = |issuer: &KeyEntry| {
            Arc::new(
                MockCrl::new(issuer.clone())
                    .with_this_update(now - time::Duration::MINUTE)
                    .next_update(Some(now + time::Duration::days(1))),
            )
        };
        let (root_crl, inter_crl) = (crl(&root), crl(&inter));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (stopped, log) = (stop.clone(), seen.clone());
        let url_origin = origin.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let Ok((socket, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                // A client may open a connection and send nothing for a while: never let one
                // connection hold up the others.
                let (url_origin, ocsp, root_crl, inter_crl, log) = (
                    url_origin.clone(),
                    ocsp.clone(),
                    root_crl.clone(),
                    inter_crl.clone(),
                    log.clone(),
                );
                std::thread::spawn(move || {
                    let _ = answer(socket, &url_origin, &ocsp, &root_crl, &inter_crl, &log);
                });
            }
        });
        Ok(Self {
            address,
            origin,
            inter,
            seen,
            stop,
            thread: Some(thread),
        })
    }

    /// A synthetic leaf issued by the intermediate, locating its status at this responder.
    fn leaf(&self, name: &str) -> anyhow::Result<KeyEntry> {
        with_status_locations(&raw(name)?, &self.inter, &self.origin, "inter")
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Answers one HTTP request of an OCSP client (POST) or a CRL client (GET).
fn answer(
    mut socket: TcpStream,
    origin: &str,
    ocsp: &MockOcsp,
    root_crl: &MockCrl,
    inter_crl: &MockCrl,
    log: &Mutex<Vec<String>>,
) -> anyhow::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let end = loop {
        let n = socket.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let header = |name: &str| {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_owned())
    };
    let length = header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < end + length {
        let n = socket.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let mut first = head.lines().next().unwrap_or_default().split_whitespace();
    let (method, path) = (
        first.next().unwrap_or_default(),
        first.next().unwrap_or_default(),
    );
    let url = format!("{origin}{path}");
    let content_type = header("content-type");
    // OCSP over POST (our server) or over GET (`/ocsp/<base64 request>`, our client), the
    // CRL of the root or of the intermediate by name.
    let reply = if method == "POST" {
        ocsp.send(&HttpRequest::post(
            &url,
            content_type.as_deref(),
            &bytes[end..end + length],
            GetOptions::default(),
        ))
    } else if path.starts_with("/ocsp") {
        ocsp.send(&HttpRequest::get(&url, GetOptions::default()))
    } else if path.contains("root") {
        root_crl.send(&HttpRequest::get(&url, GetOptions::default()))
    } else {
        inter_crl.send(&HttpRequest::get(&url, GetOptions::default()))
    };
    let outcome = match &reply {
        Ok(reply) => reply.status.to_string(),
        Err(e) => format!("error {e:?}"),
    };
    if let Ok(mut log) = log.lock() {
        log.push(format!("{method} {path} -> {outcome}"));
    }
    if let Ok(reply) = reply {
        write!(
            socket,
            "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.status,
            reply
                .content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
            reply.body.len()
        )?;
        socket.write_all(&reply.body)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_windows_socket_table() {
        let text = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1076
  TCP    127.0.0.1:13579        0.0.0.0:0              LISTENING       4242
  TCP    127.0.0.1:13579        127.0.0.1:50000        ESTABLISHED     4242
  TCP    [::1]:8080             [::]:0                 LISTENING       99
";
        let found = parse_netstat_windows(text);
        assert_eq!(found.len(), 3);
        assert!(found.contains(&Listener {
            address: Ipv4Addr::LOCALHOST.into(),
            port: 13579,
            pid: Some(4242)
        }));
        assert!(found.iter().any(|l| l.address.is_ipv6() && l.port == 8080));
    }

    #[test]
    fn parses_the_linux_socket_table() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:CB1F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n\
   1: 0100007F:CB1F 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0 100 0 0 10 0\n\
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n";
        let found = parse_proc_net_tcp(text);
        assert_eq!(
            found,
            vec![
                Listener {
                    address: Ipv4Addr::LOCALHOST.into(),
                    port: 0xCB1F,
                    pid: None
                },
                Listener {
                    address: Ipv4Addr::UNSPECIFIED.into(),
                    port: 22,
                    pid: None
                },
            ]
        );
    }

    #[test]
    fn parses_the_bsd_socket_table() {
        let text = "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
tcp4       0      0  127.0.0.1.13579        *.*                    LISTEN\n\
tcp4       0      0  127.0.0.1.13579        127.0.0.1.50000        ESTABLISHED\n";
        let found = parse_netstat_bsd(text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 13579);
    }

    #[test]
    fn a_free_port_is_closed_until_something_listens() {
        let port = free_port().unwrap();
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        assert!(!accepts(address));
        let listener = TcpListener::bind(address).unwrap();
        assert!(accepts(address));
        assert!(
            on_port(port).unwrap().iter().any(|l| l.port == port),
            "the OS table does not show the listener"
        );
        drop(listener);
    }
}
