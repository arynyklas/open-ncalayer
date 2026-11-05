//! The external tools of the matrix: how they are found, which versions they report, and a
//! bounded process runner.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

/// What a finished process left.
#[derive(Debug)]
pub struct Out {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// stdout then stderr, for a failure message (at most a few lines).
    pub fn brief(&self) -> String {
        let mut text = self.stdout_text();
        text.push_str(&self.stderr);
        let text = text.trim();
        let cut: String = text.chars().take(900).collect();
        format!("exit {:?}: {cut}", self.code)
    }
}

/// Runs `command` with `stdin`, killing it after `limit`.
pub fn exec(command: &mut Command, stdin: &[u8], limit: Duration) -> anyhow::Result<Out> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {:?}", command.get_program()))?;
    let mut input = child.stdin.take().context("no stdin")?;
    let bytes = stdin.to_vec();
    let writer = thread::spawn(move || {
        let _ = input.write_all(&bytes);
    });
    let mut stdout = child.stdout.take().context("no stdout")?;
    let mut stderr = child.stderr.take().context("no stderr")?;
    let out_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout.read_to_end(&mut buffer);
        buffer
    });
    let err_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr.read_to_end(&mut buffer);
        buffer
    });
    let (sender, receiver) = mpsc::channel();
    let pid = child.id();
    let waiter = thread::spawn(move || {
        let status = child.wait();
        let _ = sender.send(status);
    });
    let status = match receiver.recv_timeout(limit) {
        Ok(status) => status.context("waiting for the process")?,
        Err(_) => {
            kill(pid);
            let _ = waiter.join();
            bail!("{:?} did not finish in {limit:?}", command.get_program());
        }
    };
    let _ = waiter.join();
    let _ = writer.join();
    Ok(Out {
        code: status.code(),
        stdout: out_reader.join().unwrap_or_default(),
        stderr: String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).into_owned(),
    })
}

fn kill(pid: u32) {
    #[cfg(unix)]
    {
        // SAFETY: `kill` takes a process id and a signal number and touches no memory.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .output();
    }
}

/// The default bound of one tool call.
pub const SHORT: Duration = Duration::from_secs(180);

/// The tools found for this run.
pub struct Tools {
    pub openssl: PathBuf,
    pub openssl_version: String,
    /// The Python of the pyHanko environment, if configured and importable.
    pub python: Option<PathBuf>,
    pub python_versions: Vec<(String, String)>,
    /// Why the Python oracles are unavailable.
    pub python_missing: Option<String>,
    pub docker_version: Option<String>,
    /// An address of this host the NCANode container can reach: the Docker bridge's gateway
    /// where that is this host's own interface (native Docker), else the address of the
    /// default route (Docker Desktop's engine lives in another VM of the same network).
    pub container_host: Option<std::net::Ipv4Addr>,
}

impl Tools {
    pub fn discover() -> anyhow::Result<Tools> {
        let openssl = find_openssl()?;
        let out = exec(
            Command::new(&openssl).arg("version"),
            b"",
            Duration::from_secs(20),
        )?;
        let openssl_version = out.stdout_text().trim().to_owned();
        let (python, python_versions, python_missing) =
            match std::env::var_os("ONCL_PYHANKO_PYTHON") {
                None => (
                    None,
                    Vec::new(),
                    Some(
                        "ONCL_PYHANKO_PYTHON is not set: point it at a Python with pyHanko 0.38, \
                     lxml and cryptography (python -m venv + pip install pyHanko==0.38.0 \
                     pyhanko-certvalidator==0.33.0 lxml)"
                            .to_owned(),
                    ),
                ),
                Some(python) => {
                    let python = PathBuf::from(python);
                    match python_versions(&python) {
                        Ok(versions) => (Some(python), versions, None),
                        Err(e) => (
                            None,
                            Vec::new(),
                            Some(format!("{}: {e:#}", python.display())),
                        ),
                    }
                }
            };
        let docker_version = exec(
            Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]),
            b"",
            Duration::from_secs(20),
        )
        .ok()
        .filter(Out::ok)
        .map(|o| o.stdout_text().trim().to_owned());
        // NCANode runs in Linux only.
        let docker_gateway = docker_version
            .as_ref()
            .filter(|_| cfg!(target_os = "linux"))
            .and_then(|_| {
                exec(
                    Command::new("docker").args([
                        "network",
                        "inspect",
                        "bridge",
                        "--format",
                        "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
                    ]),
                    b"",
                    Duration::from_secs(20),
                )
                .ok()
                .filter(Out::ok)
                .and_then(|o| o.stdout_text().trim().parse().ok())
            });
        let container_host = docker_gateway
            .filter(|gateway| std::net::TcpListener::bind((*gateway, 0)).is_ok())
            .or_else(|| {
                docker_gateway?;
                // The source address of a route to a public address; nothing is sent.
                let socket =
                    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
                socket
                    .connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9))
                    .ok()?;
                match socket.local_addr().ok()?.ip() {
                    std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
                    _ => None,
                }
            });
        Ok(Tools {
            openssl,
            openssl_version,
            python,
            python_versions,
            python_missing,
            docker_version,
            container_host,
        })
    }

    /// The version `python_versions` found for `package`.
    pub fn python_package(&self, package: &str) -> String {
        self.python_versions
            .iter()
            .find(|(name, _)| name == package)
            .map_or_else(|| "?".to_owned(), |(_, version)| version.clone())
    }
}

/// `(package, version)` of the packages the matrix uses; an error unless all import.
fn python_versions(python: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let script = "import importlib.metadata as m, sys\n\
        names = ['pyHanko', 'pyhanko-certvalidator', 'lxml', 'cryptography', 'asn1crypto']\n\
        print(sys.version.split()[0])\n\
        [print(n + '=' + m.version(n)) for n in names]\n\
        import pyhanko.sign, lxml.etree, cryptography.x509, asn1crypto.cms\n";
    let out = exec(
        Command::new(python).args(["-c", script]),
        b"",
        Duration::from_secs(60),
    )?;
    if !out.ok() {
        bail!(
            "the Python oracle environment is incomplete: {}",
            out.brief()
        );
    }
    let mut lines = out
        .stdout_text()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let python_version = lines.remove(0);
    let mut versions = vec![("python".to_owned(), python_version)];
    for line in lines {
        if let Some((name, version)) = line.split_once('=') {
            versions.push((name.to_owned(), version.to_owned()));
        }
    }
    Ok(versions)
}

fn find_openssl() -> anyhow::Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = std::env::var_os("ONCL_OPENSSL") {
        candidates.push(explicit.into());
    }
    candidates.push("openssl".into());
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432"] {
            if let Some(base) = std::env::var_os(var) {
                candidates.push(Path::new(&base).join("Git/usr/bin/openssl.exe"));
            }
        }
    }
    candidates
        .into_iter()
        .find(|c| {
            Command::new(c)
                .arg("version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .context("OpenSSL is unavailable: install it or set ONCL_OPENSSL to its executable")
}

/// Hex sha256 of a file's bytes, streamed.
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path).with_context(|| path.display().to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
