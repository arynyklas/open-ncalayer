#![allow(dead_code)]
pub mod delivery;
pub mod token;
use oncl_pki::private_fs::PrivateDirectory;
use std::{
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use zeroize::Zeroizing;

pub fn sandbox() -> tempfile::TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target-task23/runtime");
    std::fs::create_dir_all(&root).unwrap();
    tempfile::tempdir_in(root).unwrap()
}
pub struct Process {
    pub child: Child,
    pub address: SocketAddr,
    pub token: Zeroizing<String>,
    pub directory: tempfile::TempDir,
    pub config_path: PathBuf,
}
impl Process {
    pub fn start(extra: &str) -> Self {
        Self::start_at(extra, "127.0.0.1:0")
    }
    pub fn start_at(extra: &str, bind: &str) -> Self {
        Self::configured(bind, |_| extra.to_owned())
    }
    pub fn configured(bind: &str, configure: impl FnOnce(&std::path::Path) -> String) -> Self {
        let directory = sandbox();
        let extra = configure(directory.path());
        let operator_path = directory.path().join("operator");
        let operator = PrivateDirectory::create(&operator_path).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
            .args(["token-create", "--directory"])
            .arg(&operator_path)
            .args(["--name", "token"])
            .output()
            .unwrap();
        assert!(output.status.success(), "token-create refused");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let verifier = stdout.trim().strip_prefix("verifier=").unwrap();
        let token = Zeroizing::new(std::fs::read_to_string(operator_path.join("token")).unwrap());
        let audit = directory.path().join("audit");
        let config = format!(
            "enabled = true\nbind = '{bind}'\naudit_directory = {}\n{}\n[[tokens]]\nid = 'synthetic-actor'\nverifier = '{}'\nactions = ['hash']\n",
            toml_path(&audit),
            extra,
            verifier
        );
        operator
            .create_file("server.toml")
            .unwrap()
            .write_all(config.as_bytes())
            .unwrap();
        let config_path = operator_path.join("server.toml");
        let mut child = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
            .args(["serve", "--config"])
            .arg(&config_path)
            .arg("--shutdown-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.starts_with("listening "), "standalone refused startup");
        let mut address: SocketAddr = line
            .trim()
            .strip_prefix("listening ")
            .unwrap()
            .parse()
            .unwrap();
        if address.ip().is_unspecified() {
            address.set_ip("127.0.0.1".parse().unwrap());
        }
        Self {
            child,
            address,
            token,
            directory,
            config_path,
        }
    }
    pub fn stop(mut self) {
        self.child.stdin.take().unwrap().write_all(b"\n").unwrap();
        let output = self.child.wait_with_output_ref();
        assert!(output.0.success(), "standalone exit failure");
        assert_eq!(
            output.1.trim(),
            "stopped: owned listener and workers released"
        );
        assert!(output.2.is_empty(), "unexpected standalone stderr");
        assert!(
            std::net::TcpStream::connect(self.address).is_err(),
            "owned listener leaked"
        );
        let config = oncl_server::config::ServerConfig::read(&self.config_path).unwrap();
        let audit_config = oncl_server::audit::AuditConfig::new(
            config.audit_directory,
            config.audit_segment_bytes,
            config.audit_quota_bytes,
            32,
            2,
        )
        .unwrap();
        let journal = oncl_server::audit::DurableAuditGuard::open(audit_config).unwrap();
        journal.recover().unwrap();
        assert_eq!(journal.health(), oncl_server::audit::AuditHealth::Healthy);
        drop(journal);
        eprintln!("standalone: graceful exit=0, socket refused, own journal reopened/recovered");
    }
}
trait ChildOutput {
    fn wait_with_output_ref(&mut self) -> (std::process::ExitStatus, String, String);
}
impl ChildOutput for Child {
    fn wait_with_output_ref(&mut self) -> (std::process::ExitStatus, String, String) {
        use std::io::Read;
        let status = self.wait().unwrap();
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut stdout) = self.stdout.take() {
            stdout.read_to_string(&mut out).unwrap();
        }
        if let Some(mut stderr) = self.stderr.take() {
            stderr.read_to_string(&mut err).unwrap();
        }
        (status, out, err)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
pub fn toml_path(path: &std::path::Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\\', "/"))
}
pub async fn request(
    address: SocketAddr,
    token: &str,
    path: &str,
    body: &'static [u8],
    headers: &[(&str, &str)],
    tls: Option<ArcTls>,
) -> (u16, Vec<u8>) {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use tokio::net::TcpStream;
    let stream = TcpStream::connect(address).await.unwrap();
    let io: Box<dyn TestStream> = if let Some(config) = tls {
        let connector = tokio_rustls::TlsConnector::from(config);
        Box::new(
            connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    stream,
                )
                .await
                .unwrap(),
        )
    } else {
        Box::new(stream)
    };
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let host = headers
        .iter()
        .find(|(name, _)| *name == "host")
        .map(|(_, value)| value.to_string())
        .unwrap_or_else(|| address.to_string());
    let mut builder = hyper::Request::builder()
        .method(if path == "/health" { "GET" } else { "POST" })
        .uri(path)
        .header("host", host)
        .header("authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        if *name != "host" {
            builder = builder.header(*name, *value);
        }
    }
    let response = sender
        .send_request(builder.body(Full::new(Bytes::from_static(body))).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}
trait TestStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestStream for T {}
pub type ArcTls = std::sync::Arc<rustls::ClientConfig>;
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}
