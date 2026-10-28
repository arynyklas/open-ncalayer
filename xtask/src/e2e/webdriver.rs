//! A minimal W3C WebDriver client over `ureq`: a driver process (chromedriver, geckodriver),
//! a session, navigation, `execute/async`, Firefox's `moz/addon/install` and `uninstall`.

use std::fs::File;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde_json::{Value, json};
use ureq::Agent;

use super::processes;

/// How long the driver gets to answer `/status`.
const DRIVER_START: Duration = Duration::from_secs(30);
/// Longest single WebDriver command (session start, a scenario step).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest WebDriver response read (a signed 1.5 MiB document comes back as ~2 MiB).
const RESPONSE_LIMIT: u64 = 256 << 20;

/// A running driver in its own process group, killed with the group (the browser and its
/// helpers) on drop.
pub struct Driver {
    child: Child,
    base: String,
    agent: Agent,
}

impl Driver {
    /// Starts `program --port=<free port> <args>` with `env` set (and `unset` removed) on top
    /// of this process's environment, its output written to `log`, and waits until it is
    /// ready.
    pub fn start(
        program: &Path,
        args: &[String],
        env: &[(String, String)],
        unset: &[&str],
        log: &Path,
    ) -> anyhow::Result<Driver> {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        let log_file = File::create(log).with_context(|| format!("creating {}", log.display()))?;
        let mut command = Command::new(program);
        command
            .arg(format!("--port={port}"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file);
        for name in unset {
            command.env_remove(name);
        }
        command.envs(env.iter().map(|(k, v)| (k, v)));
        // Its own group, so that the browser it starts can be killed with it. Ctrl+C then
        // reaches the xtask only, which kills the group (`processes::cleanup_on_signals`).
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let child = command
            .spawn()
            .with_context(|| format!("starting {}", program.display()))?;
        processes::track_group(child.id());
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(COMMAND_TIMEOUT))
            .build()
            .into();
        let mut driver = Driver {
            child,
            base: format!("http://127.0.0.1:{port}"),
            agent,
        };
        let deadline = Instant::now() + DRIVER_START;
        loop {
            if let Some(status) = driver.child.try_wait()? {
                bail!(
                    "{} exited with {status}; see {}",
                    program.display(),
                    log.display()
                );
            }
            if let Ok(status) = driver.call("GET", "/status", None)
                && status["ready"] == true
            {
                return Ok(driver);
            }
            if Instant::now() >= deadline {
                bail!(
                    "{} was not ready in {DRIVER_START:?}; see {}",
                    program.display(),
                    log.display()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A new session with `capabilities` (the `alwaysMatch` object).
    pub fn session(&self, capabilities: Value) -> anyhow::Result<Session<'_>> {
        let value = self
            .call(
                "POST",
                "/session",
                Some(json!({"capabilities": {"alwaysMatch": capabilities}})),
            )
            .context("starting a WebDriver session")?;
        let id = value["sessionId"]
            .as_str()
            .context("the new session has no sessionId")?
            .to_owned();
        Ok(Session { driver: self, id })
    }

    /// One WebDriver command; its `value`, or the WebDriver error as an error.
    fn call(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let url = format!("{}{path}", self.base);
        let mut response = match (method, body) {
            ("GET", _) => self.agent.get(&url).call(),
            ("DELETE", _) => self.agent.delete(&url).call(),
            (_, body) => self
                .agent
                .post(&url)
                .header("content-type", "application/json")
                .send(body.unwrap_or_else(|| json!({})).to_string()),
        }
        .with_context(|| format!("{method} {path}"))?;
        let status = response.status();
        let text = response
            .body_mut()
            .with_config()
            .limit(RESPONSE_LIMIT)
            .read_to_string()
            .with_context(|| format!("reading the response to {method} {path}"))?;
        let mut parsed: Value = serde_json::from_str(&text)
            .with_context(|| format!("{method} {path}: not JSON: {text}"))?;
        let value = parsed["value"].take();
        if !status.is_success() {
            bail!(
                "{method} {path}: {status} {}: {}",
                value["error"].as_str().unwrap_or("?"),
                value["message"].as_str().unwrap_or(&text)
            );
        }
        Ok(value)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // The group is the driver's pid: the browser it started is in it too.
        processes::kill_group(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
        processes::untrack_group(self.child.id());
    }
}

/// A WebDriver session, deleted on drop (which also ends the browser).
pub struct Session<'a> {
    driver: &'a Driver,
    id: String,
}

impl Session<'_> {
    fn call(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        self.driver
            .call(method, &format!("/session/{}{path}", self.id), body)
    }

    /// Sets the script timeout of `execute/async`.
    pub fn set_script_timeout(&self, timeout: Duration) -> anyhow::Result<()> {
        let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.call("POST", "/timeouts", Some(json!({"script": ms})))?;
        Ok(())
    }

    /// Navigates to `url` and waits for the load.
    pub fn navigate(&self, url: &str) -> anyhow::Result<()> {
        self.call("POST", "/url", Some(json!({"url": url})))?;
        Ok(())
    }

    /// Runs `script` as an async script with `args`; what it passed to its callback.
    pub fn execute_async(&self, script: &str, args: Value) -> anyhow::Result<Value> {
        self.call(
            "POST",
            "/execute/async",
            Some(json!({"script": script, "args": args})),
        )
    }

    /// Firefox: installs the add-on at `path` (an xpi or an unpacked directory), temporarily.
    pub fn install_temporary_addon(&self, path: &Path) -> anyhow::Result<String> {
        let path = path
            .to_str()
            .context("the add-on path is not UTF-8")?
            .to_owned();
        let id = self.call(
            "POST",
            "/moz/addon/install",
            Some(json!({"path": path, "temporary": true})),
        )?;
        Ok(id.as_str().unwrap_or_default().to_owned())
    }

    /// Firefox: removes the add-on `id`.
    pub fn uninstall_addon(&self, id: &str) -> anyhow::Result<()> {
        self.call("POST", "/moz/addon/uninstall", Some(json!({"id": id})))?;
        Ok(())
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        let _ = self.call("DELETE", "", None);
    }
}
