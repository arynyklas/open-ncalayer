//! The NCANode container: the pinned image, started on a free loopback port, waited on
//! until it is `UP`, removed on drop.

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use serde_json::Value;
use ureq::Agent;

/// NCANode 3.5.1 (commit `0adab29a`, the one `fetch-fixtures` pins), pinned by digest.
pub const IMAGE: &str =
    "malikzh/ncanode@sha256:052222f30ac73d9f0060a5c80c572723d25dd84e21073435795a10db254c02b8";
/// Name of the container; a container of that name left by a killed run is removed first.
const CONTAINER: &str = "oncl-ncanode-interop";
/// Docker volume for NCANode's cache (`/app/cache`): the NCA certificates and CRLs it
/// downloads. Kept between runs, so a start after the first one (even a failed one) has
/// fewer downloads left to fail.
const CACHE_VOLUME: &str = "oncl-ncanode-cache";
/// NCANode's HTTP port inside the container.
const NCANODE_PORT: u16 = 14579;
/// How long NCANode gets to report `UP`: at startup it downloads the NCA certificates and
/// CRLs, and its health check waits for them.
const STARTUP: Duration = Duration::from_secs(300);
/// Container starts before giving up (see [`start`]).
const STARTS: u32 = 5;

/// The NCANode container; removed on drop.
pub struct Container;

impl Container {
    /// Removes the container, also one a killed run left.
    fn remove(&self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", CONTAINER])
            .output();
    }

    /// Starts the container on a free loopback port, with the cache volume; returns the
    /// base URL.
    fn run(&self) -> anyhow::Result<String> {
        let publish = format!("127.0.0.1::{NCANODE_PORT}");
        let cache = format!("{CACHE_VOLUME}:/app/cache");
        docker(&[
            "run", "-d", "--name", CONTAINER, "-p", &publish, "-v", &cache, IMAGE,
        ])?;
        let mapped = docker(&["port", CONTAINER, &format!("{NCANODE_PORT}/tcp")])?;
        let address = mapped
            .lines()
            .find(|l| l.starts_with("127.0.0.1:"))
            .with_context(|| format!("unexpected `docker port` output: {mapped}"))?;
        Ok(format!("http://{address}"))
    }

    fn is_running(&self) -> bool {
        docker(&["inspect", "--format", "{{.State.Running}}", CONTAINER])
            .is_ok_and(|state| state == "true")
    }

    /// The last lines of NCANode's log (stdout and stderr).
    fn log_tail(&self) -> String {
        Command::new("docker")
            .args(["logs", "--tail", "30", CONTAINER])
            .output()
            .map(|o| {
                let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&o.stderr));
                text
            })
            .unwrap_or_default()
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Runs `docker <args>` and returns its trimmed stdout.
fn docker(args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .context("running `docker` (install it: `apt-get install -y docker.io` as root)")?;
    ensure!(
        output.status.success(),
        "`docker {}` failed ({}): {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Starts NCANode and waits until it reports `UP`; returns the container and NCANode's
/// base URL. NCANode exits when it cannot download an NCA certificate at startup (a
/// connection to `pki.gov.kz` or `root.gov.kz` failing now and then): it gets [`STARTS`]
/// attempts, each keeping what the previous ones cached.
///
/// # Errors
///
/// If Docker is missing or its daemon is down, or NCANode does not come up.
pub fn start(agent: &Agent) -> anyhow::Result<(Container, String)> {
    docker(&["version", "--format", "{{.Server.Version}}"])
        .context("the Docker daemon is not available (as root: `service docker start`)")?;
    let container = Container;
    for attempt in 1..=STARTS {
        container.remove();
        let base = container.run()?;
        println!("NCANode {IMAGE} at {base}");
        if wait_up(&container, agent, &base)? {
            return Ok((container, base));
        }
        eprintln!(
            "NCANode exited during startup (attempt {attempt} of {STARTS}); its log:\n{}",
            container.log_tail()
        );
    }
    bail!("NCANode did not start in {STARTS} attempts")
}

/// `true` once NCANode reports `UP`, `false` if its container stopped first.
fn wait_up(container: &Container, agent: &Agent, base: &str) -> anyhow::Result<bool> {
    let deadline = Instant::now() + STARTUP;
    loop {
        let last = match agent.get(format!("{base}/actuator/health")).call() {
            Ok(mut response) => {
                let text = response.body_mut().read_to_string().unwrap_or_default();
                let health: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                if health["status"] == "UP" {
                    return Ok(true);
                }
                format!("{}: {text}", response.status())
            }
            Err(e) => e.to_string(),
        };
        if !container.is_running() {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            bail!(
                "NCANode is not UP after {STARTUP:?} ({last}); its log:\n{}",
                container.log_tail()
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}
