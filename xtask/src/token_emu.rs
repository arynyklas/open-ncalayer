//! `cargo xtask token-emu`: serves the first card of an emulator configuration to vpcd, the
//! virtual reader of vsmartcard for pcscd, so the real PC/SC backend can be tested against
//! an emulated token. Runs until vpcd closes the connection or the process is stopped.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use oncl_token::emulator::{VPCD_PORT, card, read_config, serve_vpcd};

/// How long vpcd may take to listen after pcscd starts.
const CONNECT_TRIES: u32 = 30;

/// Serves the first card of `config` (key paths relative to `root`) to the vpcd at `vpcd`
/// (default `127.0.0.1:35963`), reconnecting whenever vpcd drops the connection.
///
/// # Errors
///
/// A configuration without a card, an address that does not resolve, or a vpcd that never
/// listens.
pub fn token_emu(root: &Path, config: &Path, vpcd: Option<&str>) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(config).with_context(|| format!("reading {}", config.display()))?;
    let reader = read_config(&text, root)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("{}", config.display()))?
        .into_iter()
        .find(|r| r.card.is_some())
        .with_context(|| format!("{}: no reader with a card", config.display()))?;
    let spec = reader.card.expect("found with a card");
    let addr: SocketAddr = vpcd
        .unwrap_or(&format!("127.0.0.1:{VPCD_PORT}"))
        .to_socket_addrs()
        .context("vpcd address")?
        .next()
        .context("vpcd address resolves to nothing")?;
    println!(
        "serving {} ({}) to vpcd at {addr}",
        reader.name,
        spec.kind.storage_name()
    );
    let mut failures = 0;
    loop {
        match serve_vpcd(card(spec.clone()), addr) {
            Ok(()) => {
                failures = 0;
                eprintln!("vpcd closed the connection; reconnecting");
            }
            Err(e) => {
                failures += 1;
                if failures == CONNECT_TRIES {
                    bail!("vpcd at {addr}: {e}");
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
