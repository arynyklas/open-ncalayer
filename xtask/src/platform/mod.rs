//! `cargo xtask platform-proof`: the acceptance gate of the 10 GiB / 1 GiB profile
//! (docs/design/platform.md section 5, docs/dev/platform-acceptance.md).
//!
//! The command generates meaningful XML, WSSE and PDF documents plus a framed byte stream
//! with an independent reference generator ([`generate`]), then runs the real SDK probe,
//! the real `oncl` CLI and the real `oncl-server` binary as SEPARATE processes on them
//! ([`large`]), taking the operating system's peak working set and peak private bytes of
//! every one of those processes ([`measure`]). PASS needs substantive successful cases on
//! every selected surface, every peak at or below `--max-rss-bytes` and every negative case
//! refused for the right reason. A stand that cannot do something is BLOCKED, never PASS.

pub mod generate;
pub mod large;
pub mod measure;
pub mod token_host;

use clap::{Args, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Surface {
    Sdk,
    Cli,
    Http,
    All,
}

impl Surface {
    pub fn includes(self, other: Surface) -> bool {
        self == Surface::All || self == other
    }
}

#[derive(Args, Clone, Debug)]
pub struct ProofArgs {
    /// Size of each generated source document, in bytes.
    #[arg(long, default_value_t = 10_737_418_240)]
    pub document_bytes: u64,
    /// The criterion: the stricter of peak working set and peak private bytes of every
    /// measured process.
    #[arg(long, default_value_t = 1_073_741_824)]
    pub max_rss_bytes: u64,
    /// The scratch quota the stand must offer (checked against the free space of the drive).
    #[arg(long, default_value_t = 68_719_476_736)]
    pub scratch_bytes: u64,
    /// Output directory: report, logs, generated data and per-case work. Must be on a fixed
    /// local drive with room for the data (not drive C: of a nearly full machine).
    #[arg(long, default_value = "target/platform-proof")]
    pub out: PathBuf,
    /// Where the operations' temporary stores live [default: `<out>/scratch`].
    #[arg(long)]
    pub scratch_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Surface::All)]
    pub surface: Surface,
    /// Run only the cases whose id contains one of these substrings.
    #[arg(long)]
    pub only: Vec<String>,
    /// Do not run `cargo build --release` for the probe, `oncl` and `oncl-server`.
    #[arg(long)]
    pub skip_build: bool,
    /// Reuse generated documents of a previous run in `<out>/data` when their manifest matches.
    #[arg(long)]
    pub reuse_data: bool,
    /// Generate the data and run the reference-generator validation only.
    #[arg(long)]
    pub generate_only: bool,
    /// Continue a previous run in `--out`: cases that already PASSED in its `report.json`
    /// are kept and not run again.
    #[arg(long)]
    pub resume: bool,
    /// Cases (surface x scenario) to run at the same time. Every measured process is its own
    /// process with its own OS counters, so the peaks do not depend on this; wall time does.
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
    /// Python with lxml, cryptography, asn1crypto and pyHanko [default: ONCL_PYHANKO_PYTHON].
    #[arg(long)]
    pub python: Option<PathBuf>,
    /// Keep the generated documents after the run.
    #[arg(long)]
    pub keep_data: bool,
}

pub fn run(args: ProofArgs) -> anyhow::Result<()> {
    large::run(args)
}
