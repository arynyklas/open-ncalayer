use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(Args)]
pub struct InspectArgs {
    #[arg(long, value_enum)]
    pub profile: InspectProfile,
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub alias: Vec<String>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "secret_file")]
    pub secret_interactive: bool,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum InspectProfile {
    Certificate,
    Container,
    Cms,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum ExtendProfile {
    Cms,
    Xml,
    Pdf,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Level {
    B,
    T,
    Lt,
    Lta,
}
impl Level {
    pub fn sdk(self) -> oncl_pki::evidence::AdesLevel {
        use oncl_pki::evidence::AdesLevel as L;
        match self {
            Self::B => L::B,
            Self::T => L::T,
            Self::Lt => L::Lt,
            Self::Lta => L::Lta,
        }
    }
}
#[derive(Args)]
pub struct ExtendArgs {
    #[arg(long, value_enum)]
    pub profile: ExtendProfile,
    #[arg(long, value_enum)]
    pub level: Level,
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub output: String,
    #[arg(long)]
    pub detached: Option<String>,
}
#[derive(Subcommand)]
pub enum TimestampCommand {
    Acquire {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        tsa: String,
        #[arg(long, value_enum, default_value = "sha256")]
        algorithm: crate::args::Algorithm,
    },
    Verify {
        #[arg(long)]
        input: String,
        #[arg(long)]
        data: Option<String>,
        #[arg(long, value_enum)]
        algorithm: Option<crate::args::Algorithm>,
        #[arg(long)]
        policy_oid: Option<String>,
        #[arg(long)]
        maximum_age_seconds: Option<u64>,
    },
}
