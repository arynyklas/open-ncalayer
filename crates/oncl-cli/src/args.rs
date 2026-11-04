use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "oncl",
    version,
    about = "Standalone local SDK operations; secrets are never command-line values"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub offline: bool,
    #[arg(long, global = true)]
    pub report: Option<PathBuf>,
    #[arg(long, global = true)]
    pub root: Vec<PathBuf>,
    #[arg(long, global = true)]
    pub intermediate: Vec<PathBuf>,
    #[arg(long, global = true)]
    pub pki_endpoint: Vec<String>,
    /// Aggregate encoded host certificate bytes, including duplicate roots.
    #[arg(long, global = true, default_value_t = 16_777_216)]
    pub configuration_bytes: u64,
    #[arg(long, global = true)]
    pub as_of: Option<i64>,
    #[arg(long, global = true)]
    pub output_limit: Option<u64>,
    #[arg(long, global = true, default_value_t = 300)]
    pub timeout_seconds: u64,
    #[arg(long, global = true)]
    pub temporary_directory: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    Hash {
        #[arg(long, value_enum)]
        algorithm: Algorithm,
        #[arg(long)]
        input: String,
    },
    Verify {
        #[arg(long, value_enum)]
        profile: VerifyProfile,
        #[arg(long)]
        input: String,
        #[arg(long)]
        detached: Option<String>,
    },
    Extract {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
    },
    Sign(SignArgs),
    Inspect(crate::families::InspectArgs),
    Extend(crate::families::ExtendArgs),
    Timestamp {
        #[command(subcommand)]
        command: crate::families::TimestampCommand,
    },
    Jws {
        #[command(subcommand)]
        command: crate::jose_args::JwsCommand,
    },
    Jwt {
        #[command(subcommand)]
        command: crate::jose_args::JwtCommand,
    },
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Algorithm {
    Sha256,
    Gost2004,
    Gost2015_512,
}
impl Algorithm {
    pub fn sdk(self) -> oncl_pki::key::HashAlg {
        match self {
            Self::Sha256 => oncl_pki::key::HashAlg::Sha256,
            Self::Gost2004 => oncl_pki::key::HashAlg::Gost34311,
            Self::Gost2015_512 => oncl_pki::key::HashAlg::Streebog512,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
pub enum VerifyProfile {
    Cms,
    Xml,
    XmlKalkan,
    Wsse,
    Pdf,
    CadesB,
    CadesT,
    CadesLt,
    CadesLta,
    XadesB,
    XadesT,
    XadesLt,
    XadesLta,
    PadesB,
    PadesT,
    PadesLt,
    PadesLta,
}
impl VerifyProfile {
    pub fn sdk(self) -> oncl_core::VerifyRequest {
        use oncl_core::VerifyRequest as R;
        use oncl_pki::evidence::AdesLevel as L;
        match self {
            Self::Cms => R::cms(),
            Self::Xml => R::xml(),
            Self::XmlKalkan => R::xml_kalkan(),
            Self::Wsse => R::wsse(oncl_xml::wsse::WsseVerifyProfile::default()),
            Self::Pdf => R::pdf(),
            Self::CadesB => R::cades(L::B, evidence_limits()),
            Self::CadesT => R::cades(L::T, evidence_limits()),
            Self::CadesLt => R::cades(L::Lt, evidence_limits()),
            Self::CadesLta => R::cades(L::Lta, evidence_limits()),
            Self::XadesB => R::xades(L::B),
            Self::XadesT => R::xades(L::T),
            Self::XadesLt => R::xades(L::Lt),
            Self::XadesLta => R::xades(L::Lta),
            Self::PadesB => R::pades(L::B, evidence_limits()),
            Self::PadesT => R::pades(L::T, evidence_limits()),
            Self::PadesLt => R::pades(L::Lt, evidence_limits()),
            Self::PadesLta => R::pades(L::Lta, evidence_limits()),
        }
    }
}
#[derive(Args)]
pub struct PrivateKeyArgs {
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long)]
    pub alias: Option<String>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "secret_file")]
    pub secret_interactive: bool,
    /// Authorize only this operation's exact source, key, profile and destination.
    #[arg(long)]
    pub authorize: bool,
}
#[derive(Args)]
pub struct SignArgs {
    #[arg(long, value_enum)]
    pub profile: SignProfile,
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub output: String,
    #[command(flatten)]
    pub key_options: PrivateKeyArgs,
    #[arg(long)]
    pub add: bool,
    #[arg(long)]
    pub detached: bool,
    #[arg(long)]
    pub detached_input: Option<String>,
    #[arg(long)]
    pub target_id: Option<String>,
    #[arg(long)]
    pub parent_id: Option<String>,
    #[arg(long)]
    pub signature_id: Option<String>,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum SignProfile {
    Cms,
    Raw,
    DigestSha256,
    DigestGost2004,
    DigestGost2015_512,
    Xml,
    Wsse,
    XadesB,
    XadesT,
    XadesLt,
    XadesLta,
    Pdf,
    PadesB,
    PadesT,
    PadesLt,
    PadesLta,
    CadesB,
    CadesT,
    CadesLt,
    CadesLta,
}
impl Cli {
    pub fn private_key(&self) -> Option<&PrivateKeyArgs> {
        match &self.command {
            Command::Sign(args) => Some(&args.key_options),
            Command::Jws { command } => command.key(),
            Command::Jwt { command } => command.key(),
            _ => None,
        }
    }
    pub fn preflight(&self) -> Result<(), &'static str> {
        if self.timeout_seconds == 0 {
            return Err("InvalidTimeout");
        }
        if self.root.len().saturating_add(self.intermediate.len()) > 1024
            || self.pki_endpoint.len() > 64
            || self.configuration_bytes > 16_777_216
        {
            return Err("ConfigurationLimit");
        }
        if self
            .report
            .as_ref()
            .is_some_and(|path| std::fs::symlink_metadata(path).is_ok())
        {
            return Err("DestinationExists");
        }
        let output = match &self.command {
            Command::Sign(args) => Some(args.output.as_str()),
            Command::Extract { output, .. } => Some(output.as_str()),
            Command::Extend(args) => Some(args.output.as_str()),
            Command::Timestamp {
                command: crate::families::TimestampCommand::Acquire { output, .. },
            } => Some(output.as_str()),
            Command::Jws { command } => command.output(),
            Command::Jwt { command } => command.output(),
            _ => None,
        };
        if let Some(output) = output {
            if output == "-" && self.json && self.report.is_none() {
                return Err("OutputConflict");
            }
            if output != "-" && std::fs::symlink_metadata(output).is_ok() {
                return Err("DestinationExists");
            }
            if self
                .report
                .as_ref()
                .is_some_and(|report| report == std::path::Path::new(output))
            {
                return Err("OutputConflict");
            }
        }
        if let Command::Sign(args) = &self.command {
            if !args.key_options.authorize {
                return Err("AuthorityRequired");
            }
            let cms = matches!(
                args.profile,
                SignProfile::Cms
                    | SignProfile::CadesB
                    | SignProfile::CadesT
                    | SignProfile::CadesLt
                    | SignProfile::CadesLta
            );
            let xml = matches!(
                args.profile,
                SignProfile::Xml
                    | SignProfile::Wsse
                    | SignProfile::XadesB
                    | SignProfile::XadesT
                    | SignProfile::XadesLt
                    | SignProfile::XadesLta
            );
            if (cms && args.add && args.detached)
                || (args.add && !cms && !xml)
                || (args.detached && !cms)
                || (args.detached_input.is_some() && (!cms || !args.add))
                || (!xml
                    && (args.target_id.is_some()
                        || args.parent_id.is_some()
                        || args.signature_id.is_some()))
            {
                return Err("InvalidCombination");
            }
            if args.key_options.secret_interactive
                && (args.input == "-" || args.detached_input.as_deref() == Some("-"))
            {
                return Err("SecretRequiresSeparateInput");
            }
            if args.input == "-" && args.detached_input.as_deref() == Some("-") {
                return Err("StdinConflict");
            }
        }
        match &self.command {
            Command::Verify {
                input, detached, ..
            } if input == "-" && detached.as_deref() == Some("-") => Err("StdinConflict"),
            Command::Extract { output, .. }
                if output == "-" && self.json && self.report.is_none() =>
            {
                Err("OutputConflict")
            }
            Command::Extend(args) if args.input == "-" && args.detached.as_deref() == Some("-") => {
                Err("StdinConflict")
            }
            Command::Timestamp {
                command: crate::families::TimestampCommand::Verify { input, data, .. },
            } if input == "-" && data.as_deref() == Some("-") => Err("StdinConflict"),
            Command::Inspect(args)
                if matches!(args.profile, crate::families::InspectProfile::Container)
                    && args.alias.is_empty() =>
            {
                Err("AliasRequired")
            }
            Command::Jws { command } => command.preflight(),
            Command::Jwt { command } => command.preflight(),
            _ => Ok(()),
        }
    }
}
pub fn evidence_limits() -> oncl_pki::evidence::EvidenceLimits {
    oncl_pki::evidence::EvidenceLimits {
        max_items: 256,
        max_bytes: 16 * 1024 * 1024,
        max_item_bytes: 1024 * 1024,
        max_chain_len: 16,
        max_proofs: 16,
        max_coverage_parts: 65536,
        max_coverage_bytes: 64 * 1024 * 1024,
    }
}
