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
    /// Operator-resolved address for a DNS PKI origin: `http://host:port=IP:port`.
    #[arg(long, global = true)]
    pub pki_pin: Vec<String>,
    /// TSA endpoint (POST) used when CAdES T/LT/LTA evidence is acquired.
    #[arg(long, global = true)]
    pub tsa_url: Option<String>,
    /// Public DER certificate (issuers, TSA certificate; the root may be included) embedded as
    /// CAdES/PAdES LT/LTA validation material or used for `extend`. Repeatable, at most 64.
    #[arg(long, global = true)]
    pub evidence_certificate: Vec<PathBuf>,
    /// Complete DER OCSPResponse for a certificate of the path (repeatable, at most 64).
    #[arg(long, global = true)]
    pub evidence_ocsp: Vec<PathBuf>,
    /// DER CRL for a certificate of the path (repeatable, at most 64).
    #[arg(long, global = true)]
    pub evidence_crl: Vec<PathBuf>,
    /// Dotted TSA policy OID requested and required of every token (needed for XAdES T/LT/LTA).
    #[arg(long, global = true)]
    pub tsa_policy: Option<String>,
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
        #[command(flatten)]
        wsse: crate::wsse::WsseOptions,
    },
    Extract {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
    },
    Sign(Box<SignArgs>),
    Inspect(crate::families::InspectArgs),
    Extend(crate::families::ExtendArgs),
    Timestamp {
        #[command(subcommand)]
        command: crate::families::TimestampCommand,
    },
    Batch {
        #[command(subcommand)]
        command: crate::batch::BatchCommand,
    },
    Plugin {
        #[command(subcommand)]
        command: crate::plugin::PluginCommand,
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
    pub fn sdk(self, wsse: &crate::wsse::WsseOptions) -> oncl_core::VerifyRequest {
        use oncl_core::VerifyRequest as R;
        use oncl_pki::evidence::AdesLevel as L;
        match self {
            Self::Cms => R::cms(),
            Self::Xml => R::xml(),
            Self::XmlKalkan => R::xml_kalkan(),
            Self::Wsse => R::wsse(wsse.verify_profile()),
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
    /// PKCS#12/JKS container file. Exactly one of --key or --token-reader.
    #[arg(
        long,
        conflicts_with_all = ["token_reader", "key_name"],
        required_unless_present_any = ["token_reader", "key_name"]
    )]
    pub key: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["token_reader", "key_name"])]
    pub alias: Option<String>,
    /// Select an operator-configured key by name (see `--key-config`); the
    /// container path or token reader never appears on the command line.
    #[arg(long, requires = "key_config", conflicts_with = "token_reader")]
    pub key_name: Option<String>,
    /// Operator JSON file of named key sources (no secrets).
    #[arg(long, requires = "key_name")]
    pub key_config: Option<PathBuf>,
    /// Exact PC/SC reader name of a real token (experimental; no emulator in this binary).
    #[arg(long, requires_all = ["token_kind", "token_alias"])]
    pub token_reader: Option<String>,
    #[arg(long, value_enum)]
    pub token_kind: Option<TokenFamily>,
    #[arg(long)]
    pub token_alias: Option<String>,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "secret_file")]
    pub secret_interactive: bool,
    /// Authorize only this operation's exact source, key, profile and destination.
    #[arg(long)]
    pub authorize: bool,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum TokenFamily {
    Kaztoken,
    KzIdCard,
    EToken72k,
    EToken5110,
    Jacarta,
    Akey,
}
pub fn token_selector(
    reader: &str,
    family: TokenFamily,
    alias: &str,
) -> Result<oncl_core::keys::KeySelector, oncl_core::OperationError> {
    use oncl_token::{TokenKind, execution::TokenDeviceId};
    let kind = match family {
        TokenFamily::Kaztoken => TokenKind::Kaztoken,
        TokenFamily::KzIdCard => TokenKind::KzIdCard,
        TokenFamily::EToken72k => TokenKind::EToken72K,
        TokenFamily::EToken5110 => TokenKind::EToken5110,
        TokenFamily::Jacarta => TokenKind::JaCarta,
        TokenFamily::Akey => TokenKind::AKey,
    };
    let device = TokenDeviceId::new(reader.to_owned())
        .map_err(|_| oncl_core::OperationError::InvalidKeySource)?;
    Ok(oncl_core::keys::KeySelector::token(
        device,
        kind,
        alias.to_owned(),
    ))
}
impl PrivateKeyArgs {
    pub fn uses_token(&self) -> bool {
        self.token_reader.is_some()
    }
    pub fn selector(&self) -> Result<oncl_core::keys::KeySelector, oncl_core::OperationError> {
        if let (Some(reader), Some(kind), Some(alias)) =
            (&self.token_reader, self.token_kind, &self.token_alias)
        {
            return token_selector(reader, kind, alias);
        }
        let key = self
            .key
            .as_ref()
            .ok_or(oncl_core::OperationError::InvalidKeySource)?;
        oncl_core::keys::KeySelector::file(key, self.alias.clone())
    }
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
    #[command(flatten)]
    pub wsse: crate::wsse::WsseOptions,
    #[command(flatten)]
    pub legacy: crate::legacy::LegacyOptions,
}
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
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
        if self.pki_pin.iter().any(|pin| {
            pin.split_once('=')
                .is_none_or(|(_, address)| address.parse::<std::net::SocketAddr>().is_err())
        }) {
            return Err("InvalidCombination");
        }
        if self
            .tsa_policy
            .as_deref()
            .is_some_and(|policy| policy.parse::<der::asn1::ObjectIdentifier>().is_err())
        {
            return Err("InvalidCombination");
        }
        if self.evidence_certificate.len() > crate::evidence::MAX_ITEMS
            || self.evidence_ocsp.len() > crate::evidence::MAX_ITEMS
            || self.evidence_crl.len() > crate::evidence::MAX_ITEMS
        {
            return Err("ConfigurationLimit");
        }
        if crate::evidence::any(self) {
            let uses = match &self.command {
                Command::Extend(_) => true,
                Command::Sign(args) => {
                    matches!(
                        args.profile,
                        SignProfile::CadesB
                            | SignProfile::CadesT
                            | SignProfile::CadesLt
                            | SignProfile::CadesLta
                            | SignProfile::PadesB
                            | SignProfile::PadesT
                            | SignProfile::PadesLt
                            | SignProfile::PadesLta
                    ) && !args.legacy.legacy
                }
                _ => false,
            };
            if !uses {
                return Err("InvalidCombination");
            }
        }
        // LT/LTA evidence cannot be built from nothing: the CLI refuses before any I/O
        // (sufficiency is still checked by the SDK and reported truthfully if it fails
        // after key use).
        if let Command::Sign(args) = &self.command
            && !args.legacy.legacy
            && matches!(
                args.profile,
                SignProfile::CadesLt
                    | SignProfile::CadesLta
                    | SignProfile::PadesLt
                    | SignProfile::PadesLta
            )
            && (self.evidence_certificate.is_empty()
                || (self.evidence_ocsp.is_empty() && self.evidence_crl.is_empty()))
        {
            return Err("EvidenceMaterialRequired");
        }
        if self.root.len().saturating_add(self.intermediate.len()) > 1024
            || self.pki_endpoint.len() > 64
            || self.pki_pin.len() > 64
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
            Command::Plugin { command } => Some(command.args().output.as_str()),
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
            args.legacy.preflight(args, self.tsa_url.is_some())?;
            if args.wsse.any() && !matches!(args.profile, SignProfile::Wsse) {
                return Err("InvalidCombination");
            }
            if matches!(args.profile, SignProfile::Wsse)
                && (args.target_id.is_some()
                    || args.parent_id.is_some()
                    || args.signature_id.is_some())
            {
                return Err("InvalidCombination");
            }
            args.wsse.preflight(true)?;
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
            Command::Verify { profile, wsse, .. }
                if wsse.any() && !matches!(profile, VerifyProfile::Wsse) =>
            {
                Err("InvalidCombination")
            }
            Command::Verify { wsse, .. } => wsse.preflight(false),
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
            Command::Inspect(args) => {
                use crate::families::InspectProfile as P;
                let keyed = args.key_name.is_some();
                match args.profile {
                    P::NamedKey if !keyed || args.input.is_some() => Err("InvalidCombination"),
                    P::NamedKey => Ok(()),
                    _ if keyed || args.input.is_none() => Err("InvalidCombination"),
                    P::Container if args.alias.is_empty() => Err("AliasRequired"),
                    _ => Ok(()),
                }
            }
            Command::Plugin { command } => command.preflight(),
            Command::Batch { command } => command.preflight(),
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
