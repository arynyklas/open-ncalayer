use crate::args::PrivateKeyArgs;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;
#[derive(Clone, Copy, ValueEnum)]
pub enum Serialization {
    Compact,
    Flattened,
    General,
}
impl Serialization {
    pub fn profile(self, detached: bool) -> oncl_core::jose::JoseProfile {
        use oncl_core::jose::JwsSerialization as S;
        oncl_core::jose::JoseProfile::new(
            match self {
                Self::Compact => S::Compact,
                Self::Flattened => S::Flattened,
                Self::General => S::General,
            },
            detached,
        )
    }
}
#[derive(Args)]
pub struct JwsSign {
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub output: String,
    #[arg(long, value_enum)]
    pub serialization: Serialization,
    #[arg(long)]
    pub detached: bool,
    #[arg(long)]
    pub add: bool,
    #[arg(long)]
    pub detached_input: Option<String>,
    #[arg(long)]
    pub certificate: Option<PathBuf>,
    #[command(flatten)]
    pub key: PrivateKeyArgs,
}
#[derive(Args)]
pub struct JwsVerify {
    #[arg(long)]
    pub input: String,
    #[arg(long, value_enum)]
    pub serialization: Serialization,
    #[arg(long)]
    pub detached_input: Option<String>,
    #[arg(long)]
    pub certificate: Option<PathBuf>,
}
#[derive(Subcommand)]
pub enum JwsCommand {
    Sign(Box<JwsSign>),
    Verify(JwsVerify),
}
#[derive(Args)]
pub struct JwtEncode {
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub output: String,
    #[command(flatten)]
    pub key: PrivateKeyArgs,
}
#[derive(Args)]
pub struct JwtVerify {
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub certificate: Option<PathBuf>,
    #[arg(long)]
    pub issuer: Option<String>,
    #[arg(long)]
    pub audience: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub leeway_seconds: u64,
}
#[derive(Subcommand)]
pub enum JwtCommand {
    Encode(JwtEncode),
    Verify(JwtVerify),
    Decode {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
    },
}
impl JwsCommand {
    pub fn action(&self) -> oncl_core::Action {
        match self {
            Self::Sign(_) => oncl_core::Action::Sign,
            Self::Verify(_) => oncl_core::Action::Verify,
        }
    }
    pub fn output(&self) -> Option<&str> {
        match self {
            Self::Sign(args) => Some(&args.output),
            Self::Verify(_) => None,
        }
    }
    pub fn key(&self) -> Option<&PrivateKeyArgs> {
        match self {
            Self::Sign(args) => Some(&args.key),
            Self::Verify(_) => None,
        }
    }
    pub fn preflight(&self) -> Result<(), &'static str> {
        let (input, detached) = match self {
            Self::Sign(args) => (&args.input, args.detached_input.as_deref()),
            Self::Verify(args) => (&args.input, args.detached_input.as_deref()),
        };
        if input == "-" && detached == Some("-") {
            return Err("StdinConflict");
        }
        if let Self::Sign(args) = self {
            if !args.key.authorize {
                return Err("AuthorityRequired");
            }
            if !args.add && (args.detached_input.is_some() || args.certificate.is_some()) {
                return Err("InvalidCombination");
            }
            if args.add && args.detached && args.detached_input.is_none() {
                return Err("DetachedInputRequired");
            }
            if args.key.secret_interactive && (input == "-" || detached == Some("-")) {
                return Err("SecretRequiresSeparateInput");
            }
        }
        Ok(())
    }
}
impl JwtCommand {
    pub fn action(&self) -> oncl_core::Action {
        match self {
            Self::Encode(_) => oncl_core::Action::Sign,
            Self::Verify(_) => oncl_core::Action::Verify,
            Self::Decode { .. } => oncl_core::Action::Extract,
        }
    }
    pub fn output(&self) -> Option<&str> {
        match self {
            Self::Encode(args) => Some(&args.output),
            Self::Decode { output, .. } => Some(output),
            Self::Verify(_) => None,
        }
    }
    pub fn key(&self) -> Option<&PrivateKeyArgs> {
        match self {
            Self::Encode(args) => Some(&args.key),
            _ => None,
        }
    }
    pub fn preflight(&self) -> Result<(), &'static str> {
        if let Self::Encode(args) = self {
            if !args.key.authorize {
                return Err("AuthorityRequired");
            }
            if args.key.secret_interactive && args.input == "-" {
                return Err("SecretRequiresSeparateInput");
            }
        }
        Ok(())
    }
}
