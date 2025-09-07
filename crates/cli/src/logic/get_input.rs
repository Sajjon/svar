use crate::prelude::*;

use clap::{Args, Parser, Subcommand};

const BINARY_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Debug, Parser)]
#[command(name = BINARY_NAME, about = "Protect a secret using security questions and answers.")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: CommandArgs,
}

#[derive(Debug, Subcommand)]
pub enum CommandArgs {
    Open(OpenArgs),
    Seal(SealArgs),
}

pub enum Command {
    Open(OpenInput),
    Seal(SealInput),
}

#[derive(Debug, Args, PartialEq)]
#[command(name = "open", about = "Decrypts a sealed secret.")]
pub struct OpenArgs {
    /// An optional override of where to read the sealed secret from.
    /// If not provided, the default data local directory will be used.
    #[arg(
        long,
        short = 'i',
        help = "Path to the sealed secret file, if not provided the default data local directory will be used."
    )]
    sealed_path: Option<PathBuf>,
}

impl OpenArgs {
    pub fn non_existent_path_to_sealed_secret(&self) -> Option<PathBuf> {
        let path = self.sealed_path.clone().unwrap_or(
            default_path_for_sealed_secret_without_checking_existence()
                .expect("Failed to get default data local directory"),
        );
        if !path.exists() {
            Some(path.clone())
        } else {
            None
        }
    }

    pub fn to_input(self) -> Result<OpenInput> {
        if let Some(path) = self.sealed_path {
            Ok(OpenInput { sealed_path: path })
        } else {
            let dir = default_path_for_sealed_secret(false)?;
            Ok(OpenInput { sealed_path: dir })
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct OpenInput {
    sealed_path: PathBuf,
}
impl OpenInput {
    pub fn sealed_path(&self) -> &PathBuf {
        &self.sealed_path
    }
}

#[derive(Debug, Args, PartialEq)]
#[command(name = "seal", about = "Encrypts a secret using security questions.")]
pub struct SealArgs {
    /// An optional override of where to read the secret from, if not
    /// provided the user will be prompted to enter a secret.
    #[arg(
        long,
        short = 'i',
        help = "Path to a file containing the secret to protect, if not provided the user will be prompted to enter a secret."
    )]
    secret_path: Option<PathBuf>,

    /// An optional override of where to save the output sealed secret, if not
    /// provided the default data local directory will be used.
    #[arg(
        long,
        short = 'o',
        help = "Path to the output sealed secret file, if not provided the default data local directory will be used."
    )]
    sealed_path: Option<PathBuf>,
}

impl SealArgs {
    pub fn to_input(self) -> Result<SealInput> {
        if let Some(path) = self.sealed_path {
            Ok(SealInput {
                sealed_path: path,
                secret_path: self.secret_path,
            })
        } else {
            let sealed_path = default_path_for_sealed_secret(true)?;
            Ok(SealInput {
                sealed_path,
                secret_path: self.secret_path,
            })
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SealInput {
    secret_path: Option<PathBuf>,
    sealed_path: PathBuf,
}
impl SealInput {
    pub fn secret_path(&self) -> Option<PathBuf> {
        self.secret_path.clone()
    }

    pub fn sealed_path(&self) -> &PathBuf {
        &self.sealed_path
    }
}
