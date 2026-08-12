//! Argument definitions. Nothing here reaches into `elasticctl-api`.

use clap::{Parser, Subcommand};
use elasticctl_core::{Error, ErrorKind};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Table,
    Json,
    Yaml,
    Csv,
    Jsonl,
}

impl FromStr for Format {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "table" => Ok(Format::Table),
            "json" => Ok(Format::Json),
            "yaml" | "yml" => Ok(Format::Yaml),
            "csv" => Ok(Format::Csv),
            "jsonl" | "ndjson" => Ok(Format::Jsonl),
            other => Err(Error::new(
                ErrorKind::Error,
                format!("unknown format '{other}'; expected table, json, yaml, csv, or jsonl"),
            )),
        }
    }
}

#[derive(Debug, Clone, Default, Parser)]
pub struct GlobalArgs {
    /// Use a named profile
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Use a specific configuration file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Kibana space to operate in
    #[arg(long, global = true)]
    pub space: Option<String>,

    /// Force JSON output
    #[arg(long, global = true)]
    pub json: bool,

    /// Output format: table, json, yaml, csv, jsonl
    #[arg(long, global = true)]
    pub format: Option<Format>,

    /// Comma-separated fields to include
    #[arg(long, global = true)]
    pub fields: Option<String>,

    /// Write output to a file instead of stdout
    #[arg(long, global = true)]
    pub out: Option<PathBuf>,

    /// Apply a mutation after reviewing its preview
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Request timeout in seconds
    #[arg(long, global = true)]
    pub timeout: Option<u64>,

    /// Log HTTP requests and responses, with secrets redacted
    #[arg(long, global = true)]
    pub debug: bool,
}

impl GlobalArgs {
    /// `--json` is a shorthand that wins over `--format`, so a script can force
    /// JSON without knowing what else was configured.
    pub fn effective_format(&self) -> Format {
        if self.json {
            Format::Json
        } else {
            self.format.unwrap_or_default()
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "elasticctl",
    version,
    about = "Operate Elastic Security as code"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the CLI version and, when configured, the target stack
    Info,
}
