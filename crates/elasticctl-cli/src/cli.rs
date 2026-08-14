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
    /// Manage connection profiles
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Check connectivity, authentication, key scope, and rule access
    Doctor,
    /// Show stack version, flavor, license tier, and spaces
    Info,
    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Manage exception lists
    Exceptions {
        #[command(subcommand)]
        action: ExceptionsAction,
    },
    /// Manage rules as code
    State {
        #[command(subcommand)]
        action: StateAction,
    },
    /// Generate a shell completion script
    Completion {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Emit the command tree as JSON
    Commands,
}

#[derive(Debug, Subcommand)]
pub enum RulesAction {
    /// List detection rules
    List {
        #[arg(long)]
        enabled: bool,
        #[arg(long)]
        disabled: bool,
        #[arg(long = "type")]
        rule_type: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        /// Raw KQL, combined with the other filters
        #[arg(long)]
        filter: Option<String>,
    },
    /// Show one rule by rule_id or name. rule_id is tried first: if the
    /// selector happens to be both a valid rule_id and a different rule's
    /// name, the rule_id match wins.
    Get { selector: String },
    /// Check a rule file without contacting a server
    Validate {
        #[arg(long)]
        path: std::path::PathBuf,
    },
    /// Enable one or more rules
    Enable { selectors: Vec<String> },
    /// Disable one or more rules
    Disable { selectors: Vec<String> },
    /// Delete one or more rules
    Delete { selectors: Vec<String> },
    /// Export rules to a file or stdout. Exports every rule unless selectors
    /// or --tag narrow it.
    Export {
        /// Rule ids or names to export. Omit to export every rule.
        selectors: Vec<String>,
        /// Export every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
        /// File format: ndjson or yaml. Distinct from the global --format,
        /// which renders this command's own report, not the exported file.
        #[arg(long = "format-file", default_value = "ndjson")]
        format_file: String,
    },
    /// Import rules from a file
    Import {
        #[arg(long)]
        path: std::path::PathBuf,
        /// Replace rules that already exist
        #[arg(long)]
        overwrite: bool,
        /// Leave rules that already exist alone instead of failing on them
        #[arg(long, conflicts_with = "overwrite")]
        skip_existing: bool,
    },
    /// Run a rule against history without writing alerts
    Preview {
        /// A file path, rule_id, or rule name
        source: String,
        /// Number of simulated rule executions
        #[arg(long, default_value = "1")]
        invocations: u32,
        /// Return up to N matched documents alongside the count
        #[arg(long, default_value = "0")]
        sample: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum ExceptionsAction {
    /// List exception list containers.
    List {
        #[arg(long = "type")]
        list_type: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
    },
    /// Show one container and its items.
    Get {
        list_id: String,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
    },
    /// Check a file without contacting the server.
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Export containers and their items.
    Export {
        /// List ids to export. Omit to export every list.
        list_ids: Vec<String>,
        /// Export every list carrying this tag, in addition to any selectors.
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
        /// File format: ndjson or yaml. Distinct from the global --format,
        /// which renders this command's own report, not the exported file.
        #[arg(long = "format-file", default_value = "ndjson")]
        format_file: String,
    },
    /// Import containers and items from a file.
    Import {
        #[arg(long)]
        path: PathBuf,
        /// Replace lists that already exist
        #[arg(long)]
        overwrite: bool,
        /// Leave lists that already exist alone instead of failing on them
        #[arg(long, conflicts_with = "overwrite")]
        skip_existing: bool,
    },
    /// Delete containers and their items.
    Delete {
        list_ids: Vec<String>,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum StateAction {
    /// Write live rules to a directory. Pulls every rule unless selectors or
    /// --tag narrow it.
    Pull {
        /// Rule ids or names to pull. Omit to pull every rule.
        selectors: Vec<String>,
        #[arg(long)]
        dir: std::path::PathBuf,
        #[arg(long = "format-file", default_value = "ndjson")]
        format_file: String,
        /// Pull every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
    },
    /// Show field-level drift between the directory and the stack. Compares
    /// every rule unless selectors or --tag narrow it.
    Diff {
        /// Rule ids or names to compare. Omit to compare every rule.
        selectors: Vec<String>,
        #[arg(long)]
        dir: std::path::PathBuf,
        /// Compare every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
    },
    /// Apply the directory's rules to the stack. Applies every rule unless
    /// selectors or --tag narrow it.
    Push {
        /// Rule ids or names to apply. Omit to apply every rule.
        selectors: Vec<String>,
        #[arg(long)]
        dir: std::path::PathBuf,
        /// Write a change-evidence report
        #[arg(long)]
        report: Option<std::path::PathBuf>,
        /// Apply every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Create or replace a profile
    Init {
        /// Profile name; defaults to "default"
        #[arg(long)]
        name: Option<String>,
        /// Take values from ELASTICCTL_* environment variables
        #[arg(long)]
        from_env: bool,
    },
    /// List configured profiles
    List,
    /// Show one profile, with secrets redacted
    Show,
    /// Verify the profile can reach and authenticate to the stack
    Test,
}
