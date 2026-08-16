//! Argument definitions. Nothing here reaches into `elasticctl-api`.

use clap::{Parser, Subcommand, ValueEnum};
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

/// The `--source` flag's values. The CLI-local enum keeps clap types out of
/// `-api`; `main` maps it to `elasticctl_api::rules::RuleSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SourceArg {
    Custom,
    Customized,
    Prebuilt,
    All,
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
    /// Run ES|QL or Query DSL against Elasticsearch data
    Search {
        #[command(subcommand)]
        action: SearchAction,
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
        /// Friendly name-substring + tag search, mutually exclusive with --filter
        #[arg(long, conflicts_with = "filter")]
        search: Option<String>,
        /// Which rules to list: custom, customized, prebuilt, or all
        #[arg(long, value_enum, default_value = "all")]
        source: SourceArg,
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
        /// Which rules to export: custom, customized, prebuilt, or all
        #[arg(long, value_enum, default_value = "all")]
        source: SourceArg,
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
    /// Report on and install Elastic's prebuilt rules
    Prebuilt {
        #[command(subcommand)]
        action: PrebuiltAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum PrebuiltAction {
    /// Report installed, missing, outdated, and customized prebuilt rules
    Status,
    /// Install missing and update outdated prebuilt rules
    Install,
}

#[derive(Debug, Subcommand)]
pub enum ExceptionsAction {
    /// List exception list containers
    List {
        #[arg(long = "type")]
        list_type: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
        /// Friendly name-substring search
        #[arg(long)]
        search: Option<String>,
    },
    /// Show one container and its items
    Get {
        list_id: String,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
    },
    /// Check a file without contacting the server
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Export containers and their items
    Export {
        /// `list_id` values to export. Omit to export every list
        list_ids: Vec<String>,
        /// Export every list carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
        /// File format: ndjson or yaml. Distinct from the global --format,
        /// which renders this command's own report, not the exported file.
        #[arg(long = "format-file", default_value = "ndjson")]
        format_file: String,
    },
    /// Import containers and items from a file
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
    /// Delete containers and their items
    Delete {
        list_ids: Vec<String>,
        #[arg(long, value_parser = ["single", "agnostic"])]
        namespace: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum StateAction {
    /// Write live rules to a directory. Without selectors, --tag, or --search,
    /// pulls the active --source scope.
    Pull {
        /// Rule ids or names to pull. Omit with no --tag/--search to use --source.
        selectors: Vec<String>,
        #[arg(long)]
        dir: std::path::PathBuf,
        #[arg(long = "format-file", default_value = "ndjson")]
        format_file: String,
        /// Pull every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
        /// Pull every rule whose name contains this text or carries it as a tag
        #[arg(long)]
        search: Option<String>,
        /// Source scope used when selectors, --tag, and --search are absent
        #[arg(long, value_enum, default_value = "custom")]
        source: SourceArg,
    },
    /// Show field-level drift between the directory and the stack. Without
    /// selectors, --tag, or --search, compares the active --source scope.
    Diff {
        /// Rule ids or names to compare. Omit with no --tag/--search to use --source.
        selectors: Vec<String>,
        #[arg(long)]
        dir: std::path::PathBuf,
        /// Compare every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
        /// Compare every rule whose name contains this text or carries it as a tag
        #[arg(long)]
        search: Option<String>,
        /// Source scope used when selectors, --tag, and --search are absent
        #[arg(long, value_enum, default_value = "custom")]
        source: SourceArg,
    },
    /// Apply the directory's rules to the stack. Without selectors, --tag, or
    /// --search, applies the active --source scope.
    Push {
        /// Rule ids or names to apply. Omit with no --tag/--search to use --source.
        selectors: Vec<String>,
        #[arg(long)]
        dir: std::path::PathBuf,
        /// Write a change-evidence report
        #[arg(long)]
        report: Option<std::path::PathBuf>,
        /// Apply every rule carrying this tag, in addition to any selectors
        #[arg(long)]
        tag: Option<String>,
        /// Apply every rule whose name contains this text or carries it as a tag
        #[arg(long)]
        search: Option<String>,
        /// Source scope used when selectors, --tag, and --search are absent
        #[arg(long, value_enum, default_value = "custom")]
        source: SourceArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum SearchAction {
    /// Run an ES|QL query
    Esql {
        /// The ES|QL query text
        query: String,
        /// Resolve a Kibana data view to an index pattern
        #[arg(long, conflicts_with = "index")]
        data_view: Option<String>,
        /// Explicit index or alias, overrides the query's own source
        #[arg(long, conflicts_with = "data_view")]
        index: Option<String>,
        /// Cap the number of result rows
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Run a Query DSL search body
    Dsl {
        /// JSON body or @path
        body: String,
        /// Resolve a Kibana data view to an index pattern
        #[arg(long, conflicts_with = "index")]
        data_view: Option<String>,
        /// Explicit index or alias
        #[arg(long, conflicts_with = "data_view")]
        index: Option<String>,
        /// Cap the number of result rows
        #[arg(long)]
        limit: Option<usize>,
        /// Add `_id`, `_index`, and `_score` to each rendered row
        #[arg(long)]
        with_meta: bool,
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
