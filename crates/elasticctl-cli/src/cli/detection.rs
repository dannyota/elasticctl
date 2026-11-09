use super::{SourceArg, non_empty};
use clap::Subcommand;
use std::path::PathBuf;

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
        #[arg(long, conflicts_with = "filter", value_parser = non_empty)]
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
        #[arg(long, value_parser = non_empty)]
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
        #[arg(long, value_parser = non_empty)]
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
        #[arg(long, value_parser = non_empty)]
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
        #[arg(long, value_parser = non_empty)]
        search: Option<String>,
        /// Source scope used when selectors, --tag, and --search are absent
        #[arg(long, value_enum, default_value = "custom")]
        source: SourceArg,
    },
}
