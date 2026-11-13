use clap::{CommandFactory, Parser, Subcommand, ValueEnum, builder::OsStringValueParser};
use elasticctl_core::{Error, ErrorKind};
use std::ffi::OsString;
use std::path::PathBuf;
use std::str::FromStr;

mod content;
mod detection;
mod fleet;
mod triage;
mod value_lists;
pub use value_lists::ValueListsAction;

pub use content::{
    DashboardBundleAction, DashboardsAction, DataViewDefaultAction, DataViewsAction,
};
pub use detection::{ExceptionsAction, PrebuiltAction, RulesAction, StateAction};
pub use fleet::{AgentPoliciesAction, FleetAction, IntegrationPoliciesAction};
pub use triage::{AlertsAction, CasesAction, SearchAction};

const MCP_DETECTION_VALUE_ARGS: [&str; 7] = [
    "profile", "config", "space", "format", "fields", "out", "timeout",
];

fn mcp_detection_command() -> clap::Command {
    let mut command = Cli::command()
        .ignore_errors(true)
        .args_override_self(true)
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .disable_version_flag(true);
    for id in MCP_DETECTION_VALUE_ARGS {
        command = command.mut_arg(id, |arg| arg.value_parser(OsStringValueParser::new()));
    }
    command
}

pub fn is_mcp_invocation(argv: &[OsString]) -> bool {
    mcp_detection_command()
        .try_get_matches_from(argv)
        .ok()
        .is_some_and(|matches| matches.subcommand_name() == Some("mcp"))
}

fn non_empty(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("value must not be empty".into())
    } else {
        Ok(value.to_string())
    }
}

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
    #[command(about = "Manage value lists")]
    ValueLists {
        #[command(subcommand)]
        action: ValueListsAction,
    },
    /// Manage Kibana data views
    DataViews {
        #[command(subcommand)]
        action: DataViewsAction,
    },
    /// Manage Kibana dashboards
    Dashboards {
        #[command(subcommand)]
        action: DashboardsAction,
    },
    /// Manage Fleet agent and integration policies
    Fleet {
        #[command(subcommand)]
        action: FleetAction,
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
    /// Triage detection alerts
    Alerts {
        #[command(subcommand)]
        action: AlertsAction,
    },
    /// Track investigations as cases
    Cases {
        #[command(subcommand)]
        action: CasesAction,
    },
    /// Serve Elastic tools over MCP stdio
    Mcp {
        #[command(subcommand)]
        action: McpAction,
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
pub enum McpAction {
    /// Serve MCP over stdin and stdout
    Serve {
        /// Enable the synchronous Elasticsearch query tools for this process.
        #[arg(long)]
        allow_query_tools: bool,
        /// Enable mutation tools for the named classes.
        #[arg(long, value_name = "CLASSES")]
        allow_mutations: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn detection_relaxes_every_value_taking_global_and_only_those_globals() {
        let command = Cli::command();
        let actual = command
            .get_arguments()
            .filter(|arg| arg.is_global_set() && arg.get_action().takes_values())
            .map(|arg| arg.get_id().as_str())
            .collect::<Vec<_>>();
        assert_eq!(actual, MCP_DETECTION_VALUE_ARGS);
    }

    #[test]
    fn detection_classifies_mcp_through_valid_and_invalid_global_placements() {
        for values in [
            &["elasticctl", "mcp", "serve"][..],
            &["elasticctl", "--profile", "analyst", "mcp", "serve"],
            &["elasticctl", "mcp", "--space", "default", "serve"],
            &["elasticctl", "mcp", "serve", "--timeout", "30"],
            &["elasticctl", "--timeout=argument-sentinel", "mcp", "serve"],
            &["elasticctl", "--format=argument-sentinel", "mcp", "serve"],
            &[
                "elasticctl",
                "--timeout",
                "argument-sentinel",
                "--profile",
                "analyst",
                "mcp",
                "serve",
            ],
            &[
                "elasticctl",
                "--profile=analyst",
                "mcp",
                "--space",
                "default",
                "serve",
                "--timeout",
                "30",
            ],
            &[
                "elasticctl",
                "--timeout=bad",
                "--timeout",
                "worse",
                "mcp",
                "serve",
            ],
            &[
                "elasticctl",
                "--profile",
                "one",
                "mcp",
                "--profile=two",
                "serve",
                "--profile",
                "three",
            ],
            &["elasticctl", "--debug", "--debug", "mcp", "serve"],
            &["elasticctl", "mcp", "--unknown", "serve"],
            &["elasticctl", "mcp", "serve", "--unknown"],
            &["elasticctl", "mcp", "serve", "--timeout"],
            &[
                "elasticctl",
                "--timeout",
                "--profile",
                "analyst",
                "mcp",
                "serve",
            ],
        ] {
            assert!(is_mcp_invocation(&argv(values)), "{values:?}");
        }
    }

    #[test]
    fn detection_respects_values_positionals_and_root_parse_boundaries() {
        for values in [
            &["elasticctl", "--profile", "mcp", "info"][..],
            &["elasticctl", "--profile", "serve", "info"],
            &["elasticctl", "--config", "mcp", "commands"],
            &["elasticctl", "--config=mcp", "commands"],
            &["elasticctl", "rules", "get", "mcp"],
            &["elasticctl", "rules", "get", "serve"],
            &["elasticctl", "--profile", "mcp", "serve"],
            &["elasticctl", "--", "mcp", "serve"],
            &["elasticctl", "--timeout", "mcp", "serve"],
            &["elasticctl", "--unknown", "mcp", "serve"],
        ] {
            assert!(!is_mcp_invocation(&argv(values)), "{values:?}");
        }
        assert!(is_mcp_invocation(&argv(&[
            "elasticctl",
            "--profile",
            "mcp",
            "mcp",
            "serve",
        ])));
    }

    #[test]
    fn detection_leaves_help_and_version_to_the_typed_parser() {
        assert!(!is_mcp_invocation(&argv(&["elasticctl", "--help"])));
        assert!(!is_mcp_invocation(&argv(&["elasticctl", "--version"])));
        assert!(is_mcp_invocation(&argv(&["elasticctl", "mcp", "--help"])));
        assert!(is_mcp_invocation(&argv(&[
            "elasticctl",
            "mcp",
            "serve",
            "--help",
        ])));
        assert!(is_mcp_invocation(&argv(&[
            "elasticctl",
            "--timeout=argument-sentinel",
            "mcp",
            "serve",
            "--help",
        ])));
    }

    #[test]
    fn typed_parser_remains_authoritative_for_global_duplicates() {
        let parsed = Cli::try_parse_from(argv(&[
            "elasticctl",
            "--profile",
            "one",
            "mcp",
            "--profile=two",
            "serve",
            "--profile",
            "three",
        ]));
        let parsed = parsed.expect("the normal parser retains current duplicate handling");
        assert_eq!(parsed.global.profile.as_deref(), Some("three"));
    }
}
