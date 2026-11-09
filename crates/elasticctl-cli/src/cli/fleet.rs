use super::non_empty;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum FleetAction {
    /// Manage Fleet agent policies
    AgentPolicies {
        #[command(subcommand)]
        action: AgentPoliciesAction,
    },
    /// Manage Fleet integration policies
    IntegrationPolicies {
        #[command(subcommand)]
        action: IntegrationPoliciesAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentPoliciesAction {
    /// List agent policies
    List {
        /// Case-insensitive substring over id and name
        #[arg(long, value_parser = non_empty)]
        search: Option<String>,
        /// Cap the rows returned after sorting by id
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show one agent policy by id or exact name
    Get { selector: String },
    /// Check a portable agent-policy file without contacting a server
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Export portable agent policies
    Export {
        /// Agent-policy ids or exact names
        #[arg(conflicts_with = "all_custom")]
        selectors: Vec<String>,
        /// Export every policy that is not platform-owned
        #[arg(long)]
        all_custom: bool,
        /// File format: json or yaml. This is separate from the global renderer.
        #[arg(long = "format-file", default_value = "json")]
        format_file: String,
    },
    /// Import portable agent policies
    Import {
        #[arg(long)]
        path: PathBuf,
        /// Replace agent policies that already exist
        #[arg(long, conflicts_with = "skip_existing")]
        overwrite: bool,
        /// Leave agent policies that already exist alone instead of failing
        #[arg(long, conflicts_with = "overwrite")]
        skip_existing: bool,
    },
    /// Delete agent policies that have no agents or integrations
    Delete {
        /// Agent-policy ids or exact names
        #[arg(required = true)]
        selectors: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum IntegrationPoliciesAction {
    /// List integration policies
    List {
        /// Case-insensitive substring over id and name
        #[arg(long, value_parser = non_empty)]
        search: Option<String>,
        /// Cap the rows returned after sorting by id
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show one integration policy by id or exact name
    Get {
        #[arg(value_parser = non_empty)]
        selector: String,
    },
    /// Check a portable integration-policy file without contacting a server
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Export portable integration policies
    Export {
        /// Integration-policy ids or exact names
        #[arg(conflicts_with = "all_custom", value_parser = non_empty)]
        selectors: Vec<String>,
        /// Export every integration policy that is not platform-owned
        #[arg(long)]
        all_custom: bool,
        /// File format: json or yaml. This is separate from the global renderer.
        #[arg(long = "format-file", default_value = "json")]
        format_file: String,
    },
    /// Import portable integration policies
    Import {
        #[arg(long)]
        path: PathBuf,
        /// Replace integration policies that already exist
        #[arg(long, conflicts_with = "skip_existing")]
        overwrite: bool,
        /// Leave integration policies that already exist alone instead of failing
        #[arg(long, conflicts_with = "overwrite")]
        skip_existing: bool,
    },
    /// Delete integration policies
    Delete {
        /// Integration-policy ids or exact names
        #[arg(required = true, value_parser = non_empty)]
        selectors: Vec<String>,
    },
}
