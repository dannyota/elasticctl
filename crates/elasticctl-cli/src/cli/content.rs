use super::non_empty;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum DataViewsAction {
    /// List data views
    List {
        /// Case-insensitive substring over id, name, and title
        #[arg(long, value_parser = non_empty)]
        search: Option<String>,
    },
    /// Show one data view by id or exact name
    Get { selector: String },
    /// Check a portable data-view file without contacting a server
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Export portable data views
    Export {
        /// Data-view ids or exact names. Omit to export every data view.
        selectors: Vec<String>,
        /// File format: json or yaml. This is separate from the global renderer.
        #[arg(long = "format-file", default_value = "json")]
        format_file: String,
    },
    /// Import portable data views
    Import {
        #[arg(long)]
        path: PathBuf,
        /// Replace data views that already exist
        #[arg(long, conflicts_with = "skip_existing")]
        overwrite: bool,
        /// Leave data views that already exist alone instead of failing
        #[arg(long, conflicts_with = "overwrite")]
        skip_existing: bool,
    },
    /// Delete unreferenced data views, or replace their references first
    Delete {
        /// Data-view ids or exact names
        #[arg(required = true)]
        selectors: Vec<String>,
        /// Target data view for replacing saved-object references
        #[arg(long)]
        replace_with: Option<String>,
    },
    /// Get, set, or unset the default data view
    Default {
        #[command(subcommand)]
        action: DataViewDefaultAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum DataViewDefaultAction {
    /// Show the current default data view
    Get,
    /// Set the current default data view
    Set { selector: String },
    /// Explicitly clear the current default data view
    Unset,
}

#[derive(Debug, Subcommand)]
pub enum DashboardsAction {
    /// List dashboards
    List {
        #[arg(long, value_parser = non_empty)]
        search: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show one dashboard by id or exact title
    Get { selector: String },
    /// Check a portable dashboard file without contacting a server
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Export portable dashboards
    Export {
        /// Dashboard ids or exact titles. Omit to export every dashboard.
        selectors: Vec<String>,
        /// File format: json or yaml. This is separate from the global renderer.
        #[arg(long = "format-file", default_value = "json")]
        format_file: String,
    },
    /// Import portable dashboards
    Import {
        #[arg(long)]
        path: PathBuf,
        /// Replace dashboards that already exist
        #[arg(long, conflicts_with = "skip_existing")]
        overwrite: bool,
        /// Leave dashboards that already exist alone instead of failing
        #[arg(long, conflicts_with = "overwrite")]
        skip_existing: bool,
    },
    /// Delete one or more dashboards
    Delete {
        /// Dashboard ids or exact titles
        selectors: Vec<String>,
    },
    /// Export or import opaque Saved Objects dashboard bundles
    Bundle {
        #[command(subcommand)]
        action: DashboardBundleAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum DashboardBundleAction {
    /// Export dashboards with deep Saved Objects references as NDJSON
    Export {
        /// Dashboard ids or exact titles. Omit to export every dashboard.
        selectors: Vec<String>,
    },
    /// Import an opaque Saved Objects dashboard bundle
    Import {
        #[arg(long)]
        path: PathBuf,
        /// Replace Saved Objects that already exist
        #[arg(long)]
        overwrite: bool,
    },
}
