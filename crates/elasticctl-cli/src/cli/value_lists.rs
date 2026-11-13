use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TypeArg {
    Keyword,
    Ip,
    #[value(name = "ip_range")]
    IpRange,
    Text,
}

impl From<TypeArg> for elasticctl_api::value_lists::ValueListType {
    fn from(value: TypeArg) -> Self {
        match value {
            TypeArg::Keyword => Self::Keyword,
            TypeArg::Ip => Self::Ip,
            TypeArg::IpRange => Self::IpRange,
            TypeArg::Text => Self::Text,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ValueListsAction {
    #[command(about = "List value-list containers")]
    List {
        #[arg(long = "type", value_enum, help = "Keep containers of this type")]
        list_type: Option<TypeArg>,
        #[arg(long, help = "Match id or name by substring, ignoring case")]
        search: Option<String>,
    },
    #[command(about = "Show a value list, counts, and warnings")]
    Get {
        #[arg(help = "Value list id")]
        id: String,
        #[arg(long, help = "Include the distinct values")]
        values: bool,
    },
    #[command(about = "Validate a local value-list pair without server contact")]
    Validate {
        #[arg(long, help = "Path to the container or values file")]
        path: PathBuf,
    },
    #[command(about = "Export value-list pairs without overwriting files")]
    Export {
        #[arg(required = true, num_args = 1.., help = "Value list ids to export")]
        ids: Vec<String>,
        #[arg(
            long,
            help = "Destination directory; defaults to the current directory"
        )]
        dir: Option<PathBuf>,
    },
    #[command(about = "Import a value-list pair with exact value reconciliation")]
    Import {
        #[arg(long, help = "Path to the container or values file")]
        path: PathBuf,
        #[arg(
            long,
            help = "Update an existing container and reconcile its values exactly"
        )]
        overwrite: bool,
    },
    #[command(about = "Delete value lists and their values")]
    Delete {
        #[arg(required = true, num_args = 1.., help = "Value list ids to delete")]
        ids: Vec<String>,
    },
    #[command(about = "Bootstrap the space's list data streams")]
    Init,
}
