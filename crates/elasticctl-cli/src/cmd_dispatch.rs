use crate::cli::SourceArg;
use elasticctl_api::rules::RuleSource;
use elasticctl_core::{Error, ErrorKind};

mod config;
pub(crate) use config::config;
mod diagnostics;
pub(crate) use diagnostics::{doctor, info};
mod rules;
pub(crate) use rules::rules;
mod exceptions;
pub(crate) use exceptions::exceptions;
mod data_views;
pub(crate) use data_views::data_views;
mod dashboards;
pub(crate) use dashboards::dashboards;
mod fleet;
pub(crate) use fleet::fleet;
mod state;
pub(crate) use state::state;
mod search;
pub(crate) use search::search;
mod alerts;
pub(crate) use alerts::alerts;
mod cases;
pub(crate) use cases::cases;
mod meta;
pub(crate) use meta::{commands, completion, mcp};

fn source_to_api(source: SourceArg) -> RuleSource {
    match source {
        SourceArg::Custom => RuleSource::Custom,
        SourceArg::Customized => RuleSource::Customized,
        SourceArg::Prebuilt => RuleSource::Prebuilt,
        SourceArg::All => RuleSource::All,
    }
}

fn parse_file_format(s: &str) -> Result<elasticctl_api::codec::Format, Error> {
    use elasticctl_api::codec::Format;
    match s.to_ascii_lowercase().as_str() {
        "yaml" | "yml" => Ok(Format::Yaml),
        "ndjson" | "json" => Ok(Format::Ndjson),
        other => Err(Error::new(
            ErrorKind::Error,
            format!("unknown format-file '{other}'; expected ndjson or yaml"),
        )),
    }
}

fn parse_content_format(s: &str) -> Result<elasticctl_api::content_codec::ContentFormat, Error> {
    use elasticctl_api::content_codec::ContentFormat;
    match s.to_ascii_lowercase().as_str() {
        "json" => Ok(ContentFormat::Json),
        "yaml" | "yml" => Ok(ContentFormat::Yaml),
        other => Err(Error::new(
            ErrorKind::Error,
            format!("unknown format-file '{other}'; expected json or yaml"),
        )),
    }
}
