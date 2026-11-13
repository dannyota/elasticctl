use crate::context::Context;
use elasticctl_core::{Error, ErrorKind, Result};
use serde::Serialize;

#[derive(Serialize)]
pub struct ValueListPreview<'a, T: Serialize> {
    pub dry_run: bool,
    pub profile: &'a str,
    pub host: String,
    pub space: &'a str,
    pub command: &'static str,
    pub lists: &'a [T],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_bootstrapped: Option<bool>,
}

impl<'a, T: Serialize> ValueListPreview<'a, T> {
    pub fn new(ctx: &'a Context, command: &'static str, lists: &'a [T]) -> Self {
        Self {
            dry_run: !ctx.global.yes,
            profile: &ctx.resolved.name,
            host: ctx.resolved.profile.host(),
            space: &ctx.resolved.profile.space,
            command,
            lists,
            flow: None,
            already_bootstrapped: None,
        }
    }
}

pub fn check_value_lists<T: Serialize>(
    ctx: &Context,
    preview: &ValueListPreview<'_, T>,
) -> Result<bool> {
    assert!(super::MUTATING.contains(&preview.command));
    if ctx.global.json {
        eprintln!("{}", serde_json::to_string(preview).map_err(encoding)?);
    } else {
        let data = serde_json::to_value(preview).map_err(encoding)?;
        let mut details = Vec::new();
        for list in data["lists"].as_array().into_iter().flatten() {
            let id = list["id"].as_str().unwrap_or_default();
            let kind = list["type"].as_str().unwrap_or_default();
            details.push(format!("{id} ({kind})"));
            if let Some(action) = list["container_action"].as_str() {
                details.push(format!("container: {action}"));
                for (key, label) in [("adds", "add"), ("removes", "remove")] {
                    for value in list[key].as_array().into_iter().flatten() {
                        details.push(format!("{label}: {}", value.as_str().unwrap_or_default()));
                    }
                }
                details.push(format!(
                    "phase order: {}",
                    list["phase_order"].as_str().unwrap_or_default()
                ));
                details.push(format!(
                    "phase reason: {}",
                    list["phase_reason"].as_str().unwrap_or_default()
                ));
                for warning in list["warnings"].as_array().into_iter().flatten() {
                    details.push(format!(
                        "warning: {}",
                        warning["message"].as_str().unwrap_or_default()
                    ));
                }
            }
        }
        if let Some(flow) = preview.flow {
            details.push(format!("flow: {flow}"));
            details.push(format!(
                "already bootstrapped: {}",
                preview.already_bootstrapped.unwrap_or(false)
            ));
        }
        eprint!(
            "{}",
            super::preview_text(
                &super::Preview {
                    action: preview.command.into(),
                    details,
                },
                &ctx.resolved,
                ctx.global.yes
            )
        );
    }
    Ok(ctx.global.yes)
}

fn encoding(error: serde_json::Error) -> Error {
    Error::new(ErrorKind::Error, format!("encoding preview: {error}"))
}
