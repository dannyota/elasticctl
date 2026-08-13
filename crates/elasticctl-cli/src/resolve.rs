//! Turning a user-facing selector into the stable rule_id.

use crate::context::Context;
use elasticctl_api::model::Rule;
use elasticctl_api::rules::{self, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result};

/// Exact-match only. A substring match would silently target the wrong
/// detection when two rules share a prefix.
pub fn pick_by_name(found: &[Rule], name: &str) -> Result<String> {
    let matches: Vec<&Rule> = found.iter().filter(|r| r.name() == name).collect();

    match matches.len() {
        1 => Ok(matches[0].rule_id()?.to_string()),
        0 => Err(Error::new(
            ErrorKind::NotFound,
            format!("No rule named '{name}'"),
        )),
        _ => {
            let ids: Vec<&str> = matches.iter().filter_map(|r| r.rule_id().ok()).collect();
            Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "{} rules are named '{name}'. Select one by rule_id: {}",
                    matches.len(),
                    ids.join(", ")
                ),
            ))
        }
    }
}

/// A selector is a rule_id or a display name. rule_id is tried first because
/// it is unambiguous; a name lookup only happens when that misses.
pub async fn to_rule_id(ctx: &Context, selector: &str) -> Result<String> {
    let transport = ctx.transport().await?;

    match rules::get(transport, selector).await {
        Ok(r) => return Ok(r.rule_id()?.to_string()),
        Err(e) if e.kind != ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }

    let found = rules::find_all(transport, &RuleFilter::default()).await?;
    pick_by_name(&found, selector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_api::model::Rule;
    use serde_json::json;

    fn rule(id: &str, name: &str) -> Rule {
        Rule::from_value(json!({"rule_id": id, "name": name})).unwrap()
    }

    #[test]
    fn a_unique_name_resolves_to_its_rule_id() {
        let found = vec![rule("a", "Alpha"), rule("b", "Beta")];
        assert_eq!(pick_by_name(&found, "Beta").unwrap(), "b");
    }

    #[test]
    fn an_ambiguous_name_is_a_conflict_listing_every_candidate() {
        let found = vec![rule("a", "Same"), rule("b", "Same")];
        let err = pick_by_name(&found, "Same").unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::Conflict);
        assert!(
            err.message.contains('a') && err.message.contains('b'),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_name_with_no_match_is_not_found() {
        let err = pick_by_name(&[rule("a", "Alpha")], "Ghost").unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    }

    #[test]
    fn name_matching_is_exact_not_substring() {
        let err = pick_by_name(&[rule("a", "Alpha Rule")], "Alpha").unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    }
}
