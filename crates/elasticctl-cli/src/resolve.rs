//! Turning a user-facing selector into the stable rule_id.

use crate::context::Context;
use elasticctl_api::model::Rule;
use elasticctl_api::rules::{self, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result};

/// Stands in for a rule's `rule_id` wherever one must be displayed but
/// cannot be read (e.g. a server response with a non-string `rule_id`).
/// Shared with `cmd::rules::summarize`, which has the same masking risk.
pub(crate) const UNREADABLE_RULE_ID: &str = "<unreadable rule_id>";

/// Exact-match only. A substring match would silently target the wrong
/// detection when two rules share a prefix.
pub fn pick_by_name(found: &[Rule], name: &str) -> Result<String> {
    let matches: Vec<&Rule> = found.iter().filter(|r| r.name() == name).collect();

    match matches.len() {
        1 => Ok(matches[0].rule_id()?.to_string()),
        0 => Err(Error::new(
            ErrorKind::NotFound,
            // The selector may have been a rule_id that missed. Reporting it
            // as a missed *name* points the operator at the wrong thing.
            format!("No rule with rule_id or name '{name}'"),
        )),
        _ => {
            // Every candidate must appear, even one with an unreadable
            // rule_id: dropping it would make the count and the list
            // disagree, leaving the operator unable to act on either.
            let ids: Vec<&str> = matches
                .iter()
                .map(|r| r.rule_id().unwrap_or(UNREADABLE_RULE_ID))
                .collect();
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

/// How many same-named candidates one page will consider. No real corpus has
/// a hundred rules sharing a name; the cap exists so a pathological one cannot
/// turn a lookup back into a corpus read.
pub(crate) const NAME_SEARCH_LIMIT: u32 = 100;

/// A selector is a rule_id or a display name. rule_id is tried first because
/// it is unambiguous; a name lookup only happens when that misses.
///
/// The name lookup is one server-side filtered `_find`, not a walk of every
/// page. Walking cost 8.8 seconds against 2,066 rules just to report that
/// nothing matched, and the whole answer fits in one request.
pub async fn to_rule_id(ctx: &Context, selector: &str) -> Result<String> {
    let transport = ctx.transport().await?;

    match rules::get(transport, selector).await {
        Ok(r) => return Ok(r.rule_id()?.to_string()),
        Err(e) if e.kind != ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }

    let filter = RuleFilter {
        name: Some(selector.to_string()),
        ..Default::default()
    };
    let (candidates, total) = rules::find_page(transport, &filter, 1, NAME_SEARCH_LIMIT).await?;
    pick_by_name_capped(&candidates, selector, total)
}

/// `pick_by_name` over a candidate page, told how many candidates the server
/// said there were.
///
/// The server filter is not the match: a KQL term on an analyzed field can
/// return a near match, so the exact comparison still happens here. When the
/// page was truncated and nothing matched exactly, the miss reports the cap
/// rather than claiming the name does not exist — those are different answers.
pub fn pick_by_name_capped(found: &[Rule], name: &str, total: u64) -> Result<String> {
    match pick_by_name(found, name) {
        Err(e) if e.kind == ErrorKind::NotFound && total > found.len() as u64 => Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "No rule with rule_id or name '{name}' among the first {} of {total} \
                     candidates; narrow the name",
                found.len()
            ),
        )),
        other => other,
    }
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
    fn a_capped_candidate_page_says_so_rather_than_claiming_the_name_is_absent() {
        // 100 same-named rules is beyond any real corpus, but reporting
        // "no such rule" when the answer was truncated would be a lie.
        let found: Vec<Rule> = (0..NAME_SEARCH_LIMIT)
            .map(|i| rule(&format!("id-{i}"), "Other"))
            .collect();
        let err = pick_by_name_capped(&found, "Ghost", NAME_SEARCH_LIMIT as u64 + 1).unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
        assert!(
            err.message.contains("first 100"),
            "the cap must be visible: {}",
            err.message
        );
    }

    #[test]
    fn name_matching_is_exact_not_substring() {
        let err = pick_by_name(&[rule("a", "Alpha Rule")], "Alpha").unwrap_err();
        assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
    }

    #[test]
    fn a_conflict_still_names_every_candidate_when_one_rule_id_is_unreadable() {
        let readable = rule("a", "Same");
        // `Rule::from_value` refuses a non-string rule_id; the derived
        // transparent `Deserialize` does not, which is why `pick_by_name`
        // still has to cope with one.
        let unreadable: Rule =
            serde_json::from_value(json!({"rule_id": 123, "name": "Same"})).unwrap();
        let found = vec![readable, unreadable];

        let err = pick_by_name(&found, "Same").unwrap_err();

        assert_eq!(err.kind, elasticctl_core::ErrorKind::Conflict);
        assert!(err.message.contains("2 rules"), "{}", err.message);
        assert!(
            err.message.contains('a') && err.message.contains(UNREADABLE_RULE_ID),
            "the count claims 2 candidates, so both must be listed: {}",
            err.message
        );
    }
}
