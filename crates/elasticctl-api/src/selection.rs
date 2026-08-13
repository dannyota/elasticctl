//! Turning user-facing selectors into the stable `rule_id`s they name.
//!
//! One resolver serves every command that takes selectors. `rules export`,
//! `delete`, `enable`, and the state commands all answer "which rules?" the
//! same way, and a second implementation of that question is a second set of
//! edge cases around ambiguous names and empty matches.
//!
//! Identity is always `rule_id`. A name is only ever a way of finding one.

use crate::model::Rule;
use crate::rules::{self, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result, Transport};

/// Stands in for a rule's `rule_id` wherever one must be displayed but cannot
/// be read — a server response with a non-string `rule_id`, for instance.
pub const UNREADABLE_RULE_ID: &str = "<unreadable rule_id>";

/// How many same-named candidates one page will consider. No real corpus has a
/// hundred rules sharing a name; the cap exists so a pathological one cannot
/// turn a lookup back into a corpus read.
pub const NAME_SEARCH_LIMIT: u32 = 100;

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
            // rule_id: dropping it would make the count and the list disagree,
            // leaving the operator unable to act on either.
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

/// A selector is a `rule_id` or a display name, resolved against the stack.
/// `rule_id` is tried first because it is unambiguous; a name lookup only
/// happens when that misses.
///
/// The name lookup is one server-side filtered `_find`, not a walk of every
/// page. Walking cost 8.8 seconds against 2,066 rules just to report that
/// nothing matched, and the whole answer fits in one request.
pub async fn to_rule_id(t: &Transport, selector: &str) -> Result<String> {
    match rules::get(t, selector).await {
        Ok(r) => return Ok(r.rule_id()?.to_string()),
        Err(e) if e.kind != ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }

    let filter = RuleFilter {
        name: Some(selector.to_string()),
        ..Default::default()
    };
    let (candidates, total) = rules::find_page(t, &filter, 1, NAME_SEARCH_LIMIT).await?;
    pick_by_name_capped(&candidates, selector, total)
}

/// A selector matched against rules already on disk, before the stack is asked.
///
/// `None` means no local rule answers to it, which is not an error — the
/// caller falls through to the stack. `Some(Err(..))` is an ambiguous local
/// name, which is.
fn local_match(local: &[Rule], selector: &str) -> Option<Result<String>> {
    if local.iter().any(|r| r.rule_id().ok() == Some(selector)) {
        return Some(Ok(selector.to_string()));
    }

    let named: Vec<&Rule> = local.iter().filter(|r| r.name() == selector).collect();
    match named.len() {
        0 => None,
        1 => Some(named[0].rule_id().map(str::to_string)),
        _ => {
            let ids: Vec<&str> = named
                .iter()
                .map(|r| r.rule_id().unwrap_or(UNREADABLE_RULE_ID))
                .collect();
            Some(Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "{} local rules are named '{selector}'. Select one by rule_id: {}",
                    named.len(),
                    ids.join(", ")
                ),
            )))
        }
    }
}

/// The `rule_id`s named by a set of selectors and an optional tag, or `None`
/// when neither was given and the caller should act on everything.
///
/// `local` is consulted before the stack. Pass an empty slice for a command
/// that reads from the stack, such as `rules export` or `state pull`. Pass the
/// rules read from disk for a command that acts on the local directory: a
/// locally-added rule exists in no remote index yet, so resolving remotely
/// first would make it unselectable, which is the case scoped `push` is most
/// wanted for.
///
/// `noun` completes the refusal messages ("nothing to export"), so each
/// command's failure reads as its own rather than as a generic one.
pub async fn resolve(
    t: &Transport,
    selectors: &[String],
    tag: Option<&str>,
    local: &[Rule],
    noun: &str,
) -> Result<Option<Vec<String>>> {
    if selectors.is_empty() && tag.is_none() {
        return Ok(None);
    }

    let mut ids: Vec<String> = Vec::new();
    for s in selectors {
        match local_match(local, s) {
            Some(found) => ids.push(found?),
            None => ids.push(to_rule_id(t, s).await?),
        }
    }

    // The tag's contribution is tracked separately: a tag that matched nothing
    // must not disappear into a union that a selector rescued.
    let mut tag_matched = false;
    if let Some(tag) = tag {
        for rule in local.iter().filter(|r| r.tags().contains(&tag)) {
            tag_matched = true;
            ids.push(rule.rule_id()?.to_string());
        }

        let filter = RuleFilter {
            tag: Some(tag.to_string()),
            ..Default::default()
        };
        for rule in rules::find_all(t, &filter).await? {
            tag_matched = true;
            ids.push(rule.rule_id()?.to_string());
        }
    }

    ids.sort();
    ids.dedup();

    // A `--tag` that matched nothing is a miss worth reporting even when a
    // selector resolved and rescued the union: a typo'd tag must not silently
    // shrink the result. This is also the empty-selection refusal — with no
    // selectors, the tag's zero matches leave `ids` empty.
    if let Some(t) = tag
        && !tag_matched
    {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No rules matched tag '{t}'; nothing to {noun}"),
        ));
    }

    // Defensive: unreachable today — a selector either resolves or fails, and
    // the whole-space case returned `Ok(None)` above — but the message must
    // name what was asked for, not emit a blank selector.
    if ids.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "No rules matched the selector(s) '{}'; nothing to {noun}",
                selectors.join("', '")
            ),
        ));
    }

    Ok(Some(ids))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(err.kind, ErrorKind::Conflict);
        assert!(
            err.message.contains('a') && err.message.contains('b'),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_name_with_no_match_is_not_found() {
        let err = pick_by_name(&[rule("a", "Alpha")], "Ghost").unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound);
    }

    #[test]
    fn a_capped_candidate_page_says_so_rather_than_claiming_the_name_is_absent() {
        // 100 same-named rules is beyond any real corpus, but reporting
        // "no such rule" when the answer was truncated would be a lie.
        let found: Vec<Rule> = (0..NAME_SEARCH_LIMIT)
            .map(|i| rule(&format!("id-{i}"), "Other"))
            .collect();
        let err = pick_by_name_capped(&found, "Ghost", NAME_SEARCH_LIMIT as u64 + 1).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound);
        assert!(
            err.message.contains("first 100"),
            "the cap must be visible: {}",
            err.message
        );
    }

    #[test]
    fn name_matching_is_exact_not_substring() {
        let err = pick_by_name(&[rule("a", "Alpha Rule")], "Alpha").unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound);
    }

    #[test]
    fn a_conflict_still_names_every_candidate_when_one_rule_id_is_unreadable() {
        let readable = rule("a", "Same");
        // `Rule::from_value` refuses a non-string rule_id; the derived
        // transparent `Deserialize` does not, which is why `pick_by_name` still
        // has to cope with one.
        let unreadable: Rule =
            serde_json::from_value(json!({"rule_id": 123, "name": "Same"})).unwrap();
        let found = vec![readable, unreadable];

        let err = pick_by_name(&found, "Same").unwrap_err();

        assert_eq!(err.kind, ErrorKind::Conflict);
        assert!(err.message.contains("2 rules"), "{}", err.message);
        assert!(
            err.message.contains('a') && err.message.contains(UNREADABLE_RULE_ID),
            "the count claims 2 candidates, so both must be listed: {}",
            err.message
        );
    }

    #[test]
    fn a_local_rule_id_matches_without_asking_the_stack() {
        let local = vec![rule("a", "Alpha")];
        assert_eq!(local_match(&local, "a").unwrap().unwrap(), "a");
    }

    #[test]
    fn a_local_name_resolves_to_its_rule_id() {
        let local = vec![rule("a", "Alpha")];
        assert_eq!(local_match(&local, "Alpha").unwrap().unwrap(), "a");
    }

    #[test]
    fn an_unmatched_selector_falls_through_to_the_stack() {
        let local = vec![rule("a", "Alpha")];
        assert!(local_match(&local, "Ghost").is_none());
    }

    #[test]
    fn an_ambiguous_local_name_is_refused_naming_both_rule_ids() {
        let local = vec![rule("a", "Same"), rule("b", "Same")];
        let err = local_match(&local, "Same").unwrap().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Conflict);
        assert!(
            err.message.contains('a') && err.message.contains('b'),
            "identity is rule_id, so both must be named: {}",
            err.message
        );
    }
}
