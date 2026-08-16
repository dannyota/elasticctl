//! Resolve user-facing selectors to stable `rule_id` values.
//!
//! One resolver serves `rules export`, `delete`, `enable`, and state commands.
//! This keeps ambiguous-name and empty-match behavior consistent.
//!
//! Identity is always `rule_id`. Names only find IDs.

use crate::model::Rule;
use crate::rules::{self, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result, Transport};

/// Displays an unreadable `rule_id`, such as a non-string value from the
/// server.
pub const UNREADABLE_RULE_ID: &str = "<unreadable rule_id>";

/// Same-named candidates to consider in one page. The cap prevents a
/// pathological name lookup from becoming a corpus read.
pub const NAME_SEARCH_LIMIT: u32 = 100;

/// Match names exactly. A prefix match could target the wrong rule.
pub fn pick_by_name(found: &[Rule], name: &str) -> Result<String> {
    let matches: Vec<&Rule> = found.iter().filter(|r| r.name() == name).collect();

    match matches.len() {
        1 => Ok(matches[0].rule_id()?.to_string()),
        0 => Err(Error::new(
            ErrorKind::NotFound,
            // The selector might be an absent `rule_id`; reporting a missed
            // name would misidentify the problem.
            format!("No rule with rule_id or name '{name}'"),
        )),
        _ => {
            // List every candidate, including unreadable IDs, so the count and
            // list agree.
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

/// Run `pick_by_name` on a candidate page with the server's candidate total.
///
/// The KQL filter can return near matches on an analyzed field, so compare
/// exactly here. If the page is truncated with no exact match, report the cap
/// instead of claiming the name is absent.
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

/// Resolve a `rule_id` or display name against the stack. Try `rule_id` first
/// because it is unambiguous.
///
/// Name lookup uses one server-filtered `_find`. Walking 2,066 rules took 8.8
/// seconds only to report no match.
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

/// Match a selector against local rules before querying the stack.
///
/// `None` means no local match, so the caller queries the stack.
/// `Some(Err(..))` indicates an ambiguous local name.
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

/// Whether `rule` matches a `--search` text: a case-insensitive name substring
/// or an exact tag.
///
/// The server-side KQL (`alert.attributes.name: "*<text>*"`) matches an
/// analyzed field case-insensitively, so the local matcher must too, or a
/// `diff`/`push` would select a different rule set than the remote read finds.
fn search_matches(rule: &Rule, text: &str) -> bool {
    let needle = text.to_lowercase();
    rule.name().to_lowercase().contains(needle.as_str()) || rule.tags().contains(&text)
}

/// Resolve selectors, an optional tag, and an optional search to `rule_id`
/// values. Returns `None` when none is given and the caller should act on every
/// rule.
///
/// Check `local` before the stack. Pass an empty slice for `rules export` and
/// `state pull`. Pass disk rules for local commands so scoped `push` can select
/// locally added rules that the stack does not have.
///
/// `noun` completes command-specific refusal messages, such as "nothing to
/// export".
pub async fn resolve(
    t: &Transport,
    selectors: &[String],
    tag: Option<&str>,
    search: Option<&str>,
    local: &[Rule],
    noun: &str,
) -> Result<Option<Vec<String>>> {
    if selectors.is_empty() && tag.is_none() && search.is_none() {
        return Ok(None);
    }

    let mut ids: Vec<String> = Vec::new();
    for s in selectors {
        match local_match(local, s) {
            Some(found) => ids.push(found?),
            None => ids.push(to_rule_id(t, s).await?),
        }
    }

    // Track tag matches separately so a selector cannot hide an unmatched tag.
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

    // `--search` mirrors `--tag`: match locally, then on the stack, and union
    // the results. The local matcher reuses the same predicate as the remote
    // KQL so both sides narrow to the same rule set.
    let mut search_matched = false;
    if let Some(text) = search {
        for rule in local.iter().filter(|r| search_matches(r, text)) {
            search_matched = true;
            ids.push(rule.rule_id()?.to_string());
        }

        let filter = RuleFilter {
            search: Some(text.to_string()),
            ..Default::default()
        };
        for rule in rules::find_all(t, &filter).await? {
            search_matched = true;
            ids.push(rule.rule_id()?.to_string());
        }
    }

    ids.sort();
    ids.dedup();

    // Report an unmatched `--tag` even when a selector matched. A mistyped tag
    // must not silently shrink the result.
    if let Some(t) = tag
        && !tag_matched
    {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No rules matched tag '{t}'; nothing to {noun}"),
        ));
    }

    // Same for `--search`: a mistyped text must not silently shrink the result.
    if let Some(s) = search
        && !search_matched
    {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No rules matched search '{s}'; nothing to {noun}"),
        ));
    }

    // Defensive fallback: name the selector in the refusal rather than leaving
    // it blank.
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
        // A truncated result must not report the name as absent.
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
        // `Rule::from_value` rejects non-string IDs, but transparent
        // `Deserialize` does not, so `pick_by_name` must handle one.
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

    /// The server matches the analyzed `name` field case-insensitively, so the
    /// local `--search` matcher must too, or `diff`/`push` would narrow the
    /// local side differently from the remote read (spec 4.7).
    #[test]
    fn search_matches_a_different_case_name_substring() {
        let r = rule("a", "Suspicious Process");
        assert!(search_matches(&r, "process"));
        assert!(search_matches(&r, "PROCESS"));
        assert!(search_matches(&r, "suspicious"));
        assert!(!search_matches(&r, "unrelated"));
    }

    #[test]
    fn search_matches_an_exact_tag_but_not_a_tag_substring() {
        let r = Rule::from_value(json!({
            "rule_id": "a",
            "name": "Alpha",
            "tags": ["prod"]
        }))
        .unwrap();
        assert!(search_matches(&r, "prod"));
        assert!(!search_matches(&r, "pro"), "tags are exact, not substring");
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
