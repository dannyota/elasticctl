use crate::model::Rule;
use crate::rules::{self, RuleFilter};
use elasticctl_core::{Error, ErrorKind, Result, Transport};

pub const UNREADABLE_RULE_ID: &str = "<unreadable rule_id>";

pub const NAME_SEARCH_LIMIT: u32 = 100;

pub fn pick_by_name(found: &[Rule], name: &str) -> Result<String> {
    let matches: Vec<&Rule> = found.iter().filter(|r| r.name() == name).collect();

    match matches.len() {
        1 => Ok(matches[0].rule_id()?.to_string()),
        0 => Err(Error::new(
            ErrorKind::NotFound,
            format!("No rule with rule_id or name '{name}'"),
        )),
        _ => {
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

pub async fn to_rule_id(t: &Transport, selector: &str) -> Result<String> {
    match get_if_exists(t, selector).await? {
        Some(rule) => Ok(rule.rule_id()?.to_string()),
        None => by_name(t, selector).await,
    }
}

pub async fn to_rule(t: &Transport, selector: &str) -> Result<(String, Rule)> {
    let rule_id = match get_if_exists(t, selector).await? {
        Some(rule) if rule.rule_id()? == selector => return Ok((selector.to_string(), rule)),
        Some(rule) => rule.rule_id()?.to_string(),
        None => by_name(t, selector).await?,
    };
    let rule = rules::get(t, &rule_id).await?;
    Ok((rule_id, rule))
}

async fn get_if_exists(t: &Transport, rule_id: &str) -> Result<Option<Rule>> {
    match rules::get(t, rule_id).await {
        Ok(rule) => Ok(Some(rule)),
        Err(e) if e.kind == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

async fn by_name(t: &Transport, selector: &str) -> Result<String> {
    let filter = RuleFilter {
        name: Some(selector.to_string()),
        ..Default::default()
    };
    let (candidates, total) = rules::find_page(t, &filter, 1, NAME_SEARCH_LIMIT).await?;
    pick_by_name_capped(&candidates, selector, total)
}

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

fn search_matches(rule: &Rule, text: &str) -> bool {
    let needle = text.to_lowercase();
    rule.name().to_lowercase().contains(needle.as_str()) || rule.tags().contains(&text)
}

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

    if let Some(text) = search
        && text.trim().is_empty()
    {
        return Err(Error::new(
            ErrorKind::Error,
            "the --search text must not be empty or whitespace-only",
        ));
    }

    let mut ids: Vec<String> = Vec::new();
    for s in selectors {
        match local_match(local, s) {
            Some(found) => ids.push(found?),
            None => ids.push(to_rule_id(t, s).await?),
        }
    }

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

    if let Some(t) = tag
        && !tag_matched
    {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No rules matched tag '{t}'; nothing to {noun}"),
        ));
    }

    if let Some(s) = search
        && !search_matched
    {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("No rules matched search '{s}'; nothing to {noun}"),
        ));
    }

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
