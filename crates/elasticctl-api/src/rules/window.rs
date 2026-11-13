use std::collections::HashSet;

use super::{RuleFilter, find};
use crate::model::Rule;
use elasticctl_core::{Error, ErrorKind, Result, Transport};

pub const WINDOW_PAGE: u32 = 500;

pub const WINDOW_MAX_RULES: u64 = 4_000;

const SORT: &str = "&sort_field=created_at&sort_order=asc";

const PASSES: usize = 2;

pub async fn find_window(t: &Transport, filter: &RuleFilter) -> Result<Vec<Rule>> {
    for _ in 0..PASSES {
        if let Some(rules) = read_pass(t, filter).await? {
            return Ok(rules);
        }
    }
    Err(Error::new(
        ErrorKind::Conflict,
        "the matching rules changed during both corpus read passes; retry the read",
    ))
}

async fn read_pass(t: &Transport, filter: &RuleFilter) -> Result<Option<Vec<Rule>>> {
    let (mut rules, total) = find(t, filter, 1, WINDOW_PAGE, SORT).await?;
    if total > WINDOW_MAX_RULES {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "{total} rules match, more than the {WINDOW_MAX_RULES} a corpus read accepts. \
                 Narrow the selection with a filter."
            ),
        ));
    }
    let last_page = total.div_ceil(u64::from(WINDOW_PAGE)) as u32;
    let mut same_total = true;
    for page in 2..=last_page {
        let (more, page_total) = find(t, filter, page, WINDOW_PAGE, SORT).await?;
        same_total &= page_total == total;
        rules.extend(more);
    }
    let ids = rules
        .iter()
        .map(Rule::rule_id)
        .collect::<Result<HashSet<_>>>()?;
    let verified = same_total && rules.len() as u64 == total && ids.len() == rules.len();
    Ok(verified.then_some(rules))
}
