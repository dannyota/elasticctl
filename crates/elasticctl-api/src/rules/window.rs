//! The verified corpus read: every rule matching a filter, read in pages
//! ordered by creation time and checked before it is returned.

use std::collections::HashSet;

use super::{RuleFilter, find};
use crate::model::Rule;
use elasticctl_core::{Error, ErrorKind, Result, Transport};

/// Rules per corpus page. A 500-rule page measured at most 4,458,395 bytes,
/// well under the response body cap.
pub const WINDOW_PAGE: u32 = 500;

/// The largest corpus `find_window` reads, in at most eight pages. The latency
/// gate sets it; raising it needs a new measurement.
pub const WINDOW_MAX_RULES: u64 = 4_000;

/// Creation order keeps earlier pages stable when a rule is created during the
/// read. Default-order paging returned duplicate rows on Hosted 9.5.6.
const SORT: &str = "&sort_field=created_at&sort_order=asc";

/// Read passes per call, so a call sends at most 16 requests.
const PASSES: usize = 2;

/// Every rule matching `filter`, in creation order.
///
/// Page 1 gives the total. A total above `WINDOW_MAX_RULES` fails with kind
/// `unsupported` before page 2. A pass is kept only when every page reported
/// the same total, the row count equals that total, and every `rule_id` is
/// distinct. A failed pass is discarded and the read starts again from page 1
/// once; a second failed pass is kind `conflict`.
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

/// One pass over every page. `None` means the pass failed verification.
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
    // At most eight pages after the check above.
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
