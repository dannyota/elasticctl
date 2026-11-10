//! The search that finds this run's open alerts, for cleanup and for the
//! baseline audit.
//!
//! An empty page proves nothing unless the search was complete: a timed-out
//! search, a failed shard, or a total that is a lower bound can each hide
//! alerts that are still open. Such a search is refused, never read as zero.

use crate::recorder::compose::requests::open_session_alerts_body;
use elasticctl_core::{Error, Transport};
use serde_json::Value;

/// Open alerts of this run's rule from one complete search.
#[derive(Debug, PartialEq)]
pub(super) struct OpenAlerts {
    /// The exact number of open alerts.
    pub(super) total: u64,
    /// Their ids on this page, at most the page size.
    pub(super) ids: Vec<String>,
}

/// Why a search did not produce a trustworthy answer.
#[derive(Debug)]
pub(super) enum SearchError {
    Request(Error),
    Incomplete(&'static str),
}

/// Read one search response, refusing it unless it is complete: not timed
/// out, every shard answered, an exact total, and the open ids on the page.
pub(super) fn complete_open_alerts(page: &Value) -> Result<OpenAlerts, &'static str> {
    match page.get("timed_out").and_then(Value::as_bool) {
        Some(false) => {}
        Some(true) => return Err("it timed out"),
        None => return Err("it did not report whether it timed out"),
    }
    let shards = page.get("_shards");
    let failed = shards
        .and_then(|shards| shards.get("failed"))
        .and_then(Value::as_u64);
    let failures = shards
        .and_then(|shards| shards.get("failures"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    match failed {
        Some(0) if failures == 0 => {}
        Some(_) => return Err("a shard failed"),
        None => return Err("it did not report its failed shards"),
    }
    let total = page.pointer("/hits/total");
    let exact = total
        .and_then(|total| total.get("relation"))
        .and_then(Value::as_str)
        == Some("eq");
    let Some(total) = total
        .and_then(|total| total.get("value"))
        .and_then(Value::as_u64)
        .filter(|_| exact)
    else {
        return Err("its total is not exact");
    };
    let ids = page
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .and_then(|hits| {
            hits.iter()
                .map(|hit| hit.get("_id").and_then(Value::as_str).map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or("its hits could not be read")?;
    if ids.len() as u64 > total || (total > 0 && ids.is_empty()) {
        return Err("its hits do not match its total");
    }
    Ok(OpenAlerts { total, ids })
}

/// Search the open alerts of this run's rule, by its per-creation id.
pub(super) async fn open_session_alerts(
    t: &Transport,
    rule_uuid: &str,
) -> Result<OpenAlerts, SearchError> {
    let page = t
        .post(
            elasticctl_api::alerts::SEARCH_PATH,
            Some(&open_session_alerts_body(rule_uuid)),
        )
        .await
        .map_err(SearchError::Request)?;
    complete_open_alerts(&page).map_err(SearchError::Incomplete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page(timed_out: Value, shards: Value, total: Value, ids: &[&str]) -> Value {
        let hits: Vec<Value> = ids.iter().map(|id| json!({"_id": id})).collect();
        json!({"took": 1, "timed_out": timed_out, "_shards": shards,
            "hits": {"total": total, "hits": hits}})
    }

    fn healthy() -> Value {
        json!({"total": 2, "successful": 2, "skipped": 0, "failed": 0})
    }

    #[test]
    fn a_complete_search_returns_the_exact_total_and_ids() {
        let open = complete_open_alerts(&page(
            json!(false),
            healthy(),
            json!({"value": 2, "relation": "eq"}),
            &["a1", "a2"],
        ))
        .expect("complete");
        assert_eq!(
            open,
            OpenAlerts {
                total: 2,
                ids: vec!["a1".into(), "a2".into()]
            }
        );
        let zero = complete_open_alerts(&page(
            json!(false),
            healthy(),
            json!({"value": 0, "relation": "eq"}),
            &[],
        ))
        .expect("complete zero");
        assert_eq!(zero.total, 0);
    }

    #[test]
    fn an_incomplete_empty_search_is_never_read_as_zero() {
        let eq = json!({"value": 0, "relation": "eq"});
        for (response, reason) in [
            (
                page(json!(true), healthy(), eq.clone(), &[]),
                "it timed out",
            ),
            (
                page(Value::Null, healthy(), eq.clone(), &[]),
                "it did not report whether it timed out",
            ),
            (
                page(
                    json!(false),
                    json!({"total": 2, "successful": 1, "failed": 1}),
                    eq.clone(),
                    &[],
                ),
                "a shard failed",
            ),
            (
                page(
                    json!(false),
                    json!({"total": 2, "successful": 2, "failed": 0,
                        "failures": [{"shard": 1}]}),
                    eq.clone(),
                    &[],
                ),
                "a shard failed",
            ),
            (
                page(json!(false), json!({"total": 2}), eq.clone(), &[]),
                "it did not report its failed shards",
            ),
            (
                page(
                    json!(false),
                    healthy(),
                    json!({"value": 0, "relation": "gte"}),
                    &[],
                ),
                "its total is not exact",
            ),
            (
                page(json!(false), healthy(), json!({"value": 0}), &[]),
                "its total is not exact",
            ),
            (
                page(json!(false), healthy(), json!(0), &[]),
                "its total is not exact",
            ),
            (
                page(
                    json!(false),
                    healthy(),
                    json!({"value": 3, "relation": "eq"}),
                    &[],
                ),
                "its hits do not match its total",
            ),
        ] {
            assert_eq!(complete_open_alerts(&response), Err(reason), "{response}");
        }
    }
}
