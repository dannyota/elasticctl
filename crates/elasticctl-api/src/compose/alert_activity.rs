use crate::alerts::{self, AlertHit};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::json;
#[derive(Debug)]
pub struct AlertActivity {
    pub window: String,
    pub total: u64,
    pub open: u64,
    pub acknowledged: u64,
    pub closed: u64,
    pub other: u64,
    pub recent: Vec<AlertHit>,
}
pub fn validate_since(value: &str) -> Result<()> {
    let b = value.as_bytes();
    if !(2..=5).contains(&b.len())
        || b[0] == b'0'
        || !b[..b.len() - 1].iter().all(u8::is_ascii_digit)
        || !matches!(b[b.len() - 1], b's' | b'm' | b'h' | b'd' | b'w')
    {
        return Err(Error::new(ErrorKind::Error, "invalid since"));
    }
    Ok(())
}
pub async fn alert_activity(
    t: &Transport,
    rule_id: &str,
    since: &str,
    recent: usize,
) -> Result<AlertActivity> {
    validate_since(since)?;
    let size = recent.min(super::RECENT_ALERTS);
    let body = json!({"query":{"bool":{"filter":[{"term":{"kibana.alert.rule.rule_id":rule_id}},{"range":{"@timestamp":{"gte":format!("now-{since}")}}}]}},"sort":[{"@timestamp":{"order":"desc"}},{"kibana.alert.uuid":{"order":"asc"}}],"size":size,"track_total_hits":true,"aggs":{"status":{"terms":{"field":"kibana.alert.workflow_status","size":8}}}});
    let page = alerts::search_activity(t, &body).await?;
    let mut out = AlertActivity {
        window: since.into(),
        total: page.total,
        open: 0,
        acknowledged: 0,
        closed: 0,
        other: page.other,
        recent: page.hits.into_iter().take(size).collect(),
    };
    for (key, n) in page.buckets {
        let counter = match key.as_str() {
            "open" => &mut out.open,
            "acknowledged" => &mut out.acknowledged,
            "closed" => &mut out.closed,
            _ => &mut out.other,
        };
        *counter = counter
            .checked_add(n)
            .ok_or_else(|| Error::new(ErrorKind::Http, "activity count overflow"))?;
    }
    Ok(out)
}
