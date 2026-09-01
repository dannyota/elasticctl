//! Case orchestration: filters, list/get, and the guarded mutation plans.

use crate::cases::{self, Case, CaseStatus};
use elasticctl_core::{Result, Transport, urlencode};

/// The `_find` route's per-page cap.
pub const PAGE_SIZE: u32 = 100;

#[derive(Debug, Clone, Default)]
pub struct CaseFilter {
    pub status: Option<CaseStatus>,
    pub severity: Option<String>,
    pub tag: Option<String>,
    /// Matches title and description server-side.
    pub search: Option<String>,
}

/// Deterministic query string for `GET /api/cases/_find`. Key order is
/// fixed so tests and fixtures are stable.
pub fn find_query(f: &CaseFilter, page: u32, per_page: u32) -> String {
    let mut q = format!("page={page}&perPage={per_page}&sortField=createdAt&sortOrder=desc");
    if let Some(status) = f.status {
        q.push_str(&format!("&status={}", status.as_str()));
    }
    if let Some(severity) = &f.severity {
        q.push_str(&format!("&severity={}", urlencode(severity)));
    }
    if let Some(tag) = &f.tag {
        q.push_str(&format!("&tags={}", urlencode(tag)));
    }
    if let Some(search) = &f.search {
        q.push_str(&format!(
            "&search={}&searchFields=title&searchFields=description",
            urlencode(search)
        ));
    }
    q
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaseList {
    pub cases: Vec<Case>,
    pub total: u64,
    pub truncated: bool,
}

/// One bounded peek: page until `limit + 1` rows are in hand or the server
/// runs out, then truncate.
pub async fn list(t: &Transport, f: &CaseFilter, limit: usize) -> Result<CaseList> {
    let mut cases = Vec::new();
    let mut total = 0;
    let mut page = 1;
    while cases.len() <= limit {
        let (batch, batch_total) = cases::find_page(t, &find_query(f, page, PAGE_SIZE)).await?;
        total = batch_total;
        let got = batch.len();
        cases.extend(batch);
        if got < PAGE_SIZE as usize {
            break;
        }
        page += 1;
    }
    let truncated = cases.len() > limit;
    cases.truncate(limit);
    Ok(CaseList {
        cases,
        total,
        truncated,
    })
}

/// The `--out` path: every page.
pub async fn export(t: &Transport, f: &CaseFilter) -> Result<Vec<Case>> {
    export_with_page_size(t, f, PAGE_SIZE).await
}

/// The paging loop with an explicit page size, exposed for tests.
pub async fn export_with_page_size(
    t: &Transport,
    f: &CaseFilter,
    per_page: u32,
) -> Result<Vec<Case>> {
    let mut all = Vec::new();
    let mut page = 1;
    loop {
        let (batch, _) = cases::find_page(t, &find_query(f, page, per_page)).await?;
        let got = batch.len();
        all.extend(batch);
        if got < per_page as usize {
            return Ok(all);
        }
        page += 1;
    }
}

pub async fn get_one(t: &Transport, id: &str) -> Result<Case> {
    cases::get(t, id).await
}
