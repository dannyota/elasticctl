//! Private Fleet reads shared by conformance tooling and live tests.
//!
//! Fleet list payloads contain unrelated policies, audit metadata, and package
//! registry data. This module keeps only marker ids and package coordinates.

use std::collections::{BTreeMap, BTreeSet};

use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Map, Value};

const MARKER_PREFIX: &str = "elasticctl-live-";
const PAGE_SIZE: u64 = 1000;
const INSTALLED_PACKAGES: &str = "/api/fleet/epm/packages/installed?perPage=1000&sortOrder=asc";
const AGENT_POLICIES: &str = "/api/fleet/agent_policies";
const INTEGRATION_POLICIES: &str = "/api/fleet/package_policies";

pub type PackageInventory = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetState {
    pub agent_policies: BTreeSet<String>,
    pub integration_policies: BTreeSet<String>,
    pub packages: PackageInventory,
}

impl FleetState {
    pub async fn capture(transport: &Transport) -> Result<Self> {
        Ok(Self {
            agent_policies: capture_policy_ids(transport, AGENT_POLICIES, false).await?,
            integration_policies: capture_policy_ids(transport, INTEGRATION_POLICIES, true).await?,
            packages: installed_packages(transport).await?,
        })
    }

    pub fn markers_empty(&self) -> bool {
        self.agent_policies.is_empty() && self.integration_policies.is_empty()
    }
}

pub async fn installed_packages(transport: &Transport) -> Result<PackageInventory> {
    let body = transport.get(INSTALLED_PACKAGES).await?;
    let envelope = body
        .as_object()
        .ok_or_else(|| invalid("invalid Fleet installed-package inventory"))?;
    if !envelope.keys().all(|key| {
        matches!(
            key.as_str(),
            "items" | "total" | "searchAfter" | "searchExcluded"
        )
    }) {
        return Err(invalid("invalid Fleet installed-package inventory"));
    }
    let items = envelope
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("invalid Fleet installed-package inventory"))?;
    let total = envelope
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("invalid Fleet installed-package inventory"))?;
    if total > PAGE_SIZE
        || items.len() as u64 != total
        || !valid_cursor(envelope.get("searchAfter"))
    {
        return Err(invalid("invalid Fleet installed-package inventory"));
    }
    if envelope
        .get("searchExcluded")
        .is_some_and(|value| value.as_u64() != Some(0))
    {
        return Err(invalid("invalid Fleet installed-package inventory"));
    }

    let mut packages = PackageInventory::new();
    for item in items {
        let item = item
            .as_object()
            .ok_or_else(|| invalid("invalid Fleet installed-package inventory"))?;
        let name = non_empty(item, "name")?;
        let version = non_empty(item, "version")?;
        if item.get("status").and_then(Value::as_str) != Some("installed")
            || packages.insert(name, version).is_some()
        {
            return Err(invalid("invalid Fleet installed-package inventory"));
        }
    }
    Ok(packages)
}

async fn capture_policy_ids(
    transport: &Transport,
    endpoint: &str,
    simplified: bool,
) -> Result<BTreeSet<String>> {
    let mut page_number = 1;
    let mut expected_total = None;
    let mut seen_ids = BTreeSet::new();
    let mut markers = BTreeSet::new();

    loop {
        let format = if simplified { "&format=simplified" } else { "" };
        let body = transport
            .get(&format!(
                "{endpoint}?page={page_number}&perPage={PAGE_SIZE}&sortField=created_at&sortOrder=asc{format}"
            ))
            .await?;
        let page = decode_policy_page(&body)?;
        if page.page != page_number
            || page.per_page != PAGE_SIZE
            || page.items.len() as u64 > PAGE_SIZE
        {
            return Err(invalid("invalid Fleet policy page"));
        }
        match expected_total {
            Some(total) if total != page.total => return Err(invalid("invalid Fleet policy page")),
            Some(_) => {}
            None => expected_total = Some(page.total),
        }

        let page_len = page.items.len() as u64;
        for item in page.items {
            let id = non_empty(&item, "id")?;
            let name = non_empty(&item, "name")?;
            if !seen_ids.insert(id.clone()) {
                return Err(invalid("invalid Fleet policy page"));
            }
            if id.starts_with(MARKER_PREFIX) || name.starts_with(MARKER_PREFIX) {
                markers.insert(id);
            }
        }

        let total = expected_total.expect("first page establishes total");
        if seen_ids.len() as u64 >= total {
            if seen_ids.len() as u64 == total {
                return Ok(markers);
            }
            return Err(invalid("invalid Fleet policy page"));
        }
        if page_len != PAGE_SIZE {
            return Err(invalid("invalid Fleet policy page"));
        }
        page_number += 1;
    }
}

struct PolicyPage {
    items: Vec<Map<String, Value>>,
    page: u64,
    per_page: u64,
    total: u64,
}

fn decode_policy_page(body: &Value) -> Result<PolicyPage> {
    let envelope = body
        .as_object()
        .ok_or_else(|| invalid("invalid Fleet policy page"))?;
    if !envelope
        .keys()
        .all(|key| matches!(key.as_str(), "items" | "page" | "perPage" | "total"))
    {
        return Err(invalid("invalid Fleet policy page"));
    }
    let items = envelope
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("invalid Fleet policy page"))?
        .iter()
        .map(|item| {
            item.as_object()
                .cloned()
                .ok_or_else(|| invalid("invalid Fleet policy page"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PolicyPage {
        items,
        page: envelope
            .get("page")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("invalid Fleet policy page"))?,
        per_page: envelope
            .get("perPage")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("invalid Fleet policy page"))?,
        total: envelope
            .get("total")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("invalid Fleet policy page"))?,
    })
}

fn valid_cursor(value: Option<&Value>) -> bool {
    value.is_none_or(|value| {
        matches!(value, Value::Array(values)
            if values.len() <= 2
                && values.iter().all(|value| value.is_string() || value.is_number() || value.is_boolean()))
    })
}

fn non_empty(item: &Map<String, Value>, field: &str) -> Result<String> {
    item.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid("invalid Fleet response"))
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::Http, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_core::{Profile, Transport};
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn transport(server: &MockServer) -> Transport {
        Transport::new(&Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("test".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 5,
        })
        .expect("mock transport")
    }

    async fn inventory(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .and(query_param("perPage", "1000"))
            .and(query_param("sortOrder", "asc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn installed_packages_rejects_malformed_inventory_without_values() {
        let server = MockServer::start().await;
        inventory(&server, json!({"items": "not-an-array", "total": 1})).await;
        let error = installed_packages(&transport(&server))
            .await
            .expect_err("malformed inventory must fail");
        assert_eq!(error.kind, elasticctl_core::ErrorKind::Http);
        assert!(!error.message.contains("not-an-array"));
    }

    #[tokio::test]
    async fn installed_packages_rejects_duplicate_names_and_uninstalled_rows() {
        let server = MockServer::start().await;
        inventory(
            &server,
            json!({
                "items": [
                    {"name": "system", "version": "1", "status": "installed"},
                    {"name": "system", "version": "2", "status": "installed"}
                ],
                "total": 2
            }),
        )
        .await;
        assert!(installed_packages(&transport(&server)).await.is_err());

        let server = MockServer::start().await;
        inventory(
            &server,
            json!({
                "items": [{"name": "system", "version": "1", "status": "not_installed"}],
                "total": 1
            }),
        )
        .await;
        assert!(installed_packages(&transport(&server)).await.is_err());
    }

    #[tokio::test]
    async fn installed_packages_rejects_short_reads_and_invalid_cursors() {
        let server = MockServer::start().await;
        inventory(&server, json!({"items": [], "total": 1})).await;
        assert!(installed_packages(&transport(&server)).await.is_err());

        let server = MockServer::start().await;
        inventory(
            &server,
            json!({"items": [], "total": 0, "searchAfter": ["one", "two", "three"]}),
        )
        .await;
        assert!(installed_packages(&transport(&server)).await.is_err());
    }

    #[tokio::test]
    async fn installed_packages_is_order_independent() {
        let server = MockServer::start().await;
        inventory(
            &server,
            json!({
                "items": [
                    {"name": "z", "version": "2", "status": "installed"},
                    {"name": "a", "version": "1", "status": "installed"}
                ],
                "total": 2,
                "searchAfter": ["z"]
            }),
        )
        .await;
        assert_eq!(
            installed_packages(&transport(&server)).await.unwrap(),
            PackageInventory::from([
                ("a".to_string(), "1".to_string()),
                ("z".to_string(), "2".to_string()),
            ])
        );
    }

    #[tokio::test]
    async fn capture_retains_only_marker_ids_or_names_for_both_policy_kinds() {
        let server = MockServer::start().await;
        inventory(&server, json!({"items": [], "total": 0})).await;
        for endpoint in ["agent_policies", "package_policies"] {
            Mock::given(method("GET"))
                .and(path(format!("/api/fleet/{endpoint}")))
                .and(query_param("page", "1"))
                .and(query_param("perPage", "1000"))
                .and(query_param("sortField", "created_at"))
                .and(query_param("sortOrder", "asc"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [
                        {"id": "elasticctl-live-id", "name": "ordinary"},
                        {"id": "ordinary-id", "name": "elasticctl-live-name"},
                        {"id": "ordinary", "name": "ordinary"}
                    ],
                    "page": 1,
                    "perPage": 1000,
                    "total": 3
                })))
                .mount(&server)
                .await;
        }
        let state = FleetState::capture(&transport(&server)).await.unwrap();
        assert_eq!(state.agent_policies.len(), 2);
        assert_eq!(state.integration_policies.len(), 2);
        assert!(!state.markers_empty());
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| {
                    request.url.path() == "/api/fleet/package_policies"
                        && request
                            .url
                            .query_pairs()
                            .any(|(name, value)| name == "format" && value == "simplified")
                })
        );
    }

    #[tokio::test]
    async fn capture_rejects_policy_paging_contradictions_for_both_kinds() {
        for (endpoint, simplified) in [("agent_policies", false), ("package_policies", true)] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/api/fleet/{endpoint}")))
                .and(query_param("page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "page": 2, "perPage": 1000, "total": 0
                })))
                .mount(&server)
                .await;
            assert!(
                capture_policy_ids(&transport(&server), endpoint, simplified)
                    .await
                    .is_err()
            );
        }
    }
}
