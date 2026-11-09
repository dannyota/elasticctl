//! Inventory helpers.

use crate::diagnostics::{
    recording_error, safe_recording_error_summary, safe_recording_transport_error,
};
use crate::recorder::integration::metadata::metadata_nonempty_string;
use crate::recorder::markers::{
    INSTALLED_PACKAGE_INVENTORY_PATH, INTEGRATION_POLICY_DUP_ID, INTEGRATION_POLICY_ID,
    INTEGRATION_POLICY_PACKAGE, INTEGRATION_POLICY_PARENT_ID,
};
use elasticctl_core::urlencode;
use serde_json::{Value, json};
use std::collections::BTreeSet;

async fn require_absent_integration_policy(
    t: &elasticctl_core::Transport,
    id: &str,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/fleet/package_policies/{}?format=simplified",
            urlencode(id)
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: integration policy {id} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(safe_recording_transport_error(
            "checking integration policy absence failed",
            error,
        )),
    }
}

async fn require_absent_integration_policy_parent(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    match t
        .get(&format!(
            "/api/fleet/agent_policies/{}",
            urlencode(INTEGRATION_POLICY_PARENT_ID)
        ))
        .await
    {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: integration policy parent {INTEGRATION_POLICY_PARENT_ID} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == elasticctl_core::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(safe_recording_transport_error(
            "checking integration policy parent absence failed",
            error,
        )),
    }
}

pub(crate) async fn require_absent_integration_markers(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<()> {
    require_absent_integration_policy(t, INTEGRATION_POLICY_ID).await?;
    require_absent_integration_policy(t, INTEGRATION_POLICY_DUP_ID).await?;
    require_absent_integration_policy_parent(t).await
}

/// Decode an installed-package inventory into memory-only coordinates. Fleet
/// returns the last-item sort cursor even when the fixed one-page request is
/// complete, so completeness comes from the total and item count instead.
fn decode_installed_package_inventory(
    body: &Value,
) -> elasticctl_core::Result<BTreeSet<(String, String)>> {
    let envelope = body
        .as_object()
        .ok_or_else(|| recording_error("installed package inventory must be an object"))?;
    for key in envelope.keys() {
        if !matches!(
            key.as_str(),
            "items" | "total" | "searchAfter" | "searchExcluded"
        ) {
            return Err(recording_error(
                "installed package inventory contains an unknown envelope field",
            ));
        }
    }
    let items = envelope
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| recording_error("installed package inventory items must be an array"))?;
    let total = envelope
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| recording_error("installed package inventory total must be unsigned"))?;
    if total > 1000 {
        return Err(recording_error(
            "installed package inventory total exceeds the one-page limit",
        ));
    }
    if items.len() as u64 != total {
        return Err(recording_error(
            "installed package inventory item count does not match total",
        ));
    }
    if let Some(cursor) = envelope.get("searchAfter") {
        let valid = matches!(cursor, Value::Array(values)
        if values.len() <= 2
            && values.iter().all(|value| {
                value.is_string() || value.is_number() || value.is_boolean()
            }));
        if !valid {
            return Err(recording_error(
                "installed package inventory searchAfter must contain at most two scalar sort values",
            ));
        }
    }
    if let Some(search_excluded) = envelope.get("searchExcluded")
        && search_excluded.as_u64() != Some(0)
    {
        return Err(recording_error(
            "installed package inventory searchExcluded must be unsigned zero",
        ));
    }

    let mut names = BTreeSet::new();
    let mut coordinates = BTreeSet::new();
    for item in items {
        let item = item
            .as_object()
            .ok_or_else(|| recording_error("installed package inventory items must be objects"))?;
        let name = metadata_nonempty_string(item, "name", "installed package inventory item")?;
        if item.get("status").and_then(Value::as_str) != Some("installed") {
            return Err(recording_error(
                "installed package inventory item status must be installed",
            ));
        }
        let version =
            metadata_nonempty_string(item, "version", "installed package inventory item")?;
        if !names.insert(name.clone()) || !coordinates.insert((name, version)) {
            return Err(recording_error(
                "installed package inventory contains duplicate package coordinates",
            ));
        }
    }
    Ok(coordinates)
}

pub(crate) fn require_matching_inventory(
    baseline: &BTreeSet<(String, String)>,
    current: &BTreeSet<(String, String)>,
) -> elasticctl_core::Result<()> {
    if baseline == current {
        Ok(())
    } else {
        Err(recording_error(
            "installed package inventory differs from the recording baseline",
        ))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SystemPackageStatus {
    registry_version: String,
    pub(crate) version: String,
    pub(crate) installed: bool,
}

pub(crate) fn decode_system_package_status(
    body: &Value,
) -> elasticctl_core::Result<SystemPackageStatus> {
    let item = body
        .get("item")
        .and_then(Value::as_object)
        .ok_or_else(|| recording_error("system package status must contain an item object"))?;
    if metadata_nonempty_string(item, "name", "system package status")?
        != INTEGRATION_POLICY_PACKAGE
    {
        return Err(recording_error(
            "system package status did not name the system package",
        ));
    }
    let registry_version = metadata_nonempty_string(item, "version", "system package status")?;
    match item.get("status").and_then(Value::as_str) {
        Some("installed") => {
            let installation = item
                .get("installationInfo")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    recording_error("installed system package status lacks installationInfo")
                })?;
            let version = metadata_nonempty_string(
                installation,
                "version",
                "installed system package status",
            )?;
            Ok(SystemPackageStatus {
                registry_version,
                version,
                installed: true,
            })
        }
        Some("not_installed") => {
            if !matches!(item.get("installationInfo"), None | Some(Value::Null)) {
                return Err(recording_error(
                    "not_installed system package status has installationInfo",
                ));
            }
            Ok(SystemPackageStatus {
                version: registry_version.clone(),
                registry_version,
                installed: false,
            })
        }
        _ => Err(recording_error(
            "system package status must be installed or not_installed",
        )),
    }
}

/// `package_system` is an integration-recorder-only fixture. Build it solely
/// from the strict status decoder so registry metadata such as `latestVersion`
/// never reaches a public fixture.
pub(crate) fn reduce_system_package_status(status: &SystemPackageStatus) -> Value {
    let mut item = json!({
        "name": INTEGRATION_POLICY_PACKAGE,
        "version": status.registry_version,
        "status": if status.installed { "installed" } else { "not_installed" },
    });
    if status.installed {
        item["installationInfo"] = json!({"version": status.version});
    }
    item
}

pub(crate) async fn read_installed_package_inventory(
    t: &elasticctl_core::Transport,
) -> elasticctl_core::Result<BTreeSet<(String, String)>> {
    let body = t.get(INSTALLED_PACKAGE_INVENTORY_PATH).await?;
    decode_installed_package_inventory(&body)
}

pub(crate) async fn require_unchanged_installed_package_inventory(
    t: &elasticctl_core::Transport,
    baseline: &BTreeSet<(String, String)>,
    context: &'static str,
) -> elasticctl_core::Result<()> {
    let current = read_installed_package_inventory(t)
        .await
        .map_err(|error| safe_recording_transport_error(context, error))?;
    require_matching_inventory(baseline, &current)
}

pub(crate) fn require_installed_integration_package_metadata(
    metadata: &Value,
) -> elasticctl_core::Result<()> {
    if metadata
        .get("item")
        .and_then(Value::as_object)
        .and_then(|item| item.get("status"))
        .and_then(Value::as_str)
        == Some("installed")
    {
        Ok(())
    } else {
        Err(recording_error(
            "refusing to record: system package metadata must be installed",
        ))
    }
}

pub(crate) async fn reread_system_package_before_integration_policy_create(
    t: &elasticctl_core::Transport,
    baseline_inventory: &BTreeSet<(String, String)>,
    expected_version: &str,
) -> elasticctl_core::Result<()> {
    let status_body = t
        .get(&format!(
            "/api/fleet/epm/packages/{INTEGRATION_POLICY_PACKAGE}"
        ))
        .await
        .map_err(|error| {
            safe_recording_transport_error(
                "rereading system package status before integration policy create failed",
                error,
            )
        })?;
    let status = decode_system_package_status(&status_body)?;
    if !status.installed || status.version != expected_version {
        return Err(recording_error(
            "refusing to record: system package must remain installed at the baseline version before integration policy create",
        ));
    }

    let current_inventory = read_installed_package_inventory(t).await.map_err(|error| {
        safe_recording_transport_error(
            "rereading installed package inventory before integration policy create failed",
            error,
        )
    })?;
    require_matching_inventory(baseline_inventory, &current_inventory).map_err(|_| {
        recording_error(
            "refusing to record: installed package inventory changed before integration policy create",
        )
    })
}

pub(crate) fn combine_package_policy_attempt_and_inventory_errors(
    attempt_context: &'static str,
    attempt: &elasticctl_core::Error,
    observation: &elasticctl_core::Error,
) -> elasticctl_core::Error {
    recording_error(format!(
        "{attempt_context}: {}; installed package inventory observation also failed: {}",
        safe_recording_error_summary(attempt),
        safe_recording_error_summary(observation),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{
        INTEGRATION_POLICY_ID, INTEGRATION_POLICY_PACKAGE, INTEGRATION_POLICY_PARENT_ID,
    };
    use crate::recorder::test_support::{installed_system_status, mock_transport};
    use serde_json::json;

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn strict_system_status_reducer_drops_latest_version_metadata() {
        let mut body = installed_system_status();
        body["item"]["latestVersion"] = json!({
            "host": "private.example",
            "token": "private-registry-token"
        });

        let status = decode_system_package_status(&body).expect("validated system status");
        let reduced = reduce_system_package_status(&status);

        assert_eq!(
            reduced,
            json!({
                "name": INTEGRATION_POLICY_PACKAGE,
                "version": "2.0.0",
                "status": "installed",
                "installationInfo": {"version": "2.0.0"}
            })
        );
        let encoded = reduced.to_string();
        assert!(!encoded.contains("private.example"));
        assert!(!encoded.contains("private-registry-token"));
    }

    #[test]
    fn installed_package_inventory_is_strict_and_order_independent() {
        let first = json!({
            "items": [
                {"name": "system", "status": "installed", "version": "2.0.0"},
                {"name": "endpoint", "status": "installed", "version": "8.4.0"}
            ],
            "total": 2,
            "searchAfter": ["system"],
            "searchExcluded": 0
        });
        let empty_cursor = json!({
            "items": [
                {"name": "system", "status": "installed", "version": "2.0.0"},
                {"name": "endpoint", "status": "installed", "version": "8.4.0"}
            ],
            "total": 2,
            "searchAfter": []
        });
        let reordered = json!({
            "items": [
                {"name": "endpoint", "status": "installed", "version": "8.4.0"},
                {"name": "system", "status": "installed", "version": "2.0.0"}
            ],
            "total": 2
        });
        let expected = std::collections::BTreeSet::from([
            ("endpoint".to_string(), "8.4.0".to_string()),
            ("system".to_string(), "2.0.0".to_string()),
        ]);

        assert_eq!(
            decode_installed_package_inventory(&first).expect("first inventory"),
            expected
        );
        assert_eq!(
            decode_installed_package_inventory(&reordered).expect("reordered inventory"),
            expected
        );
        assert_eq!(
            decode_installed_package_inventory(&empty_cursor).expect("empty cursor inventory"),
            expected
        );

        for cursor in [json!(["system", true]), json!([42, false])] {
            assert_eq!(
                decode_installed_package_inventory(&json!({
                    "items": [],
                    "total": 0,
                    "searchAfter": cursor,
                }))
                .expect("valid cursor inventory"),
                std::collections::BTreeSet::new(),
            );
        }

        for malformed in [
            json!({"items": [], "total": 1001}),
            json!({"items": [], "total": 1}),
            json!({"items": [], "total": 0, "searchAfter": ["first", "second", "third"]}),
            json!({"items": [], "total": 0, "searchAfter": [null]}),
            json!({"items": [], "total": 0, "searchAfter": [[]]}),
            json!({"items": [], "total": 0, "searchAfter": [{}]}),
            json!({"items": [], "total": 0, "searchAfter": null}),
            json!({"items": [], "total": 0, "searchAfter": ""}),
            json!({"items": [], "total": 0, "searchAfter": {}}),
            json!({"items": [], "total": 0, "searchAfter": 0}),
            json!({"items": [], "total": 0, "searchAfter": false}),
            json!({"items": [], "total": 0, "searchExcluded": true}),
            json!({"items": [], "total": 0, "searchExcluded": false}),
            json!({"items": [], "total": 0, "searchExcluded": null}),
            json!({"items": [], "total": 0, "searchExcluded": "0"}),
            json!({"items": [], "total": 0, "searchExcluded": []}),
            json!({"items": [], "total": 0, "searchExcluded": {}}),
            json!({"items": [], "total": 0, "searchExcluded": 1}),
            json!({"items": [], "total": 0, "searchExcluded": -1}),
            json!({"items": [], "total": 0, "searchExcluded": 0.5}),
            json!({"items": [], "total": 0, "searchExcluded": 0.0}),
            json!({"items": [], "total": 0, "unexpected": true}),
            json!({"items": [{"name": "", "status": "installed", "version": "2.0.0"}], "total": 1}),
            json!({"items": [{"name": "system", "status": "not_installed", "version": "2.0.0"}], "total": 1}),
            json!({"items": [{"name": "system", "status": "installed", "version": ""}], "total": 1}),
            json!({"items": [
                {"name": "system", "status": "installed", "version": "2.0.0"},
                {"name": "system", "status": "installed", "version": "2.1.0"}
            ], "total": 2}),
        ] {
            assert!(
                decode_installed_package_inventory(&malformed).is_err(),
                "malformed inventory must fail: {malformed}"
            );
        }
    }

    #[tokio::test]
    async fn integration_marker_preflight_refuses_existing_integration_before_parent_create() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/fleet/package_policies/{INTEGRATION_POLICY_ID}"
            )))
            .and(query_param("format", "simplified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {}})))
            .expect(1)
            .mount(&server)
            .await;
        let transport = mock_transport(&server);

        let error = require_absent_integration_markers(&transport)
            .await
            .expect_err("an existing marker integration must stop recording");

        assert!(error.message.contains(INTEGRATION_POLICY_ID));
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().all(|request| {
            request.url.path()
                != format!("/api/fleet/agent_policies/{INTEGRATION_POLICY_PARENT_ID}")
        }));
    }
}
