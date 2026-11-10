//! Marker identities, cleanup registration, and provisioning for the shared
//! objects and the two object sets of design section 12.3. The maximum-work
//! set makes every plan send its maximum; the degradation set makes parts
//! degrade. No rule of the maximum-work set names a missing list, an
//! exclusion, or an unknown package.

use std::path::Path;

use elasticctl_api::model::{ListKey, Rule};
use elasticctl_core::{Flavor, Transport};
use serde_json::{Value, json};

use super::fill::FILL_PREFIX;
use crate::mcp_smoke::create_registered_case;
use crate::{
    LIVE_PREFIX, LIVE_TAG, LiveCleanup, TRIAGE_POLL_ATTEMPTS, TRIAGE_POLL_INTERVAL, TestResult,
    assert_single_import_report, checked, cli, current_rfc3339, data_view_artifact, json_output,
    open_marker_rule_alerts_query, refresh_content_index, unique_name, write_json_artifact,
};

/// Packages on rule W, `system` first. Each is a real registry package, so
/// every status read succeeds and the integrations part stays complete.
pub(crate) const WORK_PACKAGES: [&str; 8] = [
    "system",
    "endpoint",
    "windows",
    "apache",
    "nginx",
    "mysql",
    "aws",
    "network_traffic",
];
pub(crate) const PACKAGE_VERSION: &str = "^1.0.0";
pub(crate) const WORK_WILDCARDS: usize = 15;
pub(crate) const WORK_LISTS: usize = 5;
pub(crate) const WORK_CASES: usize = 5;
/// The case description `validate_case_row` expects of an owned case.
pub(crate) const CASE_DESCRIPTION: &str = "MCP smoke case";
const RULE_DESCRIPTION: &str = "Created by elasticctl's live conformance suite. Safe to delete.";

/// A marker exception list and the items it holds.
#[derive(Clone, Debug)]
pub(crate) struct ListFixture {
    pub(crate) list_id: String,
    pub(crate) item_ids: Vec<String>,
}

/// Every name the contract writes or reads, fixed before the first write.
#[derive(Clone, Debug)]
pub(crate) struct ComposeIds {
    pub(crate) index: String,
    pub(crate) data_view: String,
    pub(crate) work_lists: Vec<ListFixture>,
    pub(crate) work_rule: String,
    pub(crate) work_wildcards: Vec<String>,
    pub(crate) case_titles: Vec<String>,
    pub(crate) degraded_list: ListFixture,
    /// A list key that is never created.
    pub(crate) missing_list: String,
    pub(crate) degraded_rule: String,
    pub(crate) exclusion: String,
    /// A package name in the registry grammar that no registry holds.
    pub(crate) unknown_package: String,
    pub(crate) view_rule: String,
    pub(crate) fill_nonce: String,
}

/// What provisioning learned from the stack.
#[derive(Clone, Debug)]
pub(crate) struct Provisioned {
    pub(crate) flavor: Flavor,
    pub(crate) work_alert: String,
    pub(crate) degraded_alert: String,
    /// `(case id, title)` for the five cases holding the rule W alert.
    pub(crate) cases: Vec<(String, String)>,
    pub(crate) prebuilt_total: u64,
}

impl ComposeIds {
    pub(crate) fn new() -> Self {
        let work_lists = (1..=WORK_LISTS)
            .map(|n| {
                let items = if n == 1 { 2 } else { 1 };
                ListFixture {
                    list_id: unique_name(&format!("compose-work-list-{n}")),
                    item_ids: (1..=items)
                        .map(|i| unique_name(&format!("compose-work-item-{n}-{i}")))
                        .collect(),
                }
            })
            .collect();
        Self {
            index: unique_name("compose-index"),
            data_view: unique_name("compose-data-view"),
            work_lists,
            work_rule: unique_name("compose-rule-w"),
            work_wildcards: (1..=WORK_WILDCARDS)
                .map(|n| format!("{}*", unique_name(&format!("compose-absent-{n:02}"))))
                .collect(),
            case_titles: (1..=WORK_CASES)
                .map(|n| unique_name(&format!("compose-case-{n}")))
                .collect(),
            degraded_list: ListFixture {
                list_id: unique_name("compose-degraded-list"),
                item_ids: vec![unique_name("compose-degraded-item")],
            },
            missing_list: unique_name("compose-missing-list"),
            degraded_rule: unique_name("compose-rule-d"),
            exclusion: format!("-{}*", unique_name("compose-excluded")),
            unknown_package: unique_name("compose-package"),
            view_rule: unique_name("compose-rule-v"),
            fill_nonce: fill_nonce(),
        }
    }

    /// The display name differs from the `rule_id`, so a by-name selector
    /// takes the three-request selector path.
    pub(crate) fn name_of(rule_id: &str) -> String {
        format!("{rule_id} rule")
    }

    pub(crate) fn work_name(&self) -> String {
        Self::name_of(&self.work_rule)
    }

    /// The 16 patterns of rule W: the marker index, then 15 wildcards.
    pub(crate) fn work_patterns(&self) -> Vec<String> {
        std::iter::once(self.index.clone())
            .chain(self.work_wildcards.iter().cloned())
            .collect()
    }

    pub(crate) fn created_lists(&self) -> impl Iterator<Item = &ListFixture> {
        self.work_lists
            .iter()
            .chain(std::iter::once(&self.degraded_list))
    }

    /// Every object name a provisioning step writes or a rule refers to.
    pub(crate) fn named_objects(&self) -> Vec<String> {
        let mut names = vec![self.index.clone(), self.data_view.clone()];
        for list in self.created_lists() {
            names.push(list.list_id.clone());
            names.extend(list.item_ids.iter().cloned());
        }
        for rule in [&self.work_rule, &self.degraded_rule, &self.view_rule] {
            names.push(rule.clone());
            names.push(Self::name_of(rule));
        }
        names.extend(self.work_wildcards.iter().cloned());
        names.extend(self.case_titles.iter().cloned());
        names.push(self.missing_list.clone());
        names.push(self.exclusion.clone());
        names.push(self.unknown_package.clone());
        names.push(super::fill::fill_prefix(&self.fill_nonce));
        names
    }
}

/// Nanoseconds since the epoch, the clock `unique_name` also uses.
fn fill_nonce() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_nanos()
        .to_string()
}

/// A marker name: the live prefix, an exclusion of one, or the fill prefix.
pub(crate) fn is_marked(name: &str) -> bool {
    let name = name.strip_prefix('-').unwrap_or(name);
    (name.starts_with(LIVE_PREFIX) && name.len() > LIVE_PREFIX.len())
        || (name.starts_with(FILL_PREFIX) && name.len() > FILL_PREFIX.len())
}

/// Register every written object before the first write. The data-view
/// default is registered because a data-view create may set it when the
/// space has none.
pub(crate) fn register_compose(
    cleanup: &mut LiveCleanup,
    ids: &ComposeIds,
    original_default: Option<String>,
) {
    cleanup.index(ids.index.clone());
    cleanup.restore_default_data_view(original_default);
    cleanup.data_view(ids.data_view.clone());
    for list in ids.created_lists() {
        cleanup.list(list.list_id.clone());
        for item in &list.item_ids {
            cleanup.item(list.list_id.clone(), item.clone());
        }
    }
    for rule in [&ids.work_rule, &ids.degraded_rule, &ids.view_rule] {
        cleanup.rule(rule.clone());
    }
    for rule in [&ids.work_rule, &ids.degraded_rule] {
        cleanup.alert_rule(rule.clone());
    }
    for title in &ids.case_titles {
        cleanup.case_scope(title.clone(), LIVE_TAG);
    }
}

/// Names a write step would create that cleanup does not own.
pub(crate) fn unregistered(ids: &ComposeIds, cleanup: &LiveCleanup) -> Vec<String> {
    let mut missing = Vec::new();
    let mut need = |owned: bool, name: &str| {
        if !owned {
            missing.push(name.to_string());
        }
    };
    need(cleanup.indices.contains(&ids.index), &ids.index);
    need(cleanup.data_views.contains(&ids.data_view), &ids.data_view);
    need(cleanup.default_data_view.is_some(), "data-view default");
    for list in ids.created_lists() {
        need(cleanup.lists.contains(&list.list_id), &list.list_id);
        for item in &list.item_ids {
            need(
                cleanup
                    .items
                    .contains(&(list.list_id.clone(), item.clone())),
                item,
            );
        }
    }
    for rule in [&ids.work_rule, &ids.degraded_rule, &ids.view_rule] {
        need(cleanup.rules.contains(rule), rule);
    }
    for rule in [&ids.work_rule, &ids.degraded_rule] {
        need(cleanup.alert_rules.contains(rule), rule);
    }
    for title in &ids.case_titles {
        need(
            cleanup
                .case_scopes
                .contains(&(title.clone(), LIVE_TAG.to_string())),
            title,
        );
    }
    missing
}

/// An exception bundle: one list and every item it holds. No item matches a
/// marker document, so rule W still alerts.
pub(crate) fn list_bundle(list: &ListFixture) -> String {
    let mut lines = vec![json!({
        "list_id": list.list_id,
        "type": "detection",
        "name": format!("{} exception list", list.list_id),
        "description": RULE_DESCRIPTION,
        "namespace_type": "single",
        "tags": [LIVE_TAG],
    })];
    for item in &list.item_ids {
        lines.push(json!({
            "item_id": item,
            "list_id": list.list_id,
            "type": "simple",
            "name": format!("{item} exception"),
            "description": RULE_DESCRIPTION,
            "namespace_type": "single",
            "entries": [{
                "field": "host.name",
                "operator": "included",
                "type": "match",
                "value": item,
            }],
            "tags": [LIVE_TAG],
        }));
    }
    lines.iter().map(|line| format!("{line}\n")).collect()
}

fn base_rule(rule_id: &str, enabled: bool) -> Value {
    json!({
        "rule_id": rule_id,
        "name": ComposeIds::name_of(rule_id),
        "description": RULE_DESCRIPTION,
        "type": "query",
        "language": "kuery",
        "query": format!("marker: \"{LIVE_TAG}\""),
        "severity": "low",
        "risk_score": 21,
        "enabled": enabled,
        "from": "now-10m",
        "interval": "1m",
        "tags": [LIVE_TAG],
    })
}

fn reference(list_id: &str, pointer: &str) -> Value {
    json!({"id": pointer, "list_id": list_id, "namespace_type": "single", "type": "detection"})
}

/// Rule W. `pointers` are the saved-object ids of the five work lists, in
/// list order; the create route requires them.
pub(crate) fn work_rule_body(ids: &ComposeIds, pointers: &[String]) -> Value {
    let mut rule = base_rule(&ids.work_rule, true);
    rule["index"] = json!(ids.work_patterns());
    rule["threat"] = json!([{
        "framework": "MITRE ATT&CK",
        "tactic": {
            "id": "TA0002",
            "name": "Execution",
            "reference": "https://attack.mitre.org/tactics/TA0002/",
        },
        "technique": [{
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "reference": "https://attack.mitre.org/techniques/T1059/",
            "subtechnique": [{
                "id": "T1059.001",
                "name": "PowerShell",
                "reference": "https://attack.mitre.org/techniques/T1059/001/",
            }],
        }],
    }]);
    rule["exceptions_list"] = Value::Array(
        ids.work_lists
            .iter()
            .zip(pointers)
            .map(|(list, pointer)| reference(&list.list_id, pointer))
            .collect(),
    );
    rule["related_integrations"] = Value::Array(
        WORK_PACKAGES
            .iter()
            .map(|package| json!({"package": package, "version": PACKAGE_VERSION}))
            .collect(),
    );
    rule
}

/// Rule D: one existing list and one missing list key, an exclusion, and one
/// package that no registry holds.
pub(crate) fn degraded_rule_body(ids: &ComposeIds, pointer: &str) -> Value {
    let mut rule = base_rule(&ids.degraded_rule, true);
    rule["index"] = json!([ids.index, ids.exclusion]);
    rule["exceptions_list"] = json!([
        reference(&ids.degraded_list.list_id, pointer),
        reference(&ids.missing_list, &ids.missing_list),
    ]);
    rule["related_integrations"] =
        json!([{"package": ids.unknown_package, "version": PACKAGE_VERSION}]);
    rule
}

/// Rule V reads through the marker data view and stays disabled.
pub(crate) fn view_rule_body(ids: &ComposeIds) -> Value {
    let mut rule = base_rule(&ids.view_rule, false);
    rule["data_view_id"] = json!(ids.data_view);
    rule
}

/// Write both object sets. Refuses to write when any name is unregistered.
pub(crate) fn provision_live(
    config: &Path,
    scratch: &Path,
    runtime: &tokio::runtime::Runtime,
    transport: &Transport,
    ids: &ComposeIds,
    cleanup: &mut LiveCleanup,
) -> TestResult<Provisioned> {
    if !unregistered(ids, cleanup).is_empty() {
        return Err("Compose provisioning found an unregistered object.".to_string());
    }
    if !transport.has_es_url() {
        return Err("The compose contract needs an Elasticsearch URL.".to_string());
    }
    let flavor = runtime
        .block_on(transport.capabilities())
        .map_err(|e| format!("Compose probe failed: {}.", e.kind.as_str()))?
        .flavor;

    // Shared: the marker index with documents, then a data view over it.
    runtime.block_on(seed_index(transport, &ids.index))?;
    import_data_view(config, scratch, &ids.data_view, &ids.index)?;

    // Lists: the five work lists, then the degradation list.
    for list in ids.created_lists() {
        import_list(config, scratch, list)?;
    }

    // Rules W, D, and V, each through the create route.
    runtime.block_on(async {
        let mut work = Vec::with_capacity(WORK_LISTS);
        for list in &ids.work_lists {
            work.push(list_pointer(transport, &list.list_id).await?);
        }
        let degraded = list_pointer(transport, &ids.degraded_list.list_id).await?;
        create_rule(transport, work_rule_body(ids, &work)).await?;
        create_rule(transport, degraded_rule_body(ids, &degraded)).await?;
        create_rule(transport, view_rule_body(ids)).await
    })?;

    let work_alert = runtime.block_on(wait_for_alert(transport, &ids.work_rule))?;
    let degraded_alert = runtime.block_on(wait_for_alert(transport, &ids.degraded_rule))?;

    // Five cases, each holding the rule W alert. The rule D alert stays in
    // no case.
    let mut cases = Vec::with_capacity(WORK_CASES);
    for title in &ids.case_titles {
        let id = create_registered_case(cleanup, title, |_| {
            runtime.block_on(create_case(transport, title))
        })?;
        runtime.block_on(attach_alert(transport, &id, &work_alert))?;
        cases.push((id, title.clone()));
    }

    let prebuilt_total = runtime.block_on(prebuilt_total(transport))?;
    Ok(Provisioned {
        flavor,
        work_alert,
        degraded_alert,
        cases,
        prebuilt_total,
    })
}

async fn seed_index(transport: &Transport, index: &str) -> TestResult {
    for seq in 1..=3_i64 {
        transport
            .post_absolute_es(
                &format!("/{index}/_doc?refresh=wait_for"),
                &json!({
                    "@timestamp": current_rfc3339(),
                    "seq": seq,
                    "message": format!("elasticctl MCP compose {seq}"),
                    "marker": LIVE_TAG,
                }),
            )
            .await
            .map_err(|_| "Compose marker document could not be indexed.".to_string())?;
    }
    refresh_content_index(transport, index)
        .await
        .map_err(|_| "Compose marker index could not be refreshed.".to_string())
}

fn import_data_view(config: &Path, scratch: &Path, id: &str, index: &str) -> TestResult {
    let path = scratch.join("compose-data-view.json");
    write_json_artifact(&path, &data_view_artifact(id, index), "compose data view")
        .map_err(|_| "Compose data view could not be written.".to_string())?;
    let out = checked(
        cli(config)
            .args(["data-views", "import", "--path"])
            .arg(&path)
            .args(["--yes", "--json"]),
        "compose data-view import",
    )
    .map_err(|_| "Compose data-view import failed.".to_string())?;
    let report = json_output(&out, "compose data-view import")
        .map_err(|_| "Compose data-view import returned invalid JSON.".to_string())?;
    assert_single_import_report(&report, id, "compose data-view import")
        .map_err(|_| "Compose data-view import returned an invalid report.".to_string())
}

fn import_list(config: &Path, scratch: &Path, list: &ListFixture) -> TestResult {
    let path = scratch.join(format!("{}.ndjson", list.list_id));
    std::fs::write(&path, list_bundle(list))
        .map_err(|_| "Compose exception bundle could not be written.".to_string())?;
    checked(
        cli(config)
            .args(["exceptions", "import", "--path"])
            .arg(&path)
            .arg("--yes"),
        "compose exception import",
    )
    .map(|_| ())
    .map_err(|_| "Compose exception import failed.".to_string())
}

async fn list_pointer(transport: &Transport, list_id: &str) -> TestResult<String> {
    let list = elasticctl_api::exceptions::get_list(
        transport,
        &ListKey {
            list_id: list_id.to_string(),
            namespace_type: "single".to_string(),
        },
    )
    .await
    .map_err(|e| format!("Compose list read failed: {}.", e.kind.as_str()))?;
    list.as_map()
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Compose list response had no id.".to_string())
}

async fn create_rule(transport: &Transport, body: Value) -> TestResult {
    let rule_id = body["rule_id"].as_str().unwrap_or_default().to_string();
    let rule =
        Rule::from_value(body).map_err(|_| "Compose rule could not be built.".to_string())?;
    let created = elasticctl_api::rules::create(transport, &rule)
        .await
        .map_err(|e| format!("Compose rule create failed: {}.", e.kind.as_str()))?;
    if created.rule_id().ok() != Some(rule_id.as_str()) {
        return Err("Compose rule create returned another rule.".to_string());
    }
    Ok(())
}

async fn wait_for_alert(transport: &Transport, rule_id: &str) -> TestResult<String> {
    for attempt in 0..TRIAGE_POLL_ATTEMPTS {
        let page = elasticctl_api::alerts::search(
            transport,
            &json!({
                "query": open_marker_rule_alerts_query(rule_id),
                "sort": elasticctl_api::alerts_ops::default_sort(),
                "size": 10,
                "track_total_hits": true,
                "_source": elasticctl_api::alerts_ops::RESOLVE_SOURCE_FIELDS,
            }),
        )
        .await
        .map_err(|_| "Compose alert poll failed.".to_string())?;
        if let Some(hit) = page.hits.first() {
            return Ok(hit.id.clone());
        }
        if attempt + 1 < TRIAGE_POLL_ATTEMPTS {
            tokio::time::sleep(TRIAGE_POLL_INTERVAL).await;
        }
    }
    Err("Compose alert did not appear.".to_string())
}

async fn create_case(transport: &Transport, title: &str) -> TestResult<Value> {
    let plan = elasticctl_api::cases_ops::plan_create(
        transport,
        title,
        Some(CASE_DESCRIPTION.to_string()),
        vec![LIVE_TAG.to_string()],
        Some("low".to_string()),
        &[],
    )
    .await
    .map_err(|_| "Compose case plan failed.".to_string())?;
    elasticctl_api::cases_ops::apply_create(transport, &plan)
        .await
        .map_err(|_| "Compose case could not be created.".to_string())
}

async fn attach_alert(transport: &Transport, case_id: &str, alert_id: &str) -> TestResult {
    let plan = elasticctl_api::cases_ops::plan_attach(transport, case_id, &[alert_id.to_string()])
        .await
        .map_err(|_| "Compose attach plan failed.".to_string())?;
    let report = elasticctl_api::cases_ops::apply_attach(transport, &plan)
        .await
        .map_err(|_| "Compose alert could not be attached.".to_string())?;
    if report.updated != 1 || report.failed != 0 {
        return Err("Compose attach did not attach exactly one alert.".to_string());
    }
    Ok(())
}

async fn prebuilt_total(transport: &Transport) -> TestResult<u64> {
    elasticctl_api::rules::find_page(
        transport,
        &elasticctl_api::rules::RuleFilter {
            source: elasticctl_api::rules::RuleSource::Prebuilt,
            ..Default::default()
        },
        1,
        1,
    )
    .await
    .map(|(_, total)| total)
    .map_err(|e| format!("Compose prebuilt total read failed: {}.", e.kind.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet_cleanup() -> LiveCleanup {
        let mut cleanup = LiveCleanup::for_test();
        cleanup.finished = true;
        cleanup
    }

    #[test]
    fn no_step_names_an_object_without_the_marker() {
        let ids = ComposeIds::new();
        for name in ids.named_objects() {
            assert!(is_marked(&name), "{name}");
        }
        let pointers: Vec<String> = ids
            .work_lists
            .iter()
            .map(|list| format!("{}-pointer", list.list_id))
            .collect();
        for body in [
            work_rule_body(&ids, &pointers),
            degraded_rule_body(&ids, "pointer"),
            view_rule_body(&ids),
        ] {
            assert!(is_marked(body["rule_id"].as_str().unwrap()));
            assert!(is_marked(body["name"].as_str().unwrap()));
            assert_eq!(body["tags"], json!([LIVE_TAG]));
            for pattern in body["index"].as_array().into_iter().flatten() {
                assert!(is_marked(pattern.as_str().unwrap()), "{pattern}");
            }
            for list in body["exceptions_list"].as_array().into_iter().flatten() {
                assert!(is_marked(list["list_id"].as_str().unwrap()), "{list}");
            }
            if let Some(view) = body.get("data_view_id") {
                assert!(is_marked(view.as_str().unwrap()));
            }
        }
        for list in ids.created_lists() {
            for line in list_bundle(list).lines() {
                let row: Value = serde_json::from_str(line).unwrap();
                assert_eq!(row["list_id"], list.list_id.as_str());
                assert_eq!(row["tags"], json!([LIVE_TAG]));
                if let Some(item) = row.get("item_id") {
                    assert!(is_marked(item.as_str().unwrap()));
                }
            }
        }
        for unmarked in [
            "",
            "elasticctl-live-",
            "-",
            "prebuilt-rule",
            "elasticctl-sample-fill-",
            "logs-*",
        ] {
            assert!(!is_marked(unmarked), "{unmarked}");
        }
    }

    #[test]
    fn registration_covers_every_written_object_before_the_first_write() {
        let ids = ComposeIds::new();
        let mut cleanup = quiet_cleanup();
        assert!(!unregistered(&ids, &cleanup).is_empty());
        register_compose(&mut cleanup, &ids, Some("original".to_string()));
        assert_eq!(unregistered(&ids, &cleanup), Vec::<String>::new());
        assert!(
            !cleanup.lists.contains(&ids.missing_list),
            "the missing list key is never written"
        );
        assert_eq!(
            cleanup.default_data_view,
            Some(Some("original".to_string()))
        );
        assert!(!cleanup.alert_rules.contains(&ids.view_rule));

        let mut partial = quiet_cleanup();
        register_compose(&mut partial, &ids, None);
        partial.rules.remove(&ids.degraded_rule);
        assert_eq!(unregistered(&ids, &partial), [ids.degraded_rule.as_str()]);
    }

    #[test]
    fn the_two_sets_stay_separate() {
        let ids = ComposeIds::new();
        let pointers = vec!["p".to_string(); WORK_LISTS];
        let work = work_rule_body(&ids, &pointers);
        let patterns = work["index"].as_array().unwrap();
        assert_eq!(patterns.len(), 16);
        assert_eq!(patterns[0], ids.index.as_str());
        assert!(
            patterns
                .iter()
                .all(|p| !p.as_str().unwrap().starts_with('-'))
        );
        let lists: Vec<&str> = work["exceptions_list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["list_id"].as_str().unwrap())
            .collect();
        assert_eq!(lists.len(), WORK_LISTS);
        assert!(!lists.contains(&ids.missing_list.as_str()));
        let packages: Vec<&str> = work["related_integrations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["package"].as_str().unwrap())
            .collect();
        assert_eq!(packages, WORK_PACKAGES);
        assert_eq!(work["enabled"], true);
        assert_eq!(
            work["threat"][0]["technique"][0]["subtechnique"][0]["id"],
            "T1059.001"
        );
        assert_eq!(ids.work_lists[0].item_ids.len(), 2);
        assert!(ids.work_lists[1..].iter().all(|l| l.item_ids.len() == 1));

        let degraded = degraded_rule_body(&ids, "p");
        assert_eq!(degraded["index"], json!([ids.index, ids.exclusion]));
        assert_eq!(
            degraded["exceptions_list"][1]["list_id"],
            ids.missing_list.as_str()
        );
        let package = &ids.unknown_package;
        assert!(package.len() <= 128);
        assert!(
            package
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        );
        let view = view_rule_body(&ids);
        assert!(view.get("index").is_none());
        assert_eq!(view["enabled"], false);
    }
}
