use super::{
    CONTAIN, EXCEPTION, IP, LIST, MARKER, OTHER_RULE, OUTSIDE, RANGES, RULE, Session, TEXT,
    cleanup, inventory,
    objects::{self, Object, entry},
    state_values::{self, read},
    steps,
};
use crate::diagnostics::recording_error;
use elasticctl_core::{Result, urlencode};
use serde_json::{Value, json};

async fn items(
    session: &mut Session<'_>,
    container: &str,
    namespace: &str,
    name: &'static str,
    expected: usize,
) -> Result<()> {
    let body = read(session, name, &format!("/api/exception_lists/items/_find?list_id={container}&namespace_type={namespace}&page=1&per_page=10000"), 200).await?;
    if inventory::total(&body)? != expected as u64 || inventory::data(&body)?.len() != expected {
        return Err(recording_error(format!(
            "{name}: unexpected exception item count"
        )));
    }
    Ok(())
}

pub(super) async fn repeated(session: &mut Session<'_>) -> Result<()> {
    items(
        session,
        EXCEPTION,
        "single",
        "state_items_repeated_10000",
        1,
    )
    .await
}

async fn rules(
    session: &mut Session<'_>,
    name: &'static str,
    selected: bool,
    expected: usize,
) -> Result<()> {
    let filter = if selected {
        format!("alert.attributes.params.ruleId: \"{RULE}\"")
    } else {
        "alert.attributes.params.immutable: false AND alert.attributes.params.ruleId: elasticctl-live-vl-*".into()
    };
    let body = read(
        session,
        name,
        &format!(
            "/api/detection_engine/rules/_find?page=1&per_page=10000&filter={}",
            urlencode(&filter)
        ),
        200,
    )
    .await?;
    if inventory::total(&body)? != expected as u64 || inventory::data(&body)?.len() != expected {
        return Err(recording_error(format!("{name}: unexpected rule count")));
    }
    Ok(())
}

pub(super) async fn record(session: &mut Session<'_>) -> Result<()> {
    state_values::prepare(session)
        .await
        .map_err(|e| steps::step_error("state_values", 200, e))?;
    let request = json!({"list_id": OUTSIDE, "name": OUTSIDE, "description": MARKER,
        "type": "detection", "namespace_type": "agnostic", "tags": [MARKER, session.nonce]});
    objects::create(
        session,
        OUTSIDE,
        Object::Container {
            namespace: "agnostic",
        },
        request,
        None,
    )
    .await?;
    let outside = read(
        session,
        "state_outside_get",
        &Object::Container {
            namespace: "agnostic",
        }
        .path(OUTSIDE),
        200,
    )
    .await?;
    let inside = session.get(&cleanup::exception_path(false)).await?;
    objects::item(
        session,
        "included",
        EXCEPTION,
        "single",
        json!([entry(CONTAIN, "ip_range", "source.ip", "included")]),
    )
    .await?;
    objects::item(
        session,
        "coreferenced",
        OUTSIDE,
        "agnostic",
        json!([
            entry(CONTAIN, "ip_range", "source.ip", "included"),
            entry(RANGES, "ip_range", "destination.ip", "included"),
            entry(IP, "ip", "client.ip", "included")
        ]),
    )
    .await?;
    let binding = |body: &Value, list: &str, ns: &str| json!({"id": body["id"], "list_id": list, "type": "detection", "namespace_type": ns});
    for (id, name, bindings) in [
        (
            RULE,
            "state_rule_r",
            json!([binding(&inside, EXCEPTION, "single")]),
        ),
        (
            OTHER_RULE,
            "state_rule_q",
            json!([
                binding(&inside, EXCEPTION, "single"),
                binding(&outside, OUTSIDE, "agnostic")
            ]),
        ),
    ] {
        let request = json!({"rule_id": id, "name": id, "description": MARKER, "type": "query", "language": "kuery", "query": "*:*",
            "index": ["elasticctl-live-vl-events"], "enabled": false, "interval": "1m", "from": "now-5m", "to": "now", "risk_score": 21,
            "severity": "low", "tags": [MARKER, session.nonce], "exceptions_list": bindings});
        objects::create(session, id, Object::Rule, request, Some(name))
            .await
            .map_err(|e| steps::step_error(name, 200, e))?;
    }
    rules(session, "state_rules_full", false, 2).await?;
    rules(session, "state_rules_selected", true, 1).await?;
    for (namespace, name, prefix) in [
        ("single", "state_scan_single", "exception-list"),
        ("agnostic", "state_scan_agnostic", "exception-list-agnostic"),
    ] {
        let filter = urlencode(&format!("{prefix}.attributes.list_id:elasticctl-live-vl-*"));
        let body = read(session, name, &format!("/api/exception_lists/_find?page=1&per_page=10000&namespace_type={namespace}&filter={filter}"), 200).await?;
        if inventory::total(&body)? != 1 || inventory::data(&body)?.len() != 1 {
            return Err(recording_error(format!("{name}: expected one container")));
        }
    }
    items(session, OUTSIDE, "agnostic", "state_items_coreferenced", 1).await?;
    objects::delete(session, "elasticctl-live-vl-coreferenced").await?;
    items(session, EXCEPTION, "single", "state_items_included", 1).await?;
    objects::clear_items(session).await?;
    objects::item(
        session,
        "excluded",
        EXCEPTION,
        "single",
        json!([entry(CONTAIN, "ip_range", "source.ip", "excluded")]),
    )
    .await?;
    items(session, EXCEPTION, "single", "state_items_excluded", 1).await?;
    state_values::add(session, CONTAIN, "union", "10.0.0.6/32", 3).await?;
    state_values::export(
        session,
        CONTAIN,
        "export_c_union",
        &["10.0.0.0/8", "10.0.0.5/32", "10.0.0.6/32"],
    )
    .await?;
    state_values::page(
        session,
        CONTAIN,
        "items_c_union_1000",
        &["10.0.0.0/8", "10.0.0.5/32", "10.0.0.6/32"],
    )
    .await?;
    state_values::remove_value(session, CONTAIN, "10.0.0.6/32", 2).await?;
    objects::item(
        session,
        "mixed-included",
        EXCEPTION,
        "single",
        json!([entry(CONTAIN, "ip_range", "source.ip", "included")]),
    )
    .await?;
    items(session, EXCEPTION, "single", "state_items_mixed", 2).await?;
    objects::clear_items(session).await?;
    for (suffix, list) in [
        ("independent-v", LIST),
        ("independent-c", CONTAIN),
        ("independent-s", RANGES),
    ] {
        objects::item(
            session,
            suffix,
            EXCEPTION,
            "single",
            json!([entry(list, "ip_range", "source.ip", "included")]),
        )
        .await?;
    }
    items(session, EXCEPTION, "single", "state_items_independent", 3).await?;
    objects::clear_items(session).await?;
    items(session, EXCEPTION, "single", "state_items_empty", 0).await?;
    for id in [RULE, OTHER_RULE] {
        objects::delete(session, id).await?;
    }
    read(
        session,
        "cleanup_rule_absent",
        &Object::Rule.path(RULE),
        404,
    )
    .await?;
    read(
        session,
        "cleanup_exception_item_absent",
        &cleanup::exception_path(true),
        404,
    )
    .await?;
    objects::delete(session, OUTSIDE).await?;
    cleanup::delete_owned(
        session,
        &cleanup::exception_path(false),
        EXCEPTION,
        true,
        false,
    )
    .await?;
    session.exception = false;
    read(
        session,
        "cleanup_exception_absent",
        &cleanup::exception_path(false),
        404,
    )
    .await?;
    rules(session, "state_rules_empty", false, 0).await?;
    state_values::dash(session)
        .await
        .map_err(|e| steps::step_error("dash_values", 200, e))?;
    cli_cleanup(session).await
}

async fn cli_cleanup(session: &mut Session<'_>) -> Result<()> {
    for (list, kind, name) in [
        (CONTAIN, "keyword", "container_c_keyword"),
        (RANGES, "long", "container_s_unsupported"),
    ] {
        state_values::delete_list(session, list).await?;
        steps::create_typed_list(
            session,
            list,
            kind,
            if list == CONTAIN {
                "state_container_c"
            } else {
                "state_container_s"
            },
        )
        .await?;
        read(session, name, &format!("/api/lists?id={list}"), 200).await?;
    }
    steps::create_typed_list(session, TEXT, "text", "state_container_t").await?;
    let body = read(
        session,
        "cli_lists_all",
        &format!(
            "/api/lists/_find?page=1&per_page=1000&filter={}",
            urlencode("name:elasticctl-live-vl-*")
        ),
        200,
    )
    .await?;
    let actual: std::collections::BTreeMap<_, _> = inventory::data(&body)?
        .iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap_or(""),
                r["type"].as_str().unwrap_or(""),
            )
        })
        .collect();
    if inventory::total(&body)? != 5
        || actual
            != [
                (LIST, "ip_range"),
                (CONTAIN, "keyword"),
                (RANGES, "long"),
                (IP, "ip"),
                (TEXT, "text"),
            ]
            .into_iter()
            .collect()
    {
        return Err(recording_error(
            "cli_lists_all: expected all five list types",
        ));
    }
    state_values::add(session, CONTAIN, "keyword", "elasticctl-live-vl-value", 1).await?;
    for list in [LIST, RANGES, IP, TEXT] {
        state_values::delete_list(session, list).await?;
    }
    let path = format!(
        "/api/lists/_find?per_page=1&filter={}",
        urlencode("name:elasticctl-live-vl-*")
    );
    let body = read(session, "cleanup_lists_nonempty", &path, 200).await?;
    if inventory::total(&body)? != 1
        || inventory::data(&body)?.len() != 1
        || body["data"][0]["id"] != CONTAIN
    {
        return Err(recording_error("cleanup_lists_nonempty: expected only C"));
    }
    state_values::remove_value(session, CONTAIN, "elasticctl-live-vl-value", 0).await?;
    state_values::page(session, CONTAIN, "cleanup_items_empty", &[]).await?;
    state_values::delete_list(session, CONTAIN).await?;
    let body = read(session, "cleanup_lists_empty", &path, 200).await?;
    if inventory::total(&body)? != 0 || !inventory::data(&body)?.is_empty() {
        return Err(recording_error("cleanup_lists_empty: expected zero lists"));
    }
    let deadline = tokio::time::Instant::now() + session.timing.budget;
    loop {
        let mut markers = std::collections::BTreeSet::new();
        let result = tokio::time::timeout_at(
            deadline,
            inventory::marker_items(session, false, &mut markers),
        )
        .await;
        if matches!(result, Ok(Ok(()))) && markers.is_empty() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(recording_error(
                "cleanup_items_audit: marker items remain or audit failed",
            ));
        }
        tokio::time::sleep(session.timing.interval).await;
    }
    let audit = format!(
        "/.items-{}/_search?size=100&track_total_hits=true&q={}",
        urlencode(session.t.space()),
        urlencode("list_id:elasticctl-live-vl-*")
    );
    let body = session
        .t
        .get_absolute_es(&audit)
        .await
        .map_err(|e| steps::step_error("cleanup_items_audit", 200, e))?;
    if body["timed_out"] != false
        || body["_shards"]["failed"] != 0
        || body["hits"]["total"]["relation"] != "eq"
        || body["hits"]["total"]["value"] != 0
        || body["hits"]["hits"]
            .as_array()
            .is_none_or(|hits| !hits.is_empty())
    {
        return Err(recording_error(
            "cleanup_items_audit: final audit is incomplete or nonempty",
        ));
    }
    session
        .evidence
        .exchange("cleanup_items_audit", json!({"path": audit}), body);
    Ok(())
}
