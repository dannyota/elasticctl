use super::*;
use crate::state::diff::ExceptionPlan;
use crate::state::reports::ExceptionDrift;
use elasticctl_core::{Profile, TransportOptions};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "test_cone.rs"]
mod cone;
#[path = "test_planning.rs"]
mod planning;
#[path = "test_pull.rs"]
mod pull;

pub(in crate::state) const FLAVORS: [&str; 3] =
    ["traditional-9.5.1", "ech-9.5.6", "serverless-9.7.0"];

pub(in crate::state) fn fixture(flavor: &str, operation: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(flavor)
        .join("value_lists");
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<Value>(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .find(|v| v["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {flavor} {operation}"))
}

pub(in crate::state) fn response(flavor: &str, operation: &str, status: u16) -> ResponseTemplate {
    let value = fixture(flavor, operation);
    if let Some(body) = value["response"].as_str() {
        ResponseTemplate::new(status).set_body_string(body)
    } else {
        ResponseTemplate::new(status).set_body_json(&value["response"])
    }
}

pub(in crate::state) fn transport(server: &MockServer) -> Transport {
    Transport::with_options(
        &Profile {
            kibana_url: server.uri(),
            es_url: None,
            api_key: Some("synthetic".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 2,
        },
        TransportOptions {
            disable_retries: true,
            ..Default::default()
        },
    )
    .unwrap()
}

pub(in crate::state) async fn mount(
    server: &MockServer,
    flavor: &str,
    verb: &str,
    route: &str,
    operation: &str,
    status: u16,
) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(response(flavor, operation, status))
        .mount(server)
        .await;
}

pub(in crate::state) async fn base(server: &MockServer, flavor: &str) {
    mount(server, flavor, "GET", "/api/status", "status", 200).await;
    mount(
        server,
        flavor,
        "GET",
        "/api/lists/index",
        "index_after",
        200,
    )
    .await;
    mount(
        server,
        flavor,
        "GET",
        "/api/exception_lists/_find",
        "exception_lists_find_agnostic",
        200,
    )
    .await;
}

pub(in crate::state) fn remote(flavor: &str) -> RemoteList {
    RemoteList {
        container: vl::decode_remote_container(&fixture(flavor, "container_read")["response"])
            .unwrap(),
        stored: vl::decode_export(
            &vl::ValueListType::IpRange,
            fixture(flavor, "items_export")["response"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    }
}

pub(in crate::state) fn pair(flavor: &str) -> LocalPair {
    let remote = remote(flavor);
    LocalPair {
        stem: vl::file_stem(&remote.container.container.id),
        container: remote.container.container,
        values: remote.stored.set(),
    }
}

pub(in crate::state) fn item(id: &str) -> ExceptionItem {
    ExceptionItem::from_value(json!({
        "item_id": "item", "list_id": "exceptions", "namespace_type": "single", "type": "simple", "name": "Item",
        "entries": [{"type": "list", "field": "source.ip", "operator": "included", "list": {"id": id, "type": "ip_range"}}]
    })).unwrap()
}

pub(in crate::state) fn list() -> ExceptionList {
    ExceptionList::from_value(json!({"list_id": "exceptions", "namespace_type": "single", "type": "detection", "name": "Exceptions"})).unwrap()
}

pub(in crate::state) fn rule() -> Rule {
    Rule::from_value(json!({"rule_id": "rule", "type": "query", "name": "Rule", "exceptions_list": [{"list_id": "exceptions", "namespace_type": "single", "type": "detection"}]})).unwrap()
}

pub(in crate::state) fn exceptions() -> ExceptionPlan {
    ExceptionPlan {
        drift: ExceptionDrift {
            local: 0,
            remote: 0,
            changes: vec![],
            dangling: vec![],
        },
        list_ops: vec![],
        item_ops: vec![],
        resolvable: BTreeSet::new(),
    }
}

pub(in crate::state) async fn run(
    t: &Transport,
    pairs: &[LocalPair],
    lists: &[ExceptionList],
    items: &[ExceptionItem],
    local: &[Rule],
    pushing: bool,
) -> Result<ValuePlan> {
    plan(
        t,
        Inputs {
            pairs,
            has_root: !pairs.is_empty(),
            lists,
            items,
            local,
            remote: &[],
            exception_plan: &exceptions(),
        },
        pushing,
    )
    .await
}

pub(in crate::state) async fn no_writes(server: &MockServer) {
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET" || r.url.path() == "/api/lists/items/_export")
    );
}
