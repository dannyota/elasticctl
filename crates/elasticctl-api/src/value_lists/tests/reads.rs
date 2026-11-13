use super::super::*;
use elasticctl_core::{Profile, Transport, TransportOptions};
use serde_json::Value;
use std::path::PathBuf;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub(super) const FLAVORS: [&str; 3] = ["serverless-9.7.0", "ech-9.5.6", "traditional-9.5.1"];

pub(super) fn fixture(flavor: &str, operation: &str) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(flavor)
        .join("value_lists");
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<Value>(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .find(|value| value["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {flavor} {operation}"))
}

pub(super) fn transport(server: &MockServer) -> Transport {
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

pub(super) fn response(fixture: &Value, status: u16) -> ResponseTemplate {
    if let Some(text) = fixture["response"].as_str() {
        ResponseTemplate::new(status).set_body_string(text)
    } else {
        ResponseTemplate::new(status).set_body_json(&fixture["response"])
    }
}

#[tokio::test]
async fn bootstrap_reads_both_streams_and_the_recorded_absence() {
    for flavor in FLAVORS {
        for (operation, status, expected) in
            [("index_before", 404, false), ("index_after", 200, true)]
        {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/lists/index"))
                .respond_with(response(&fixture(flavor, operation), status))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                bootstrap_state(&transport(&server)).await.unwrap().ready(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn container_and_export_preserve_stored_spelling_and_every_duplicate() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        let read = fixture(flavor, "container_read");
        let export = fixture(flavor, "items_export");
        let id = read["response"]["id"].as_str().unwrap();
        Mock::given(method("GET"))
            .and(path("/api/lists"))
            .and(query_param("id", id))
            .respond_with(response(&read, 200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(query_param("list_id", id))
            .respond_with(response(&export, 200))
            .expect(1)
            .mount(&server)
            .await;
        let remote = read_list(&transport(&server), id).await.unwrap().unwrap();
        assert_eq!(
            remote.container.version,
            read["response"]["_version"].as_str().unwrap()
        );
        let expected: Vec<_> = export["response"]
            .as_str()
            .unwrap()
            .split_terminator('\n')
            .map(str::to_owned)
            .collect();
        assert_eq!(remote.stored.values, expected);
        assert_eq!(remote.stored.values.len(), 4);
        assert_eq!(remote.stored.set().len(), 3);
        let requests = server.received_requests().await.unwrap();
        assert!(requests[1].body.is_empty());
        assert_eq!(requests[1].url.query_pairs().count(), 1);
    }
}

#[tokio::test]
async fn container_find_uses_cursor_and_sorts_without_assuming_page_order() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        let first = fixture(flavor, "lists_find_first");
        let next = fixture(flavor, "lists_find_next");
        for f in [&first, &next] {
            let mut mock = Mock::given(method("GET")).and(path("/api/lists/_find"));
            for (key, value) in f["request"].as_object().unwrap() {
                let value = value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string());
                mock = mock.and(query_param(key, value));
            }
            mock.respond_with(response(f, 200))
                .expect(1)
                .mount(&server)
                .await;
        }
        let found = find_containers(&transport(&server), first["request"]["filter"].as_str(), 1)
            .await
            .unwrap();
        let mut expected: Vec<_> = [&first, &next]
            .into_iter()
            .flat_map(|f| f["response"]["data"].as_array().unwrap())
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect();
        expected.sort();
        assert_eq!(
            found
                .iter()
                .map(|v| v.container.id.clone())
                .collect::<Vec<_>>(),
            expected
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[0].url.query_pairs().count(), 3);
        assert_eq!(requests[1].url.query_pairs().count(), 4);
    }
}
