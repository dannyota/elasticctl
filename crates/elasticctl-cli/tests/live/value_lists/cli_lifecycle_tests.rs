use super::*;

fn config(dir: &Path, server: &MockServer) -> PathBuf {
    let config = mcp_smoke::mcp_subprocess_config(dir, &server.uri());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    config
}

async fn status(server: &MockServer, flavor: &str) {
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(&fixture(flavor, "status")["response"]),
        )
        .mount(server)
        .await;
}

async fn index_reads(server: &MockServer, flavor: &str, operation: &str, status: u16, count: u64) {
    mount(
        server,
        "GET",
        "/api/lists/index",
        None,
        &fixture(flavor, operation)["response"],
        status,
        count,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_init_dry_run_is_read_only_and_bootstrap_is_owned_only_after_success() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        status(&server, flavor).await;
        index_reads(&server, flavor, "index_before", 404, 5).await;
        index_reads(&server, flavor, "index_after", 200, 2).await;
        let flow = fixture(flavor, "initialize");
        Mock::given(method("POST"))
            .and(path("/api/security_solution/initialize"))
            .and(wiremock::matchers::body_json(&flow["request"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&flow["response"]))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &server);
        let t = transport(&server);
        let mut lease = lease();
        lease.before = Some(api::bootstrap_state(&t).await.unwrap());
        setup::initialize(&t, &mut lease, &config, None)
            .await
            .unwrap();
        assert!(lease.restore_streams && !lease.init_pending);
        let requests = server.received_requests().await.unwrap();
        let writes: Vec<_> = requests.iter().filter(|r| r.method != "GET").collect();
        assert_eq!(writes.len(), 1);
        let post = requests.iter().position(|r| r.method == "POST").unwrap();
        assert_eq!(
            requests[..post]
                .iter()
                .filter(|r| r.url.path() == "/api/lists/index")
                .count(),
            5
        );
        assert_eq!(writes[0].body_json::<Value>().unwrap(), flow["request"]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_init_races_never_claim_another_runs_streams() {
    let flavor = FLAVORS[0];
    for before_count in [3, 4] {
        let server = MockServer::start().await;
        status(&server, flavor).await;
        index_reads(&server, flavor, "index_before", 404, before_count).await;
        index_reads(&server, flavor, "index_after", 200, 2).await;
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &server);
        let t = transport(&server);
        let mut lease = lease();
        lease.before = Some(api::bootstrap_state(&t).await.unwrap());
        setup::initialize(&t, &mut lease, &config, None)
            .await
            .unwrap();
        assert!(!lease.restore_streams && !lease.init_pending);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}

#[tokio::test]
async fn existing_streams_skip_cli_init_and_never_authorize_restore() {
    let server = MockServer::start().await;
    let mut lease = lease();
    lease.before = Some(api::BootstrapState {
        list_index: true,
        list_item_index: true,
    });
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &server);
    setup::initialize(&transport(&server), &mut lease, &config, None)
        .await
        .unwrap();
    assert!(!lease.restore_streams && !lease.init_pending);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_cli_init_apply_preflight_fault_cannot_authorize_deletion_of_other_streams() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    index_reads(&server, flavor, "index_before", 404, 2).await;
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(&fixture(flavor, "index_before")["response"]),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &server);
    let t = transport(&server);
    let mut lease = lease();
    lease.before = Some(api::BootstrapState::default());
    assert!(
        setup::initialize(&t, &mut lease, &config, None)
            .await
            .is_err()
    );
    assert!(lease.init_pending && !lease.restore_streams);
    audit(&server, flavor).await;
    assert!(cleanup::finish(&t, &mut lease).await.is_err());
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_delete_dry_run_writes_nothing_and_yes_reports_409_references_then_preserves_the_list()
{
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        status(&server, flavor).await;
        let mut lease = lease();
        for (kind, operation) in [
            (Kind::List, "state_container_v"),
            (Kind::Exception, "exception_create"),
            (Kind::Item, "exception_item_create"),
        ] {
            let body = fixture(flavor, operation)["response"].clone();
            let id = body[kind.key()].as_str().unwrap();
            Mock::given(method("GET"))
                .and(path(kind.endpoint()))
                .and(query_param(kind.key(), id))
                .respond_with(ResponseTemplate::new(200).set_body_json(&body))
                .mount(&server)
                .await;
            lease.objects.push(Object::new(kind, id.into()));
        }
        for (endpoint, operation) in [
            ("/api/lists/index", "index_after"),
            ("/api/exception_lists", "exception_create"),
            ("/api/exception_lists/items/_find", "exception_items_find"),
        ] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(&fixture(flavor, operation)["response"]),
                )
                .mount(&server)
                .await;
        }
        for (namespace, operation) in [
            ("single", "exception_lists_find"),
            ("agnostic", "exception_lists_find_agnostic"),
        ] {
            Mock::given(method("GET"))
                .and(path("/api/exception_lists/_find"))
                .and(query_param("namespace_type", namespace))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(&fixture(flavor, operation)["response"]),
                )
                .mount(&server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    fixture(flavor, "items_export")["response"]
                        .as_str()
                        .unwrap(),
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/lists"))
            .and(query_param("id", &lease.objects[0].id))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(&fixture(flavor, "container_delete_referenced")["response"]),
            )
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &server);
        let run = super::round_trip_tests::case(&dir, &config, flavor);
        let t = transport(&server);
        delete_preview(&t, &lease, &run, &lease.objects[0])
            .await
            .unwrap();
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET" || r.url.path() == "/api/lists/items/_export")
        );
        referenced_delete(&t, &lease, &run).await.unwrap();
        assert!(
            api::read_container(&t, &lease.objects[0].id)
                .await
                .unwrap()
                .is_some()
        );
        let requests = server.received_requests().await.unwrap();
        let deletes: Vec<_> = requests.iter().filter(|r| r.method == "DELETE").collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(
            deletes[0].url.query_pairs().collect::<Vec<_>>(),
            [("id".into(), lease.objects[0].id.clone().into())]
        );
        assert!(deletes[0].body.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_init_preview_reports_the_read_only_flow() {
    let flavor = FLAVORS[0];
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(&fixture(flavor, "index_before")["response"]),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &server);
    let out = round_trip::command(&config, None)
        .args(["value-lists", "init", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let preview: Value = serde_json::from_slice(&out.stderr)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(preview["dry_run"], true, "{preview}");
    assert_eq!(preview["command"], "value-lists init", "{preview}");
    assert_eq!(
        value_list_preview(&preview, "value-lists init", true, None),
        Ok(()),
        "{preview}"
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
}
