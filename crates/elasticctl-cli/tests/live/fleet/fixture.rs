//! Reusable marked Fleet fixture for live MCP reads.

use elasticctl_api::fleet::{agent_policies, integration_policies};
use elasticctl_api_test_support::fleet::FleetState;
use elasticctl_core::{Profile, Transport};
use serde_json::json;

use super::cleanup::FleetCleanup;
use super::{FleetFailure, SYSTEM_PACKAGE, assert_system_unchanged, ensure_system, prepare_fleet};

/// A nonce-owned parent and integration policy retained for a live reader.
pub(crate) struct FleetFixtureLease {
    profile: Profile,
    nonce: String,
    parent_id: String,
    bootstrap_id: String,
    integration_id: String,
    baseline: Option<FleetState>,
    cleanup: Option<FleetCleanup>,
    finished: bool,
}

impl FleetFixtureLease {
    pub(crate) fn new(profile: Profile, nonce: &str) -> Self {
        Self {
            profile,
            nonce: nonce.to_string(),
            parent_id: super::unique_name("fleet-fixture-parent"),
            bootstrap_id: super::unique_name("fleet-fixture-bootstrap"),
            integration_id: super::unique_name("fleet-fixture-integration"),
            baseline: None,
            cleanup: None,
            finished: false,
        }
    }

    pub(crate) async fn prepare(&mut self) -> Result<(), FleetFailure> {
        self.prepare_with_setup(
            std::env::var("ELASTICCTL_CONFORMANCE_FLEET_SETUP").as_deref() == Ok("1"),
        )
        .await
    }

    async fn prepare_with_setup(
        &mut self,
        controller_setup_complete: bool,
    ) -> Result<(), FleetFailure> {
        if self.finished || self.baseline.is_some() || self.cleanup.is_some() {
            return Err(FleetFailure::Contract(
                "Fleet fixture lease cannot be prepared more than once".to_string(),
            ));
        }
        let transport = Transport::new(&self.profile).map_err(|error| {
            FleetFailure::Contract(format!("building Fleet transport: {}", error.kind.as_str()))
        })?;
        prepare_fleet(&transport, controller_setup_complete)
            .await
            .map_err(FleetFailure::Contract)?;

        let baseline = FleetState::capture(&transport).await.map_err(|error| {
            FleetFailure::Contract(format!("capturing Fleet baseline: {}", error.kind.as_str()))
        })?;
        if !baseline.markers_empty() {
            return Err(FleetFailure::Contract(
                "Fleet baseline contains marker policies".to_string(),
            ));
        }

        self.baseline = Some(baseline.clone());
        self.cleanup = Some(FleetCleanup::new(
            self.profile.clone(),
            self.nonce.clone(),
            baseline,
        ));

        let baseline = self.baseline.as_ref().expect("baseline stored above");
        let version = ensure_system(
            &transport,
            baseline,
            self.cleanup.as_mut().expect("cleanup stored above"),
        )
        .await
        .map_err(FleetFailure::Contract)?;
        assert_system_unchanged(&transport, baseline, &version)
            .await
            .map_err(FleetFailure::Contract)?;

        let parent = self.parent_spec(&transport);
        self.cleanup
            .as_mut()
            .expect("cleanup stored above")
            .register_parent(parent.id.clone(), parent.clone())
            .map_err(FleetFailure::Contract)?;
        create_parent_once(&transport, &parent).await?;

        let bootstrap = self.bootstrap_spec(&transport, &version);
        let mut integration = self
            .cleanup
            .as_mut()
            .expect("cleanup stored above")
            .materialize_system_inputs(&transport, bootstrap)
            .await
            .map_err(FleetFailure::Contract)?;

        assert_system_unchanged(&transport, baseline, &version)
            .await
            .map_err(FleetFailure::Contract)?;
        integration.id = self.integration_id.clone();
        integration.name = super::unique_name("fleet-fixture-integration-name");
        integration.description = Some(format!("Fleet fixture marker {}", self.nonce));
        integration.policy_ids = vec![self.parent_id.clone()];
        self.cleanup
            .as_mut()
            .expect("cleanup stored above")
            .register_integration(integration.id.clone(), integration.clone())
            .map_err(FleetFailure::Contract)?;
        create_integration_once(&transport, &integration).await
    }

    pub(crate) fn parent_id(&self) -> &str {
        &self.parent_id
    }

    pub(crate) fn integration_id(&self) -> &str {
        &self.integration_id
    }

    pub(crate) async fn finish(&mut self) -> Result<(), FleetFailure> {
        if self.finished || self.cleanup.is_none() {
            return Ok(());
        }
        self.cleanup
            .as_mut()
            .expect("cleanup checked above")
            .finish_async()
            .await
            .map_err(FleetFailure::Cleanup)?;
        let final_state = FleetState::capture(&Transport::new(&self.profile).map_err(|error| {
            FleetFailure::Cleanup(format!(
                "building Fleet cleanup transport: {}",
                error.kind.as_str()
            ))
        })?)
        .await
        .map_err(|error| {
            FleetFailure::Cleanup(format!("auditing Fleet cleanup: {}", error.kind.as_str()))
        })?;
        if Some(&final_state) != self.baseline.as_ref() {
            return Err(FleetFailure::Cleanup(
                "Fleet cleanup did not restore the exact baseline".to_string(),
            ));
        }
        self.finished = true;
        Ok(())
    }

    fn parent_spec(&self, transport: &Transport) -> agent_policies::AgentPolicySpec {
        agent_policies::AgentPolicySpec {
            id: self.parent_id.clone(),
            name: super::unique_name("fleet-fixture-parent-name"),
            namespace: transport.space().to_string(),
            description: Some(format!("Fleet fixture marker {}", self.nonce)),
            inactivity_timeout: 1_209_600,
            unenroll_timeout: None,
            monitoring_enabled: Vec::new(),
            agent_features: Vec::new(),
            global_data_tags: Vec::new(),
            advanced_settings: None,
            overrides: None,
            keep_monitoring_alive: None,
            monitoring_pprof_enabled: None,
            monitoring_http: None,
            monitoring_diagnostics: None,
        }
    }

    fn bootstrap_spec(
        &self,
        transport: &Transport,
        version: &str,
    ) -> integration_policies::IntegrationPolicySpec {
        serde_json::from_value(json!({
            "id": self.bootstrap_id,
            "name": super::unique_name("fleet-fixture-bootstrap-name"),
            "description": format!("Fleet fixture bootstrap marker {}", self.nonce),
            "namespace": transport.space(),
            "policy_ids": [self.parent_id],
            "package": {"name": SYSTEM_PACKAGE, "version": version},
            "inputs": {}
        }))
        .expect("Fleet fixture bootstrap specification is valid")
    }
}

async fn create_parent_once(
    transport: &Transport,
    spec: &agent_policies::AgentPolicySpec,
) -> Result<(), FleetFailure> {
    spec.validate().map_err(|error| {
        FleetFailure::Contract(format!(
            "validating Fleet fixture parent: {}",
            error.kind.as_str()
        ))
    })?;
    let body = serde_json::to_value(spec)
        .map_err(|_| FleetFailure::Contract("encoding Fleet fixture parent failed".to_string()))?;
    transport
        .post_once(
            "/api/fleet/agent_policies?sys_monitoring=false",
            Some(&body),
        )
        .await
        .map_err(|error| {
            FleetFailure::Contract(format!(
                "creating Fleet fixture parent: {}",
                error.kind.as_str()
            ))
        })?;
    Ok(())
}

async fn create_integration_once(
    transport: &Transport,
    spec: &integration_policies::IntegrationPolicySpec,
) -> Result<(), FleetFailure> {
    spec.validate().map_err(|error| {
        FleetFailure::Contract(format!(
            "validating Fleet fixture integration: {}",
            error.kind.as_str()
        ))
    })?;
    let body = serde_json::to_value(spec).map_err(|_| {
        FleetFailure::Contract("encoding Fleet fixture integration failed".to_string())
    })?;
    transport
        .post_once("/api/fleet/package_policies", Some(&body))
        .await
        .map_err(|error| {
            FleetFailure::Contract(format!(
                "creating Fleet fixture integration: {}",
                error.kind.as_str()
            ))
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::FleetFailure;
    use super::FleetFixtureLease;
    use elasticctl_api::fleet::{agent_policies, integration_policies};
    use elasticctl_core::Profile;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct SequenceResponder {
        next: Arc<AtomicUsize>,
        responses: Vec<ResponseTemplate>,
    }

    impl SequenceResponder {
        fn new(responses: Vec<ResponseTemplate>) -> Self {
            Self {
                next: Arc::new(AtomicUsize::new(0)),
                responses,
            }
        }
    }

    impl Respond for SequenceResponder {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            self.responses[index.min(self.responses.len() - 1)].clone()
        }
    }

    struct FleetMockState {
        parents: BTreeMap<String, Value>,
        integrations: BTreeMap<String, Value>,
        received_parent: Option<Value>,
        received_integration: Option<Value>,
        failed_integration_reads: std::collections::BTreeSet<String>,
        failed_empty_parent_lists: usize,
        failed_baseline_parent_lists: usize,
        failed_setup_posts: usize,
        setup_installs_system: bool,
        system_installed: bool,
        ambiguous_system_install: bool,
        lost_parent_create: bool,
        lost_bootstrap_create: bool,
        lost_final_create: bool,
        inventory_drift: bool,
        drift_after_bootstrap_delete: bool,
    }

    impl Default for FleetMockState {
        fn default() -> Self {
            Self {
                parents: BTreeMap::new(),
                integrations: BTreeMap::new(),
                received_parent: None,
                received_integration: None,
                failed_integration_reads: std::collections::BTreeSet::new(),
                failed_empty_parent_lists: 0,
                failed_baseline_parent_lists: 0,
                failed_setup_posts: 0,
                setup_installs_system: false,
                system_installed: true,
                ambiguous_system_install: false,
                lost_parent_create: false,
                lost_bootstrap_create: false,
                lost_final_create: false,
                inventory_drift: false,
                drift_after_bootstrap_delete: false,
            }
        }
    }

    #[derive(Clone, Default)]
    struct FleetResponder {
        state: Arc<Mutex<FleetMockState>>,
    }

    impl FleetResponder {
        fn parent_item(spec: Value) -> Value {
            let mut item = spec
                .as_object()
                .expect("parent create body is an object")
                .clone();
            item.insert("is_default".into(), json!(false));
            item.insert("is_default_fleet_server".into(), json!(false));
            item.insert("has_fleet_server".into(), Value::Null);
            item.insert("is_managed".into(), json!(false));
            item.insert("is_preconfigured".into(), json!(false));
            item.insert("is_verifier".into(), Value::Null);
            item.insert("supports_agentless".into(), json!(false));
            item.insert("is_protected".into(), json!(false));
            item.insert("agentless".into(), Value::Null);
            item.insert("space_ids".into(), json!(["default"]));
            item.insert("agents".into(), json!(0));
            item.insert("package_policies".into(), json!([]));
            Value::Object(item)
        }

        fn integration_item(spec: Value) -> Value {
            let mut item = spec
                .as_object()
                .expect("integration create body is an object")
                .clone();
            item.insert("policy_id".into(), item["policy_ids"][0].clone());
            item.insert("inputs".into(), json!({"system-system": {}}));
            item.insert("enabled".into(), json!(true));
            item.insert("is_managed".into(), json!(false));
            item.insert("supports_agentless".into(), json!(false));
            item.insert("supports_cloud_connector".into(), json!(false));
            item.insert("output_id".into(), Value::Null);
            item.insert("cloud_connector_id".into(), Value::Null);
            item.insert("cloud_connector_name".into(), Value::Null);
            item.insert("secret_references".into(), json!([]));
            item.insert("spaceIds".into(), json!(["default"]));
            Value::Object(item)
        }

        fn list(items: impl Iterator<Item = Value>) -> ResponseTemplate {
            let items: Vec<_> = items.collect();
            ResponseTemplate::new(200).set_body_json(json!({
                "items": items, "page": 1, "perPage": 1000, "total": items.len()
            }))
        }

        fn not_found() -> ResponseTemplate {
            ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404, "error": "Not Found", "message": "missing"
            }))
        }
    }

    impl Respond for FleetResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let path = request.url.path();
            let mut state = self.state.lock().expect("Fleet mock state lock");
            match (request.method.as_str(), path) {
                ("GET", "/api/status") => ResponseTemplate::new(200).set_body_json(json!({
                    "version": {"number": "9.5.1", "build_flavor": "traditional"}
                })),
                ("POST", "/api/fleet/setup") if state.failed_setup_posts > 0 => {
                    state.failed_setup_posts -= 1;
                    ResponseTemplate::new(500).set_body_json(json!({"message": "setup lost"}))
                }
                ("POST", "/api/fleet/setup") => {
                    if state.setup_installs_system {
                        state.system_installed = true;
                    }
                    ResponseTemplate::new(200).set_body_json(json!({"isInitialized": true}))
                }
                ("GET", "/api/fleet/agent_policies") if state.failed_baseline_parent_lists > 0 => {
                    state.failed_baseline_parent_lists -= 1;
                    ResponseTemplate::new(500).set_body_json(json!({"message": "baseline lost"}))
                }
                ("GET", "/api/fleet/agent_policies") if state.parents.is_empty()
                    && state.failed_empty_parent_lists > 0 =>
                {
                    state.failed_empty_parent_lists -= 1;
                    ResponseTemplate::new(500).set_body_json(json!({"message": "audit lost"}))
                }
                ("GET", "/api/fleet/agent_policies") => Self::list(state.parents.values().cloned()),
                ("GET", "/api/fleet/package_policies") => {
                    Self::list(state.integrations.values().cloned())
                }
                ("GET", "/api/fleet/epm/packages/installed") => {
                    let mut items = if state.system_installed {
                        vec![json!({"name": "system", "version": "2.0.0", "status": "installed"})]
                    } else {
                        Vec::new()
                    };
                    if state.inventory_drift {
                        items.push(json!({
                            "name": "other", "version": "1.0.0", "status": "installed"
                        }));
                    }
                    ResponseTemplate::new(200).set_body_json(json!({"items": items, "total": items.len()}))
                }
                ("GET", "/api/fleet/epm/packages/system") => ResponseTemplate::new(200)
                    .set_body_json(if state.system_installed {
                        json!({"item": {"name": "system", "status": "installed", "installationInfo": {"version": "2.0.0"}}})
                    } else {
                        json!({"item": {"name": "system", "status": "not_installed", "latestVersion": "2.0.0"}})
                    }),
                ("GET", "/api/fleet/epm/packages/system/2.0.0") => ResponseTemplate::new(200)
                    .set_body_json(json!({"item": {
                        "name": "system", "version": "2.0.0", "vars": [],
                        "policy_templates": [{"name": "system", "inputs": [{"type": "system", "vars": []}]}]
                    }})),
                ("POST", "/api/fleet/agent_policies") => {
                    let body: Value = serde_json::from_slice(&request.body)
                        .expect("parent request has JSON body");
                    let item = Self::parent_item(body.clone());
                    let id = item["id"].as_str().expect("parent id").to_string();
                    state.received_parent = Some(body);
                    state.parents.insert(id, item.clone());
                    if state.lost_parent_create {
                        return ResponseTemplate::new(500).set_body_json(json!({"message": "parent lost"}));
                    }
                    ResponseTemplate::new(200).set_body_json(json!({"item": item}))
                }
                ("POST", "/api/fleet/package_policies") => {
                    let body: Value = serde_json::from_slice(&request.body)
                        .expect("integration request has JSON body");
                    let item = Self::integration_item(body.clone());
                    let id = item["id"].as_str().expect("integration id").to_string();
                    let parent = item["policy_id"].as_str().expect("integration parent");
                    state.received_integration = Some(body);
                    state.integrations.insert(id.clone(), item.clone());
                    state.parents.get_mut(parent).expect("parent exists")["package_policies"] =
                        json!([id]);
                    let lost = if item["id"].as_str().is_some_and(|id| id.contains("bootstrap")) {
                        state.lost_bootstrap_create
                    } else {
                        state.lost_final_create
                    };
                    if lost {
                        return ResponseTemplate::new(500).set_body_json(json!({"message": "integration lost"}));
                    }
                    ResponseTemplate::new(200).set_body_json(json!({"item": item}))
                }
                ("POST", "/api/fleet/epm/packages/system/2.0.0") => {
                    state.system_installed = true;
                    if state.ambiguous_system_install {
                        ResponseTemplate::new(500).set_body_json(json!({"message": "install lost"}))
                    } else {
                        ResponseTemplate::new(200).set_body_json(json!({
                            "items": [], "_meta": {"name": "system", "install_source": "registry"}
                        }))
                    }
                }
                ("DELETE", "/api/fleet/epm/packages/system/2.0.0") => {
                    state.system_installed = false;
                    ResponseTemplate::new(200).set_body_json(json!({}))
                }
                ("POST", "/api/fleet/agent_policies/delete") => {
                    let body: Value =
                        serde_json::from_slice(&request.body).expect("parent delete has JSON body");
                    let id = body["agentPolicyId"].as_str().expect("parent delete id");
                    state.parents.remove(id);
                    ResponseTemplate::new(200).set_body_json(json!({"id": id}))
                }
                ("DELETE", path) if path.starts_with("/api/fleet/package_policies/") => {
                    let id = path.rsplit('/').next().expect("integration id");
                    let item = state.integrations.remove(id);
                    if let Some(item) = item {
                        if id.contains("bootstrap") && state.drift_after_bootstrap_delete {
                            state.inventory_drift = true;
                        }
                        let parent = item["policy_id"].as_str().expect("integration parent");
                        state.parents.get_mut(parent).expect("parent exists")["package_policies"] =
                            json!([]);
                        ResponseTemplate::new(200).set_body_json(json!({"id": id}))
                    } else {
                        Self::not_found()
                    }
                }
                ("GET", path) if path.starts_with("/api/fleet/agent_policies/") => {
                    let id = path.rsplit('/').next().expect("parent id");
                    state
                        .parents
                        .get(id)
                        .cloned()
                        .map(|item| ResponseTemplate::new(200).set_body_json(json!({"item": item})))
                        .unwrap_or_else(Self::not_found)
                }
                ("GET", path) if path.starts_with("/api/fleet/package_policies/") => {
                    let id = path.rsplit('/').next().expect("integration id");
                    if state.failed_integration_reads.contains(id) {
                        return ResponseTemplate::new(500)
                            .set_body_json(json!({"message": "child read lost"}));
                    }
                    state
                        .integrations
                        .get(id)
                        .cloned()
                        .map(|item| ResponseTemplate::new(200).set_body_json(json!({"item": item})))
                        .unwrap_or_else(Self::not_found)
                }
                _ => ResponseTemplate::new(500).set_body_json(json!({
                    "message": format!("unexpected Fleet mock route {} {}", request.method, path)
                })),
            }
        }
    }

    async fn mount_stateful_fleet(server: &MockServer) -> FleetResponder {
        let responder = FleetResponder::default();
        Mock::given(path_regex("^/api/"))
            .respond_with(responder.clone())
            .mount(server)
            .await;
        responder
    }

    fn profile(kibana_url: String) -> Profile {
        Profile {
            kibana_url,
            es_url: None,
            api_key: Some("test".to_string()),
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 1,
        }
    }

    async fn mount_status(server: &MockServer, version: &str) {
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": version, "build_flavor": "traditional"}
            })))
            .mount(server)
            .await;
    }

    async fn mount_clean_system_baseline(server: &MockServer) {
        for endpoint in ["/api/fleet/agent_policies", "/api/fleet/package_policies"] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "page": 1, "perPage": 1000, "total": 0
                })))
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "system", "version": "2.0.0", "status": "installed"}],
                "total": 1
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "system", "status": "installed",
                "installationInfo": {"version": "2.0.0"}
            }})))
            .mount(server)
            .await;
    }

    async fn mount_setup(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/fleet/setup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"isInitialized": true})))
            .mount(server)
            .await;
    }

    /// Removing the no-I/O constructor guarantee would create a remote
    /// dependency before callers can retain the lease for cleanup.
    #[tokio::test]
    async fn new_assigns_distinct_marker_ids_without_remote_io() {
        let server = MockServer::start().await;

        let lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");

        assert!(lease.parent_id().starts_with("elasticctl-live-"));
        assert!(lease.integration_id().starts_with("elasticctl-live-"));
        assert_ne!(lease.parent_id(), lease.integration_id());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Removing the marker-baseline refusal would permit package or policy
    /// mutations against a target that a prior run may still own.
    #[tokio::test]
    async fn dirty_marker_baseline_stops_before_package_or_policy_creation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.1", "build_flavor": "traditional"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/setup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "isInitialized": true
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "elasticctl-live-stale", "name": "Stale"}],
                "page": 1,
                "perPage": 1000,
                "total": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "page": 1, "perPage": 1000, "total": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "total": 0
            })))
            .mount(&server)
            .await;

        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        let error = lease
            .prepare_with_setup(false)
            .await
            .expect_err("a dirty marker baseline must be refused");

        assert!(matches!(error, FleetFailure::Contract(message) if message.contains("marker")));
        let requests_before_finish = server.received_requests().await.unwrap();
        assert_eq!(
            requests_before_finish
                .iter()
                .filter(|request| request.method != "GET")
                .count(),
            1
        );
        assert!(requests_before_finish.iter().any(|request| {
            request.method == "POST" && request.url.path() == "/api/fleet/setup"
        }));
        assert!(requests_before_finish.iter().all(|request| {
            request.method == "GET" || request.url.path() == "/api/fleet/setup"
        }));
        assert!(
            lease.finish().await.is_ok(),
            "unarmed lease must be a no-op"
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), requests_before_finish.len());
        assert!(requests.iter().all(|request| {
            request.method == "GET" || request.url.path() == "/api/fleet/setup"
        }));
    }

    #[tokio::test]
    async fn dirty_integration_baseline_stops_before_package_or_policy_creation() {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.1").await;
        mount_setup(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/agent_policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [], "page": 1, "perPage": 1000, "total": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/package_policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"id": "elasticctl-live-stale", "name": "Stale"}],
                "page": 1, "perPage": 1000, "total": 1
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"items": [], "total": 0})),
            )
            .mount(&server)
            .await;

        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(matches!(
            lease.prepare_with_setup(false).await,
            Err(FleetFailure::Contract(message)) if message.contains("marker")
        ));
        assert!(lease.finish().await.is_ok());
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request.method == "GET" || request.url.path() == "/api/fleet/setup"
        }));
    }

    #[tokio::test]
    async fn unsupported_floor_stops_before_setup_or_fixture_mutation() {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.0").await;
        mount_setup(&server).await;

        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(matches!(
            lease.prepare_with_setup(false).await,
            Err(FleetFailure::Contract(_))
        ));
        assert!(lease.finish().await.is_ok());
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method == "GET")
        );
    }

    #[tokio::test]
    async fn controller_setup_marker_skips_setup_but_still_checks_floor() {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.1").await;
        mount_clean_system_baseline(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("^/api/fleet/agent_policies/elasticctl-live-"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404, "error": "Not Found", "message": "missing"
            })))
            .mount(&server)
            .await;

        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(true).await.is_err());
        assert!(lease.finish().await.is_ok());
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.url.path() == "/api/status")
        );
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() != "/api/fleet/setup")
        );
    }

    #[tokio::test]
    async fn parent_create_failure_after_registration_is_cleaned_without_replay() {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.1").await;
        mount_setup(&server).await;
        mount_clean_system_baseline(&server).await;
        Mock::given(method("POST"))
            .and(path("/api/fleet/agent_policies"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "lost"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("^/api/fleet/agent_policies/elasticctl-live-"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "statusCode": 404, "error": "Not Found", "message": "missing"
            })))
            .mount(&server)
            .await;

        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_err());
        let requests_before_retry = server.received_requests().await.unwrap().len();
        assert!(lease.prepare_with_setup(false).await.is_err());
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            requests_before_retry,
            "an armed lease must reject prepare before I/O"
        );
        assert!(lease.finish().await.is_ok());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/api/fleet/agent_policies")
                .filter(|request| request.method == "POST")
                .count(),
            1
        );
        assert!(requests.iter().all(|request| {
            request.url.path() != "/api/fleet/agent_policies/delete"
                && !(request.url.path() == "/api/fleet/package_policies" && request.method != "GET")
        }));
    }

    #[tokio::test]
    async fn changed_package_inventory_stops_before_parent_creation() {
        let server = MockServer::start().await;
        mount_status(&server, "9.5.1").await;
        mount_setup(&server).await;
        for endpoint in ["/api/fleet/agent_policies", "/api/fleet/package_policies"] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "page": 1, "perPage": 1000, "total": 0
                })))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/installed"))
            .respond_with(SequenceResponder::new(vec![
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "system", "version": "2.0.0", "status": "installed"}], "total": 1
                })),
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [
                        {"name": "system", "version": "2.0.0", "status": "installed"},
                        {"name": "other", "version": "1.0.0", "status": "installed"}
                    ], "total": 2
                })),
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "system", "version": "2.0.0", "status": "installed"}], "total": 1
                })),
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/fleet/epm/packages/system"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"item": {
                "name": "system", "status": "installed", "installationInfo": {"version": "2.0.0"}
            }})))
            .mount(&server)
            .await;

        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(
            matches!(lease.prepare_with_setup(false).await, Err(FleetFailure::Contract(message)) if message.contains("inventory"))
        );
        assert!(lease.finish().await.is_ok());
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !(request.method == "POST"
                    && request.url.path() == "/api/fleet/agent_policies"))
        );
    }

    #[tokio::test]
    async fn successful_fixture_lease_restores_the_exact_baseline_and_cannot_reprepare() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");

        match lease.prepare_with_setup(false).await {
            Ok(()) => {}
            Err(FleetFailure::Contract(message) | FleetFailure::Cleanup(message)) => {
                panic!("fixture preparation failed: {message}")
            }
        }

        let transport =
            elasticctl_core::Transport::new(&profile(server.uri())).expect("mock Fleet transport");
        let parent = agent_policies::get(&transport, lease.parent_id())
            .await
            .expect("prepared parent is readable");
        let integration = integration_policies::get(&transport, lease.integration_id())
            .await
            .expect("prepared integration is readable");
        assert_eq!(parent.item["id"], lease.parent_id());
        assert_eq!(integration.item["id"], lease.integration_id());
        assert_eq!(integration.item["policy_ids"], json!([lease.parent_id()]));
        assert_eq!(integration.item["inputs"], json!({"system-system": {}}));

        let (received_parent, received_integration) = {
            let state = responder.state.lock().expect("Fleet mock state lock");
            (
                state
                    .received_parent
                    .clone()
                    .expect("parent create received"),
                state
                    .received_integration
                    .clone()
                    .expect("integration create received"),
            )
        };
        assert_eq!(received_parent["id"], lease.parent_id());
        assert_eq!(received_integration["id"], lease.integration_id());
        assert_eq!(
            received_integration["policy_ids"],
            json!([lease.parent_id()])
        );
        assert_eq!(received_integration["inputs"], json!({"system-system": {}}));

        assert!(lease.finish().await.is_ok(), "fixture cleanup succeeds");
        {
            let state = responder.state.lock().expect("Fleet mock state lock");
            assert!(state.parents.is_empty());
            assert!(state.integrations.is_empty());
        }

        let requests_before_reprepare = server.received_requests().await.unwrap().len();
        assert!(matches!(
            lease.prepare_with_setup(false).await,
            Err(FleetFailure::Contract(message)) if message.contains("cannot be prepared more than once")
        ));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            requests_before_reprepare,
            "a finished lease rejects prepare before I/O"
        );
    }

    #[tokio::test]
    async fn mismatched_child_ownership_blocks_all_deletes_until_the_exact_object_is_restored() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());
        let deletes_before_fault = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "DELETE")
            .count();

        let integration_id = lease.integration_id().to_string();
        let (saved_description, saved_name) = {
            let mut state = responder.state.lock().expect("Fleet mock state lock");
            let item = state
                .integrations
                .get_mut(&integration_id)
                .expect("created child");
            let description = item["description"].clone();
            let name = item["name"].clone();
            item["description"] = json!("Fleet fixture marker someone-else");
            (description, name)
        };
        assert!(matches!(
            lease.finish().await,
            Err(FleetFailure::Cleanup(_))
        ));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "DELETE")
                .count(),
            deletes_before_fault
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .filter(|request| request.url.path() == "/api/fleet/agent_policies/delete")
                .count(),
            0
        );

        {
            let mut state = responder.state.lock().expect("Fleet mock state lock");
            let item = state
                .integrations
                .get_mut(&integration_id)
                .expect("created child");
            item["description"] = saved_description;
            item["name"] = json!("different but marker-owned integration");
        }
        assert!(matches!(
            lease.finish().await,
            Err(FleetFailure::Cleanup(_))
        ));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{integration_id}")
                })
                .count(),
            0,
            "a marker-owned but unregistered specification is not deleted"
        );

        responder
            .state
            .lock()
            .expect("Fleet mock state lock")
            .integrations
            .get_mut(&integration_id)
            .expect("created child")["name"] = saved_name;
        assert!(lease.finish().await.is_ok());
        {
            let state = responder.state.lock().expect("Fleet mock state lock");
            assert!(state.parents.is_empty() && state.integrations.is_empty());
        }
        let requests = server.received_requests().await.unwrap();
        let child_delete = requests
            .iter()
            .position(|request| {
                request.method == "DELETE"
                    && request.url.path() == format!("/api/fleet/package_policies/{integration_id}")
            })
            .expect("child delete after ownership is restored");
        let parent_delete = requests
            .iter()
            .position(|request| {
                request.method == "POST" && request.url.path() == "/api/fleet/agent_policies/delete"
            })
            .expect("parent delete after child delete");
        assert!(child_delete < parent_delete);
    }

    #[tokio::test]
    async fn unknown_parent_agent_count_blocks_parent_delete_until_the_exact_read_is_safe() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());
        let parent_id = lease.parent_id().to_string();
        responder
            .state
            .lock()
            .expect("Fleet mock state lock")
            .parents
            .get_mut(&parent_id)
            .expect("created parent")["agents"] = Value::Null;
        assert!(matches!(
            lease.finish().await,
            Err(FleetFailure::Cleanup(_))
        ));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{}", lease.integration_id())
                })
                .count(),
            0,
            "the unsafe parent exact read blocks the final child delete"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .filter(|request| request.url.path() == "/api/fleet/agent_policies/delete")
                .count(),
            0
        );

        responder
            .state
            .lock()
            .expect("Fleet mock state lock")
            .parents
            .get_mut(&parent_id)
            .expect("created parent")["agents"] = json!(0);
        assert!(lease.finish().await.is_ok());
        {
            let state = responder.state.lock().expect("Fleet mock state lock");
            assert!(state.parents.is_empty() && state.integrations.is_empty());
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .filter(|request| request.url.path() == "/api/fleet/agent_policies/delete")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn failed_child_exact_read_blocks_deletes_until_the_persistent_fault_is_cleared() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());

        let integration_id = lease.integration_id().to_string();
        let child_reads_before_fault = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                request.method == "GET"
                    && request.url.path() == format!("/api/fleet/package_policies/{integration_id}")
            })
            .count();
        let deletes_before_fault = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "DELETE")
            .count();
        responder
            .state
            .lock()
            .expect("Fleet mock state lock")
            .failed_integration_reads
            .insert(integration_id.clone());
        assert!(matches!(
            lease.finish().await,
            Err(FleetFailure::Cleanup(_))
        ));
        assert!(matches!(
            lease.finish().await,
            Err(FleetFailure::Cleanup(_))
        ));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == "GET"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{integration_id}")
                })
                .count(),
            child_reads_before_fault + 6,
            "the child read fault remains active across cleanup retries"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "DELETE")
                .count(),
            deletes_before_fault
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/api/fleet/agent_policies/delete")
                .count(),
            0
        );

        responder
            .state
            .lock()
            .expect("Fleet mock state lock")
            .failed_integration_reads
            .remove(&integration_id);
        assert!(lease.finish().await.is_ok());
        let state = responder.state.lock().expect("Fleet mock state lock");
        assert!(state.parents.is_empty() && state.integrations.is_empty());
    }

    #[tokio::test]
    async fn failed_final_baseline_audit_retains_the_lease_for_a_second_finish() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());
        responder
            .state
            .lock()
            .expect("Fleet mock state lock")
            .failed_empty_parent_lists = 3;

        match lease.finish().await {
            Err(FleetFailure::Cleanup(message)) if message.contains("auditing") => {}
            Err(FleetFailure::Contract(message) | FleetFailure::Cleanup(message)) => {
                panic!("unexpected cleanup failure: {message}")
            }
            Ok(()) => panic!("final baseline audit unexpectedly succeeded"),
        }
        let requests = server.received_requests().await.unwrap();
        let child_delete = requests
            .iter()
            .position(|request| {
                request.method == "DELETE"
                    && request.url.path()
                        == format!("/api/fleet/package_policies/{}", lease.integration_id())
            })
            .expect("child deletion before final audit");
        let parent_delete = requests
            .iter()
            .position(|request| {
                request.method == "POST" && request.url.path() == "/api/fleet/agent_policies/delete"
            })
            .expect("parent deletion before final audit");
        assert!(child_delete < parent_delete);

        assert!(lease.finish().await.is_ok());
        {
            let state = responder.state.lock().expect("Fleet mock state lock");
            assert!(state.parents.is_empty() && state.integrations.is_empty());
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| {
                    request.method == "DELETE"
                        && request.url.path()
                            == format!("/api/fleet/package_policies/{}", lease.integration_id())
                })
                .count(),
            1,
            "the retry observes the already-deleted child without replaying deletion"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.url.path() == "/api/fleet/agent_policies/delete")
                .count(),
            1,
            "the retry observes the already-deleted parent without replaying deletion"
        );
    }

    #[tokio::test]
    async fn setup_precedes_all_baseline_reads_and_controller_mode_skips_only_setup() {
        let server = MockServer::start().await;
        let _responder = mount_stateful_fleet(&server).await;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());
        let requests = server.received_requests().await.unwrap();
        let status = requests
            .iter()
            .position(|request| request.url.path() == "/api/status")
            .unwrap();
        let setup = requests
            .iter()
            .position(|request| request.url.path() == "/api/fleet/setup")
            .unwrap();
        assert!(status < setup);
        for endpoint in [
            "/api/fleet/agent_policies",
            "/api/fleet/package_policies",
            "/api/fleet/epm/packages/installed",
        ] {
            assert!(
                requests
                    .iter()
                    .position(|request| request.url.path() == endpoint)
                    .unwrap()
                    > setup,
                "baseline read {endpoint} follows setup"
            );
        }
        assert!(lease.finish().await.is_ok());

        let controller = MockServer::start().await;
        let _responder = mount_stateful_fleet(&controller).await;
        let mut lease = FleetFixtureLease::new(profile(controller.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(true).await.is_ok());
        let requests = controller.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|request| request.url.path() == "/api/status")
        );
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() != "/api/fleet/setup")
        );
        assert!(lease.finish().await.is_ok());
    }

    #[tokio::test]
    async fn pre_arm_setup_and_baseline_failures_are_retryable_without_fixture_mutation() {
        for baseline_failure in [false, true] {
            let server = MockServer::start().await;
            let responder = mount_stateful_fleet(&server).await;
            if baseline_failure {
                responder.state.lock().unwrap().failed_baseline_parent_lists = 3;
            } else {
                responder.state.lock().unwrap().failed_setup_posts = 1;
            }
            let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
            assert!(lease.prepare_with_setup(false).await.is_err());
            let before_finish = server.received_requests().await.unwrap().len();
            assert!(lease.finish().await.is_ok());
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                before_finish
            );
            let requests = server.received_requests().await.unwrap();
            assert!(requests.iter().all(|request| {
                request.url.path() != "/api/fleet/agent_policies" || request.method != "POST"
            }));
            assert!(requests.iter().all(|request| request.url.path()
                != "/api/fleet/package_policies"
                || request.method == "GET"));
            responder.state.lock().unwrap().failed_setup_posts = 0;
            responder.state.lock().unwrap().failed_baseline_parent_lists = 0;
            assert!(lease.prepare_with_setup(false).await.is_ok());
            assert!(lease.finish().await.is_ok());
        }
    }

    #[tokio::test]
    async fn system_installed_by_setup_is_baseline_and_is_never_uninstalled() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        {
            let mut state = responder.state.lock().unwrap();
            state.system_installed = false;
            state.setup_installs_system = true;
        }
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());
        assert!(lease.finish().await.is_ok());
        assert!(responder.state.lock().unwrap().system_installed);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| {
                    !(request.method == "DELETE"
                        && request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
                })
        );
    }

    #[tokio::test]
    async fn confirmed_and_ambiguous_system_installs_preserve_the_package_lease_contract() {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        responder.state.lock().unwrap().system_installed = false;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_ok());
        assert!(lease.finish().await.is_ok());
        assert!(!responder.state.lock().unwrap().system_installed);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST"
                    && request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "DELETE"
                    && request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
                .count(),
            1
        );

        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        {
            let mut state = responder.state.lock().unwrap();
            state.system_installed = false;
            state.ambiguous_system_install = true;
        }
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(lease.prepare_with_setup(false).await.is_err());
        assert!(
            matches!(lease.finish().await, Err(FleetFailure::Cleanup(message)) if message.contains("claimed"))
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST"
                    && request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "DELETE"
                    && request.url.path() == "/api/fleet/epm/packages/system/2.0.0")
                .count(),
            0
        );
        responder.state.lock().unwrap().system_installed = false;
        assert!(lease.finish().await.is_ok());
    }

    #[tokio::test]
    async fn lost_created_policy_responses_are_recovered_once_by_finish() {
        for phase in ["parent", "bootstrap", "final"] {
            let server = MockServer::start().await;
            let responder = mount_stateful_fleet(&server).await;
            {
                let mut state = responder.state.lock().unwrap();
                state.lost_parent_create = phase == "parent";
                state.lost_bootstrap_create = phase == "bootstrap";
                state.lost_final_create = phase == "final";
            }
            let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
            assert!(
                lease.prepare_with_setup(false).await.is_err(),
                "{phase} response is lost"
            );
            assert!(
                lease.finish().await.is_ok(),
                "{phase} created state is cleaned"
            );
            {
                let state = responder.state.lock().unwrap();
                assert!(state.parents.is_empty() && state.integrations.is_empty());
            }
            let requests = server.received_requests().await.unwrap();
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.method == "POST"
                        && request.url.path() == "/api/fleet/agent_policies")
                    .count(),
                1
            );
            let integration_creates = requests
                .iter()
                .filter(|request| {
                    request.method == "POST" && request.url.path() == "/api/fleet/package_policies"
                })
                .count();
            assert_eq!(
                integration_creates,
                if phase == "parent" {
                    0
                } else if phase == "bootstrap" {
                    1
                } else {
                    2
                }
            );
        }
    }

    #[tokio::test]
    async fn inventory_drift_after_bootstrap_blocks_final_create_until_cleanup_can_audit_baseline()
    {
        let server = MockServer::start().await;
        let responder = mount_stateful_fleet(&server).await;
        responder.state.lock().unwrap().drift_after_bootstrap_delete = true;
        let mut lease = FleetFixtureLease::new(profile(server.uri()), "nonce-a");
        assert!(
            matches!(lease.prepare_with_setup(false).await, Err(FleetFailure::Contract(message)) if message.contains("inventory"))
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST"
                    && request.url.path() == "/api/fleet/package_policies")
                .count(),
            1
        );
        responder.state.lock().unwrap().inventory_drift = false;
        assert!(lease.finish().await.is_ok());
        let state = responder.state.lock().unwrap();
        assert!(state.parents.is_empty() && state.integrations.is_empty());
    }
}
