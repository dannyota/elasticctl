use super::mcp_smoke::{McpChild, McpProtocolPath};
use super::*;

#[path = "mcp_mutations/frames.rs"]
mod frames;
#[cfg(test)]
#[path = "mcp_mutations/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "mcp_mutations/classification_tests.rs"]
mod classification_tests;

#[path = "mcp_mutations/conformance.rs"]
mod conformance;

const SHIPPED_CLASSES: &[&str] = &["rules-toggle", "alerts-triage", "cases", "rules-create"];
const MUTATION_TOOLS: &[&str] = &[
    "plan_apply",
    "plan_discard",
    "plan_get",
    "plan_list",
    "rules_set_enabled_plan",
    "alerts_set_status_plan",
    "alerts_set_tags_plan",
    "cases_comment_plan",
    "cases_create_plan",
    "cases_set_status_plan",
    "rules_create_plan",
];

fn require(ok: bool) -> TestResult {
    if ok { Ok(()) } else { Err("contract".into()) }
}
fn marker(id: &str) -> TestResult {
    require(id.starts_with(LIVE_PREFIX) && id.len() > LIVE_PREFIX.len())
}

trait Child {
    fn send(&mut self, frame: Value) -> TestResult;
    fn receive(&mut self) -> TestResult<Value>;
}
impl Child for McpChild {
    fn send(&mut self, frame: Value) -> TestResult {
        McpChild::send(self, frame)
    }
    fn receive(&mut self) -> TestResult<Value> {
        check_cancelled()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(75);
        let bytes = loop {
            check_cancelled()?;
            match self.replies.recv_timeout(Duration::from_millis(100)) {
                Ok(reply) => break reply.map_err(|_| "contract")?.ok_or("contract")?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    if std::time::Instant::now() < deadline => {}
                Err(_) => return Err("contract".into()),
            }
        };
        serde_json::from_slice(&bytes).map_err(|_| "mutation reply invalid".into())
    }
}
struct Session<C> {
    child: C,
    path: McpProtocolPath,
    form: bool,
    next: u64,
    owned: std::collections::BTreeSet<String>,
    plans: std::collections::BTreeMap<String, String>,
    checks: std::collections::BTreeMap<String, (Vec<String>, Value)>,
}
impl<C: Child> Session<C> {
    fn call(&mut self, name: &str, args: Value) -> TestResult<Value> {
        check_cancelled()?;
        let id = self.next;
        self.next += 1;
        self.child
            .send(frames::request(self.path, id, name, args, self.form))?;
        let frame = self.child.receive()?;
        require(frame["jsonrpc"] == "2.0" && frame["id"] == id)?;
        Ok(frame)
    }
    fn plan(&mut self, rule: &str, enabled: bool) -> TestResult<String> {
        marker(rule)?;
        require(self.owned.contains(rule))?;
        let f = self.call(
            "rules_set_enabled_plan",
            json!({"selectors":[rule],"enabled":enabled}),
        )?;
        let content = frames::content(f, self.path)?;
        verify_view(&content, rule)?;
        let id = frames::plan_id(&content)?;
        self.plans.insert(id.clone(), rule.into());
        Ok(id)
    }
    fn apply(&mut self, plan: &str, accept: bool) -> TestResult<Value> {
        let rule = self.plans.get(plan).ok_or("contract")?.clone();
        require(self.owned.contains(&rule))?;
        let view = self.call("plan_get", json!({"plan_id":plan}))?;
        let content = frames::content(view, self.path)?;
        if let Some((targets, operation)) = self.checks.get(plan) {
            self.check_change(&content, targets, operation)?;
        } else {
            verify_view(&content, &rule)?;
        }
        let id = self.next;
        self.next += 1;
        let request = frames::request(
            self.path,
            id,
            "plan_apply",
            json!({"plan_id":plan}),
            self.form,
        );
        self.child.send(request.clone())?;
        let question = self.child.receive()?;
        match self.path {
            McpProtocolPath::Current => {
                require(question["id"] == id)?;
                let answer = frames::answer(&question, accept)?;
                let mut retry = request;
                retry["id"] = json!(self.next);
                self.next += 1;
                for (key, value) in answer.as_object().ok_or("invalid answer")? {
                    retry["params"][key] = value.clone();
                }
                check_cancelled()?;
                self.child.send(retry.clone())?;
                let result = self.child.receive()?;
                require(result["id"] == retry["id"])?;
                frames::content(result, self.path)
            }
            McpProtocolPath::Legacy => {
                require(
                    question["method"] == "elicitation/create" && question.get("id").is_some(),
                )?;
                frames::form(&question["params"])?;
                check_cancelled()?;
                self.child
                    .send(frames::legacy_answer(question["id"].clone(), accept))?;
                let result = self.child.receive()?;
                require(result["id"] == id)?;
                frames::content(result, self.path)
            }
        }
    }
}
impl Session<McpChild> {
    fn spawn(
        config: &Path,
        path: McpProtocolPath,
        form: bool,
        mutations: bool,
    ) -> TestResult<Self> {
        let mut command = mcp_smoke::offline_child_command(config, false);
        if mutations {
            command.args(["--allow-mutations", &SHIPPED_CLASSES.join(",")]);
        }
        let child = McpChild::spawn_command(command, false)?;
        let mut s = Self {
            child,
            path,
            form,
            next: 10,
            owned: Default::default(),
            plans: Default::default(),
            checks: Default::default(),
        };
        if matches!(path, McpProtocolPath::Legacy) {
            s.child.send(
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":frames::capabilities(form),
                "clientInfo":{"name":"elasticctl-marker-harness","version":"1"}}}),
            )?;
            let f = Child::receive(&mut s.child)?;
            require(f.pointer("/result/protocolVersion") == Some(&json!("2025-11-25")))?;
            s.child.notify("notifications/initialized", json!({}))?;
        }
        Ok(s)
    }
}

fn safe<T>(r: elasticctl_core::Result<T>) -> TestResult<T> {
    r.map_err(|_| "contract".into())
}
fn runtime() -> TestResult<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().map_err(|_| "contract".into())
}
fn rule_body(id: &str, index: &str) -> TestResult<elasticctl_api::model::Rule> {
    marker(id)?;
    marker(index)?;
    let mut value: Value = serde_json::from_str(&query_rule(id, index, "*", None))
        .map_err(|_| "invalid marker rule")?;
    value["tags"] = json!([LIVE_TAG, id]);
    safe(elasticctl_api::model::Rule::from_value(value))
}
/// The rule as the plans see it. An enabled rule runs on its own, and Kibana then
/// rewrites `execution_summary`, so "no change" compares this form, the same one
/// stale detection uses, not the raw read.
fn rule_state(rule: &elasticctl_api::model::Rule) -> elasticctl_api::model::Rule {
    elasticctl_api::normalize::canonical(rule)
}
async fn owned_rule(t: &Transport, id: &str) -> TestResult<elasticctl_api::model::Rule> {
    marker(id)?;
    let r = safe(elasticctl_api::rules::get(t, id).await)?;
    require(
        r.rule_id().ok() == Some(id)
            && r.as_map()["tags"]
                .as_array()
                .is_some_and(|a| a.contains(&json!(LIVE_TAG)) && a.contains(&json!(id))),
    )?;
    Ok(r)
}
async fn toggle(t: &Transport, registry: &Registry, id: &str, enabled: bool) -> TestResult {
    check_cancelled()?;
    require(registry.rules.contains(id))?;
    owned_rule(t, id).await?;
    let p = safe(elasticctl_api::rules_ops::plan_set_enabled(t, &[id.into()], enabled).await)?;
    exact_targets(&p.targets, &[id.into()])?;
    let o = safe(elasticctl_api::rules_ops::apply_set_enabled(t, &p, enabled).await)?;
    require(o.failed == 0 && o.total == 1)?;
    require(owned_rule(t, id).await?.as_map().get("enabled") == Some(&json!(enabled)))
}
fn contract(
    config: &Path,
    profile: &Profile,
    registry: &mut Registry,
    id: &str,
    index: &str,
) -> TestResult {
    let rt = runtime()?;
    let t = safe(Transport::new(profile))?;
    require(registry.rules.contains(id))?;
    let read = || {
        rt.block_on(owned_rule(&t, id))
            .map(|rule| rule_state(&rule))
    };
    let mut a = Session::spawn(config, McpProtocolPath::Current, true, true)?;
    a.owned = registry.rules.clone();
    {
        let before = read()?;
        require(!before.enabled())?;
        let plan = a.plan(id, true)?;
        require(read()? == before)?;
        frames::applied(&a.apply(&plan, true)?, false)?;
        require(read()?.enabled())?;
        let after = read()?;
        let replay = a.call("plan_apply", json!({"plan_id":plan}))?;
        frames::applied(&frames::content(replay, a.path)?, true)?;
        require(read()? == after)?;
        let plan = a.plan(id, false)?;
        frames::code(&a.apply(&plan, false)?, "plan_declined")?;
        require(read()? == after)?;
        let plan = a.plan(id, false)?;
        rt.block_on(toggle(&t, registry, id, false))?;
        let outside = read()?;
        let stale = a.call("plan_apply", json!({"plan_id":plan}))?;
        frames::code(&frames::content(stale, a.path)?, "plan_stale")?;
        require(read()? == outside)?;
    }
    extension::run(
        &mut a,
        &rt,
        &cleanup_transport(profile)?,
        registry,
        id,
        index,
    )?;
    a.child.shutdown()?;
    let mut b = Session::spawn(config, McpProtocolPath::Legacy, true, true)?;
    b.owned = registry.rules.clone();
    let before = read()?;
    let plan = b.plan(id, !before.enabled())?;
    require(read()? == before)?;
    frames::applied(&b.apply(&plan, true)?, false)?;
    require(read()?.enabled() != before.enabled())?;
    b.child.shutdown()?;
    for path in [McpProtocolPath::Current, McpProtocolPath::Legacy] {
        let mut no = Session::spawn(config, path, false, true)?;
        no.owned = registry.rules.clone();
        let before = read()?;
        let plan = no.plan(id, !before.enabled())?;
        let f = no.call("plan_apply", json!({"plan_id":plan}))?;
        frames::code(&frames::content(f, path)?, "confirmation_unavailable")?;
        require(read()? == before)?;
        no.child.shutdown()?;
    }
    let mut c = Session::spawn(config, McpProtocolPath::Current, false, false)?;
    let before = read()?;
    for tool in MUTATION_TOOLS {
        let f = c.call(tool, json!({}))?;
        require(f.pointer("/error/code") == Some(&json!(-32601)))?;
    }
    require(read()? == before)?;
    c.child.shutdown()
}

fn live_run(measurements: bool, started: &std::cell::Cell<bool>) -> TestResult {
    let _serial = serialize_live();
    let dir = tempfile::tempdir().map_err(|_| "contract")?;
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let rt = runtime()?;
    let t = safe(Transport::new(&profile))?;
    let mut registry = Registry::default();
    let signals = Signals::install(&rt)?;
    let mut baseline = None;
    let result = orchestrate(
        &rt,
        &t,
        &cleanup_transport(&profile)?,
        &mut registry,
        || {
            rt.block_on(lab_identity::baseline(
                &t,
                &profile,
                std::env::var("ELASTICCTL_MUTATION_LAB").as_deref() == Ok("1"),
            ))?;
            if baseline.is_none() {
                baseline = Some(capture_baseline(&config, &profile)?);
            }
            let mut audit = LiveCleanup::new(config.clone(), profile.clone());
            audit.finished = true;
            assert_clean_baseline(&config, &audit, baseline.clone().ok_or("baseline_failed")?)
        },
        |registry| {
            started.set(true);
            let id = unique_name("mutation-rule");
            let index = unique_name("mutation-index");
            rt.block_on(create_rule(&t, registry, &id, &index))?;
            if measurements {
                measure::run(&rt, &t, &profile, &id, &index, registry)
            } else {
                contract(&config, &profile, registry, &id, &index)
            }
        },
    );
    drop(signals);
    result
}
#[path = "mcp_mutations/measure.rs"]
mod measure;
fn finish_contract(result: TestResult, started: bool) {
    if let Err(error) = result {
        let class = match error.as_str() {
            "cleanup_failed" => ConformanceFailureClass::Cleanup,
            "baseline_failed" if !started => ConformanceFailureClass::Harness,
            "baseline_failed" => ConformanceFailureClass::Cleanup,
            _ => ConformanceFailureClass::Contract,
        };
        panic_conformance(class, error);
    }
}
pub(super) fn run_contract() {
    if skip_unless_live() {
        return;
    }
    let started = std::cell::Cell::new(false);
    let result = live_run(false, &started);
    finish_contract(result, started.get());
}
pub(super) fn run_measurements() {
    if skip_unless_live() {
        return;
    }
    if let Err(class) = live_run(true, &std::cell::Cell::new(false)) {
        panic!("{class}");
    }
}

#[path = "mcp_mutations/ownership.rs"]
mod ownership;
use ownership::*;

#[cfg(test)]
#[path = "mcp_mutations/ownership_tests.rs"]
mod ownership_tests;

#[path = "mcp_mutations/lab_identity.rs"]
mod lab_identity;

#[cfg(test)]
#[path = "mcp_mutations/lab_tests.rs"]
mod lab_tests;

#[cfg(test)]
#[path = "mcp_mutations/extension_tests.rs"]
mod extension_tests;

#[path = "mcp_mutations/extension.rs"]
mod extension;

#[cfg(test)]
#[path = "mcp_mutations/extension_conformance.rs"]
mod extension_conformance;

#[cfg(test)]
#[path = "mcp_mutations/pending_tests.rs"]
mod pending_tests;
