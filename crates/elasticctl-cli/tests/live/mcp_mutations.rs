use super::mcp_smoke::{McpChild, McpProtocolPath};
use super::*;

#[path = "mcp_mutations/frames.rs"]
mod frames;
#[cfg(test)]
#[path = "mcp_mutations/tests.rs"]
mod tests;

#[path = "mcp_mutations/conformance.rs"]
mod conformance;

const SHIPPED_CLASSES: &[&str] = &["rules-toggle"];
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
    if ok {
        Ok(())
    } else {
        Err("mutation contract refused".into())
    }
}
fn marker(id: &str) -> TestResult {
    require(id.starts_with(LIVE_PREFIX) && id.len() > LIVE_PREFIX.len())
}
fn guarded_run(
    baseline: impl FnOnce() -> TestResult,
    body: impl FnOnce() -> TestResult,
    cleanup: impl FnOnce() -> TestResult,
    audit: impl FnOnce() -> TestResult,
) -> TestResult {
    baseline()?;
    let result = body();
    cleanup()?;
    audit()?;
    result
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
        let bytes = self
            .replies
            .recv_timeout(Duration::from_secs(75))
            .map_err(|_| "mutation reply unavailable")?
            .map_err(|_| "mutation reply failed")?
            .ok_or("mutation child closed")?;
        serde_json::from_slice(&bytes).map_err(|_| "mutation reply invalid".into())
    }
}
struct Session<C> {
    child: C,
    path: McpProtocolPath,
    form: bool,
    next: u64,
}
impl<C: Child> Session<C> {
    fn call(&mut self, name: &str, args: Value) -> TestResult<Value> {
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
        let f = self.call(
            "rules_set_enabled_plan",
            json!({"selectors":[rule],"enabled":enabled}),
        )?;
        frames::plan_id(&frames::content(f, self.path)?)
    }
    fn apply(&mut self, plan: &str, accept: bool) -> TestResult<Value> {
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
    r.map_err(|_| "mutation API failed".into())
}
fn runtime() -> TestResult<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().map_err(|_| "mutation runtime failed".into())
}
fn rule_body(id: &str, index: &str) -> TestResult<elasticctl_api::model::Rule> {
    marker(id)?;
    marker(index)?;
    let value = serde_json::from_str(&query_rule(id, index, "*", None))
        .map_err(|_| "invalid marker rule")?;
    safe(elasticctl_api::model::Rule::from_value(value))
}
async fn owned_rule(t: &Transport, id: &str) -> TestResult<elasticctl_api::model::Rule> {
    marker(id)?;
    let r = safe(elasticctl_api::rules::get(t, id).await)?;
    require(
        r.rule_id().ok() == Some(id)
            && r.as_map()["tags"]
                .as_array()
                .is_some_and(|a| a.contains(&json!(LIVE_TAG))),
    )?;
    Ok(r)
}
async fn toggle(t: &Transport, id: &str, enabled: bool) -> TestResult {
    owned_rule(t, id).await?;
    let p = safe(elasticctl_api::rules_ops::plan_set_enabled(t, &[id.into()], enabled).await)?;
    let o = safe(elasticctl_api::rules_ops::apply_set_enabled(t, &p, enabled).await)?;
    require(o.failed == 0 && o.total == 1)?;
    require(owned_rule(t, id).await?.enabled() == enabled)
}
fn contract(config: &Path, profile: &Profile, id: &str) -> TestResult {
    let rt = runtime()?;
    let t = safe(Transport::new(profile))?;
    let read = || rt.block_on(owned_rule(&t, id));
    let mut a = Session::spawn(config, McpProtocolPath::Current, true, true)?;
    for class in SHIPPED_CLASSES {
        require(*class == "rules-toggle")?;
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
        rt.block_on(toggle(&t, id, false))?;
        let outside = read()?;
        let stale = a.call("plan_apply", json!({"plan_id":plan}))?;
        frames::code(&frames::content(stale, a.path)?, "plan_stale")?;
        require(read()? == outside)?;
    }
    a.child.shutdown()?;
    let mut b = Session::spawn(config, McpProtocolPath::Legacy, true, true)?;
    let before = read()?;
    let plan = b.plan(id, !before.enabled())?;
    require(read()? == before)?;
    frames::applied(&b.apply(&plan, true)?, false)?;
    require(read()?.enabled() != before.enabled())?;
    b.child.shutdown()?;
    for path in [McpProtocolPath::Current, McpProtocolPath::Legacy] {
        let mut no = Session::spawn(config, path, false, true)?;
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

fn live_run(measurements: bool) -> TestResult {
    let _serial = serialize_live();
    let dir = tempfile::tempdir().map_err(|_| "mutation scratch failed")?;
    let config = write_live_config(dir.path());
    let profile = live_profile();
    let baseline = capture_baseline(&config, &profile).map_err(|_| "mutation baseline failed")?;
    let mut cleanup = LiveCleanup::new(config.clone(), profile.clone());
    // The wrapper owns cleanup errors and keeps private details out of Drop.
    cleanup.finished = true;
    assert_clean_baseline(&config, &cleanup, baseline.clone())
        .map_err(|_| "mutation baseline dirty")?;
    let id = unique_name("mutation-rule");
    let index = unique_name("mutation-index");
    marker(&id)?;
    marker(&index)?;
    cleanup.rule(id.clone());
    let rt = runtime()?;
    let t = safe(Transport::new(&profile))?;
    let run = (|| {
        rt.block_on(async {
            let body = rule_body(&id, &index)?;
            let (p, _) = safe(elasticctl_api::rules_ops::plan_create(&t, body).await)?;
            safe(elasticctl_api::rules_ops::apply_create(&t, &p).await)?;
            require(!owned_rule(&t, &id).await?.enabled())
        })?;
        if measurements {
            measure::run(&rt, &t, &profile, &id, &index, &mut cleanup)
        } else {
            contract(&config, &profile, &id)
        }
    })();
    let mut auditor = LiveCleanup::new(config.clone(), profile.clone());
    auditor.finished = true;
    guarded_run(
        || Ok(()),
        || run,
        || {
            rt.block_on(async {
                for rule in &cleanup.rules {
                    match elasticctl_api::rules::get(&t, rule).await {
                        Ok(_) => {
                            owned_rule(&t, rule).await?;
                        }
                        Err(e) if e.kind == ErrorKind::NotFound => {}
                        Err(_) => return Err("mutation cleanup read failed".into()),
                    }
                }
                Ok::<_, String>(())
            })?;
            cleanup
                .finish()
                .map_err(|_| "mutation cleanup failed".into())
        },
        || {
            assert_clean_baseline(&config, &auditor, baseline)
                .map_err(|_| "mutation final baseline failed".into())
        },
    )
}
#[path = "mcp_mutations/measure.rs"]
mod measure;
pub(super) fn run_contract() {
    if skip_unless_live() {
        return;
    }
    assert!(live_run(false).is_ok(), "mutation contract failed");
}
pub(super) fn run_measurements() {
    if skip_unless_live() {
        return;
    }
    assert!(live_run(true).is_ok(), "mutation measurements failed");
}
