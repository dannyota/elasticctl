use super::*;
use elasticctl_api::state;
use std::collections::BTreeMap;

pub(super) struct RoundTrip<'a> {
    pub(super) config: &'a Path,
    pub(super) dir: PathBuf,
    pub(super) key: Option<&'a str>,
    pub(super) rule: String,
    pub(super) ip: String,
    pub(super) keyword: String,
}

pub(super) fn multiset(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

pub(super) fn verify_alerts(report: &Value, expected: &[&str]) -> StepResult {
    require(
        report["errors"].as_array().is_some_and(Vec::is_empty)
            && report["warnings"].as_array().is_some_and(Vec::is_empty)
            && report["hits_error"].is_null()
            && report["preview_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
            && report["hits"].as_u64() == Some(expected.len() as u64),
    )?;
    let hits = report["sample"].as_array().ok_or(StepError::Failed)?;
    let observed = hits
        .iter()
        .map(|hit| {
            let source = &hit["_source"];
            source
                .pointer("/event/code")
                .or_else(|| source.get("event.code"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(StepError::Failed)
        })
        .collect::<StepResult<Vec<_>>>()?;
    require(multiset(observed) == multiset(expected.iter().map(|s| (*s).into()).collect()))
}

impl<'a> RoundTrip<'a> {
    pub(super) fn new(
        config: &'a Path,
        scratch: &Path,
        key: Option<&'a str>,
        lease: &Lease,
    ) -> StepResult<Self> {
        let base = format!("{PREFIX}{}", lease.nonce);
        let run = Self {
            config,
            dir: scratch.join("mirror"),
            key,
            rule: format!("{base}-rule"),
            ip: format!("{base}-ip"),
            keyword: format!("{base}-keyword"),
        };
        for (kind, id) in [
            (Kind::Rule, &run.rule),
            (Kind::List, &run.ip),
            (Kind::List, &run.keyword),
        ] {
            require(lease.objects.iter().any(|o| o.kind == kind && o.id == *id))?;
        }
        Ok(run)
    }

    pub(super) fn command(&self) -> Command {
        let mut command = cli(self.config);
        for name in mcp_smoke::TARGET_OVERRIDES {
            command.env_remove(name);
        }
        if let Some(key) = self.key {
            command.env("ELASTICCTL_API_KEY", key);
        }
        command
    }

    pub(super) fn state_command(&self, action: &str) -> Command {
        let mut command = self.command();
        command
            .args(["state", action, &self.rule, "--dir"])
            .arg(&self.dir)
            .arg("--json");
        command
    }

    pub(super) fn values_path(&self, id: &str) -> PathBuf {
        self.dir
            .join("value-lists")
            .join(format!("{}.txt", api::file_stem(id)))
    }

    fn expected(&self, after: bool) -> [(&str, api::ValueListType, Vec<String>); 2] {
        let (ip, keyword) = if after {
            (vec!["10.0.0.0/8", "198.51.100.5/32"], vec!["block", "stay"])
        } else {
            (vec!["10.0.0.0/8", "192.0.2.0/24"], vec!["allow", "stay"])
        };
        [
            (
                &self.ip,
                api::ValueListType::IpRange,
                ip.into_iter().map(str::to_owned).collect(),
            ),
            (
                &self.keyword,
                api::ValueListType::Keyword,
                keyword.into_iter().map(str::to_owned).collect(),
            ),
        ]
    }

    pub(super) fn mirror(&self) -> StepResult<state::Mirror> {
        let mirror = checked_step(state::read_mirror(&self.dir))?;
        require(
            mirror.rules.len() == 1
                && mirror.rules[0].rule_id().ok() == Some(self.rule.as_str())
                && mirror.rules[0].as_map().get("enabled") == Some(&json!(false)),
        )?;
        Ok(mirror)
    }

    pub(super) async fn pull(&self, lease: &Lease) -> StepResult {
        lease.check_interrupt()?;
        let output = self
            .state_command("pull")
            .output()
            .map_err(|_| StepError::Failed)?;
        require(output.status.success())?;
        let report: Value =
            serde_json::from_slice(&output.stdout).map_err(|_| StepError::Failed)?;
        require(
            report["pulled"] == 1
                && report["selected"] == 1
                && report["value_lists"] == 2
                && report["exception_lists"] == 1
                && report["exception_items"] == 2,
        )?;
        let mirror = self.mirror()?;
        require(mirror.has_value_lists && mirror.value_lists.len() == 2)?;
        for (id, kind, values) in self.expected(false) {
            let pair = mirror
                .value_lists
                .iter()
                .find(|p| p.container.id == id)
                .ok_or(StepError::Failed)?;
            require(
                pair.container.list_type == kind
                    && pair.values.iter().cloned().collect::<Vec<_>>() == multiset(values),
            )?;
        }
        Ok(())
    }

    async fn guard_mirror(&self, t: &Transport, lease: &Lease) -> StepResult {
        let mirror = self.mirror()?;
        let owned = |kind| {
            lease
                .objects
                .iter()
                .filter(|o| o.kind == kind)
                .map(|o| o.id.as_str())
                .collect::<BTreeSet<_>>()
        };
        require(
            mirror
                .value_lists
                .iter()
                .map(|p| p.container.id.as_str())
                .collect::<BTreeSet<_>>()
                == owned(Kind::List)
                && mirror
                    .lists
                    .iter()
                    .map(|list| list.list_id().unwrap_or_default())
                    .collect::<BTreeSet<_>>()
                    == owned(Kind::Exception)
                && mirror
                    .items
                    .iter()
                    .map(|item| item.item_id().unwrap_or_default())
                    .collect::<BTreeSet<_>>()
                    == owned(Kind::Item),
        )?;
        for object in &lease.objects {
            let body = checked_step(t.get(&object.path()).await)?;
            require(object.owns(&body, &lease.nonce))?;
            match object.kind {
                Kind::Rule => {
                    let remote = checked_step(elasticctl_api::model::Rule::from_value(body))?;
                    require(
                        elasticctl_api::normalize::canonical(&remote)
                            == elasticctl_api::normalize::canonical(&mirror.rules[0]),
                    )?;
                }
                Kind::Exception => {
                    let remote =
                        checked_step(elasticctl_api::model::ExceptionList::from_value(body))?;
                    let local = mirror
                        .lists
                        .iter()
                        .find(|list| list.list_id().ok() == Some(object.id.as_str()))
                        .ok_or(StepError::Failed)?;
                    require(
                        elasticctl_api::normalize::canonical_list(&remote)
                            == elasticctl_api::normalize::canonical_list(local),
                    )?;
                }
                Kind::Item => {
                    let remote =
                        checked_step(elasticctl_api::model::ExceptionItem::from_value(body))?;
                    let local = mirror
                        .items
                        .iter()
                        .find(|item| item.item_id().ok() == Some(object.id.as_str()))
                        .ok_or(StepError::Failed)?;
                    require(
                        elasticctl_api::normalize::canonical_item(&remote)
                            == elasticctl_api::normalize::canonical_item(local),
                    )?;
                }
                Kind::List => {
                    let remote = checked_step(api::decode_remote_container(&body))?;
                    let local = mirror
                        .value_lists
                        .iter()
                        .find(|pair| pair.container.id == object.id)
                        .ok_or(StepError::Failed)?;
                    require(remote.container == local.container)?;
                }
            }
        }
        Ok(())
    }

    pub(super) async fn snapshot(&self, t: &Transport, lease: &Lease) -> StepResult<Value> {
        let mut objects = BTreeMap::new();
        for object in &lease.objects {
            let body = checked_step(t.get(&object.path()).await)?;
            require(object.owns(&body, &lease.nonce))?;
            let values = if object.kind == Kind::List {
                let kind = checked_step(api::decode_remote_container(&body))?
                    .container
                    .list_type;
                Some(multiset(
                    checked_step(api::export_values(t, &object.id, &kind).await)?.values,
                ))
            } else {
                None
            };
            objects.insert(object.path(), json!({"object":body,"values":values}));
        }
        serde_json::to_value(objects).map_err(|_| StepError::Failed)
    }

    pub(super) async fn read_back(&self, t: &Transport, after: bool) -> StepResult {
        for (id, kind, values) in self.expected(after) {
            let remote = checked_step(api::read_list(t, id).await)?.ok_or(StepError::Failed)?;
            require(
                remote.container.container.list_type == kind
                    && multiset(remote.stored.values) == multiset(values),
            )?;
        }
        self.disabled(t).await
    }

    async fn disabled(&self, t: &Transport) -> StepResult {
        let rule = checked_step(
            t.get(&format!(
                "/api/detection_engine/rules?rule_id={}",
                urlencode(&self.rule)
            ))
            .await,
        )?;
        require(rule["rule_id"] == self.rule && rule["enabled"] == false)
    }

    pub(super) async fn preview(&self, t: &Transport, lease: &Lease, after: bool) -> StepResult {
        lease.check_interrupt()?;
        self.disabled(t).await?;
        lease.check_interrupt()?;
        let output = self
            .command()
            .args([
                "rules",
                "preview",
                &self.rule,
                "--invocations",
                "1",
                "--sample",
                "100",
                "--json",
            ])
            .output()
            .map_err(|_| StepError::Failed)?;
        require(output.status.success())?;
        let report: Value =
            serde_json::from_slice(&output.stdout).map_err(|_| StepError::Failed)?;
        verify_alerts(
            &report,
            if after {
                &["1", "4", "5"]
            } else {
                &["2", "3", "5"]
            },
        )?;
        self.disabled(t).await
    }

    pub(super) async fn push(&self, t: &Transport, lease: &mut Lease) -> StepResult {
        lease.check_interrupt()?;
        self.guard_mirror(t, lease).await?;
        for (id, text) in [
            (&self.ip, "10.0.0.0/8\n198.51.100.5\n"),
            (&self.keyword, "block\nstay\n"),
        ] {
            std::fs::write(self.values_path(id), text).map_err(|_| StepError::Failed)?;
        }
        let before = self.snapshot(t, lease).await?;
        lease.check_interrupt()?;
        let preview = self
            .state_command("push")
            .output()
            .map_err(|_| StepError::Failed)?;
        require(preview.status.success())?;
        let summary: Value =
            serde_json::from_slice(&preview.stdout).map_err(|_| StepError::Failed)?;
        require(summary["applied"] == false && summary["pending"] == 0)?;
        require(self.snapshot(t, lease).await? == before)?;
        lease.check_interrupt()?;
        let report_path = self.dir.with_file_name("state-push-report.json");
        require(!report_path.exists())?;
        lease.state_push_pending = true;
        let output = self
            .state_command("push")
            .arg("--yes")
            .arg("--report")
            .arg(&report_path)
            .output()
            .map_err(|_| StepError::Failed)?;
        let report = std::fs::read(&report_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        if let Some(report) = report {
            settle_push_report(&report, lease, [&self.ip, &self.keyword])?;
        }
        require(output.status.success() && !lease.state_push_pending)?;
        let summary: Value =
            serde_json::from_slice(&output.stdout).map_err(|_| StepError::Failed)?;
        require(
            [
                "created",
                "updated",
                "lists_created",
                "lists_updated",
                "items_created",
                "items_updated",
                "items_removed",
            ]
            .iter()
            .all(|key| summary[*key] == 0),
        )?;
        require(
            summary["applied"] == true
                && summary["failed"] == 0
                && summary["pending"] == 0
                && summary["value_lists_updated"] == 2
                && summary["values_added"] == 2
                && summary["values_removed"] == 2
                && summary["value_lists_unknown"].as_u64().unwrap_or(0) == 0,
        )?;
        self.read_back(t, true).await
    }
}

pub(super) fn settle_push_report(report: &Value, lease: &mut Lease, ids: [&str; 2]) -> StepResult {
    require(report["applied"] == true)?;
    let entries = report["entries"].as_array().ok_or(StepError::Failed)?;
    let mut seen = BTreeSet::new();
    for entry in entries {
        let Some(id) = entry["rule_id"].as_str().filter(|id| ids.contains(id)) else {
            continue;
        };
        if entry["action"] == "read_back" {
            continue;
        }
        seen.insert(id);
        match entry["sent"].as_str() {
            Some("accepted") if entry["phase_verified"] == true => {}
            Some("refused")
                if entry["status"]
                    .as_u64()
                    .is_some_and(|s| (400..500).contains(&s) && s != 408) => {}
            Some("not_sent") => {}
            Some("uncertain") if entry["phase_verified"] == true => {}
            _ => return Err(StepError::Failed),
        }
    }
    require(seen.len() == 2)?;
    lease.state_push_pending = false;
    Ok(())
}
