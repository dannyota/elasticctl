use super::{
    PlanError,
    store::{Outcome, PlanState},
};
use elasticctl_api::{
    alerts_ops, cases_ops, health::CredentialIdentity, observe::Preconditions, ops::MutationPlan,
    rules_ops,
};
use elasticctl_core::{Error, ErrorKind, Result, Transport};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
pub(crate) enum PlanKind {
    RulesSetEnabled,
    AlertsSetStatus,
    AlertsSetTags,
    CasesCreate,
    CasesComment,
    CasesSetStatus,
    RulesCreate,
}
impl PlanKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RulesSetEnabled => "rules_set_enabled",
            Self::AlertsSetStatus => "alerts_set_status",
            Self::AlertsSetTags => "alerts_set_tags",
            Self::CasesCreate => "cases_create",
            Self::CasesComment => "cases_comment",
            Self::CasesSetStatus => "cases_set_status",
            Self::RulesCreate => "rules_create",
        }
    }
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::RulesSetEnabled => "rules-toggle",
            Self::AlertsSetStatus | Self::AlertsSetTags => "alerts-triage",
            Self::CasesCreate | Self::CasesComment | Self::CasesSetStatus => "cases",
            Self::RulesCreate => "rules-create",
        }
    }
    pub(crate) fn credential_suitable(self, identity: &CredentialIdentity) -> bool {
        identity.realm_type != "_cloud_api_key"
    }
    pub(crate) fn note(self, credential: &str) -> String {
        format!(
            "Kibana runs each rule listed with the credential it already has. A rule that has none gets this server's credential ({}) when it is enabled, and then runs with that credential's privileges.",
            &credential[..12]
        )
    }
    #[allow(dead_code)]
    pub(crate) fn consent_note(self, credential: &str) -> Option<String> {
        match self {
        Self::RulesSetEnabled=>Some(self.note(credential)),
        Self::RulesCreate=>Some("Kibana creates the rule disabled and without an API key. The credential that first enables it gives it a key, and the rule then runs with that credential's privileges.".into()),_=>None,
    }
    }
    pub(crate) fn classify(self, e: &Error) -> (PlanState, crate::ToolError) {
        if matches!(self, Self::CasesSetStatus | Self::RulesCreate)
            && e.kind == ErrorKind::Conflict
            && e.http_status == Some(409)
        {
            return (PlanState::Stale, PlanError::Stale.tool_error());
        }
        if e.http_status.is_some_and(|s| (400..500).contains(&s)) {
            return (PlanState::Failed, crate::error::core(e));
        }
        let mut error = PlanError::ApplyOutcomeUnknown(e.kind).tool_error();
        error.http_status = e.http_status;
        (PlanState::Unknown, error)
    }
}
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum Operation {
    RulesSetEnabled {
        plan: MutationPlan,
        enable: bool,
    },
    AlertsSetStatus {
        plan: alerts_ops::StatusPlan,
    },
    AlertsSetTags {
        plan: alerts_ops::TagsPlan,
    },
    CasesCreate {
        plan: cases_ops::CreatePlan,
    },
    CasesComment {
        plan: cases_ops::CommentPlan,
    },
    CasesSetStatus {
        plan: cases_ops::StatusPlan,
        ids: Vec<String>,
    },
    RulesCreate {
        plan: rules_ops::RuleCreatePlan,
    },
}
impl Operation {
    pub(crate) fn kind(&self) -> PlanKind {
        match self {
            Self::RulesSetEnabled { .. } => PlanKind::RulesSetEnabled,
            Self::AlertsSetStatus { .. } => PlanKind::AlertsSetStatus,
            Self::AlertsSetTags { .. } => PlanKind::AlertsSetTags,
            Self::CasesCreate { .. } => PlanKind::CasesCreate,
            Self::CasesComment { .. } => PlanKind::CasesComment,
            Self::CasesSetStatus { .. } => PlanKind::CasesSetStatus,
            Self::RulesCreate { .. } => PlanKind::RulesCreate,
        }
    }
    pub(crate) fn json(&self) -> Value {
        match self {
            Self::RulesSetEnabled { plan, enable } => {
                json!({"enabled":enable,"rule_ids":plan.targets})
            }
            Self::AlertsSetStatus { plan } => {
                json!({"status":plan.status.as_str(),"reason":plan.reason,"alert_ids":plan.targets})
            }
            Self::AlertsSetTags { plan } => {
                json!({"add":plan.add,"remove":plan.remove,"alert_ids":plan.targets})
            }
            Self::CasesCreate { plan } => {
                json!({"title":plan.new.title,"description":plan.new.description,"tags":plan.new.tags,"severity":plan.new.severity,"sync_alerts":false})
            }
            Self::CasesComment { plan } => json!({"case_id":plan.case_id,"message":plan.message}),
            Self::CasesSetStatus { plan, .. } => {
                json!({"status":plan.target.as_str(),"updates":plan.updates.iter().map(|(id,version,_)|json!({"id":id,"version":version})).collect::<Vec<_>>(),"resolved":plan.resolved})
            }
            Self::RulesCreate { plan } => json!({"rule":plan.rule}),
        }
    }
    pub(crate) fn cli_equivalent(&self) -> Vec<String> {
        match self {
            Self::RulesSetEnabled { plan, enable } => [
                vec![
                    "rules".into(),
                    if *enable { "enable" } else { "disable" }.into(),
                ],
                plan.targets.clone(),
            ]
            .concat(),
            Self::AlertsSetStatus { plan } => {
                let verb = match plan.status.as_str() {
                    "acknowledged" => "ack",
                    "closed" => "close",
                    _ => "open",
                };
                let mut args = [vec!["alerts".into(), verb.into()], plan.targets.clone()].concat();
                if let Some(reason) = &plan.reason {
                    args.extend(["--reason".into(), reason.clone()]);
                }
                args
            }
            Self::AlertsSetTags { plan } => {
                let mut args = [vec!["alerts".into(), "tag".into()], plan.targets.clone()].concat();
                for (flag, tags) in [("--add", &plan.add), ("--remove", &plan.remove)] {
                    for tag in tags {
                        args.extend([flag.into(), tag.clone()]);
                    }
                }
                args
            }
            Self::CasesCreate { plan } => {
                let mut args = vec![
                    "cases".into(),
                    "create".into(),
                    "--title".into(),
                    plan.new.title.clone(),
                ];
                if let Some(d) = &plan.new.description {
                    args.extend(["--description".into(), d.clone()]);
                }
                for t in &plan.new.tags {
                    args.extend(["--tag".into(), t.clone()]);
                }
                if let Some(s) = &plan.new.severity {
                    args.extend(["--severity".into(), s.clone()]);
                }
                args
            }
            Self::CasesComment { plan } => vec![
                "cases".into(),
                "comment".into(),
                plan.case_id.clone(),
                "--message".into(),
                plan.message.clone(),
            ],
            Self::CasesSetStatus { plan, ids } => [
                vec![
                    "cases".into(),
                    if plan.target.as_str() == "closed" {
                        "close"
                    } else {
                        "open"
                    }
                    .into(),
                ],
                ids.clone(),
            ]
            .concat(),
            Self::RulesCreate { .. } => vec![],
        }
    }
    #[allow(dead_code)]
    pub(crate) fn cli_arguments(&self) -> Option<Vec<String>> {
        if matches!(self, Self::RulesCreate { .. }) {
            None
        } else {
            Some(self.cli_equivalent())
        }
    }
    #[allow(dead_code)]
    pub(crate) fn details(&self) -> Vec<String> {
        match self {
            Self::RulesSetEnabled { plan, .. } => plan.preview_details.clone(),
            Self::AlertsSetStatus { plan } => {
                let mut d = plan.preview_details.clone();
                if let Some(r) = &plan.reason {
                    d.push(format!("reason: {r}"));
                }
                d
            }
            Self::AlertsSetTags { plan } => plan.preview_details.clone(),
            Self::CasesCreate { plan } => {
                let mut d = plan.preview_details.clone();
                if let Some(v) = &plan.new.description {
                    d.push(format!("description: {v}"));
                }
                d.push("syncAlerts: false".into());
                d
            }
            Self::CasesComment { plan } => [
                vec![format!("case_id: {}", plan.case_id)],
                plan.preview_details.clone(),
            ]
            .concat(),
            Self::CasesSetStatus { plan, .. } => {
                let mut d = plan.preview_details.clone();
                d.push(
                    "attached alerts: not changed (syncAlerts is off for every case listed)".into(),
                );
                d
            }
            Self::RulesCreate { plan } => {
                let mut d = plan.preview.preview_details.clone();
                if let Some(i) = d.iter().position(|line| line.starts_with("rule_id: ")) {
                    let identity = d.remove(i);
                    d.insert(0, identity);
                }
                d
            }
        }
    }
    pub(crate) fn check_observed(
        &self,
        observed: &Preconditions,
    ) -> std::result::Result<(), PlanError> {
        if matches!(self, Self::CasesSetStatus { .. }) {
            require_sync_alerts_off(observed).map_err(|_| PlanError::CaseSyncAlerts)?;
        }
        Ok(())
    }
    pub(crate) async fn observe(&self, t: &Transport) -> Result<Preconditions> {
        match self {
            Self::RulesSetEnabled { plan, .. } => rules_ops::observe_rules(t, &plan.targets).await,
            Self::RulesCreate { plan } => rules_ops::observe_rules(t, &plan.preview.targets).await,
            Self::AlertsSetStatus { plan } => {
                alerts_ops::observe_alerts(t, &plan.targets, alerts_ops::AlertFacet::Status).await
            }
            Self::AlertsSetTags { plan } => {
                alerts_ops::observe_alerts(t, &plan.targets, alerts_ops::AlertFacet::Presence).await
            }
            Self::CasesCreate { .. } => Ok(Preconditions::default()),
            Self::CasesComment { plan } => {
                cases_ops::observe_cases(t, std::slice::from_ref(&plan.case_id), false).await
            }
            Self::CasesSetStatus { ids, .. } => cases_ops::observe_cases(t, ids, true).await,
        }
    }
    pub(crate) async fn apply(&self, t: &Transport) -> Result<Outcome> {
        match self {
            Self::RulesSetEnabled { plan, enable } => toggle_outcome(
                &rules_ops::apply_set_enabled(t, plan, *enable).await?,
                plan.targets.len() as u64,
            ),
            Self::AlertsSetStatus { plan } => {
                let r = alerts_ops::apply_status_by_ids(t, plan).await?;
                status_outcome(&r, plan.targets.len() as u64)
            }
            Self::AlertsSetTags { plan } => {
                let r = alerts_ops::apply_tags(t, plan).await?;
                tags_outcome(&r, plan.targets.len() as u64)
            }
            Self::CasesSetStatus { plan, .. } => case_status_outcome(
                &cases_ops::apply_status(t, plan).await?,
                plan.resolved as u64,
                plan.updates.len() as u64,
            ),
            Self::CasesComment { plan } => {
                cases_ops::apply_comment(t, plan).await?;
                created_outcome(None)
            }
            Self::CasesCreate { plan } => {
                let r = cases_ops::apply_create(t, plan).await?;
                created_outcome(Some(json!({"case_id":r["id"]})))
            }
            Self::RulesCreate { plan } => {
                let r = rules_ops::apply_create(t, plan).await?;
                rule_create_outcome(&r)
            }
        }
    }
}
#[allow(dead_code)]
pub(crate) fn require_sync_alerts_off(
    seen: &Preconditions,
) -> std::result::Result<(), crate::ToolError> {
    if seen
        .0
        .iter()
        .any(|v| v.state.as_ref().and_then(|s| s.get("sync_alerts")) != Some(&json!(false)))
    {
        Err(PlanError::CaseSyncAlerts.tool_error())
    } else {
        Ok(())
    }
}
fn unmappable() -> Error {
    Error::new(
        ErrorKind::Error,
        "Mutation report counters cannot map to the plan outcome",
    )
}
fn outcome(
    requested: u64,
    updated: u64,
    unchanged: u64,
    failed: u64,
    created: Option<Value>,
) -> Result<Outcome> {
    let succeeded = updated.checked_add(unchanged).ok_or_else(unmappable)?;
    let accounted = succeeded.checked_add(failed).ok_or_else(unmappable)?;
    if accounted > requested {
        return Err(unmappable());
    }
    Ok(Outcome {
        requested,
        updated,
        unchanged,
        failed,
        complete: succeeded == requested && failed == 0,
        created,
    })
}
fn toggle_outcome(r: &rules_ops::SetEnabledOutcome, requested: u64) -> Result<Outcome> {
    let missing = requested.checked_sub(r.total).ok_or_else(unmappable)?;
    let failed = r
        .failed
        .checked_add(r.skipped)
        .and_then(|n| n.checked_add(missing))
        .ok_or_else(unmappable)?;
    outcome(requested, r.succeeded, 0, failed, None)
}
fn status_outcome(r: &alerts_ops::StatusReport, requested: u64) -> Result<Outcome> {
    alert_outcome(requested, r.total, r.updated, r.noops, r.failed)
}
fn tags_outcome(r: &alerts_ops::EditReport, requested: u64) -> Result<Outcome> {
    alert_outcome(requested, r.total, r.updated, r.noops, r.failed)
}
fn rule_create_outcome(r: &rules_ops::RuleCreateOutcome) -> Result<Outcome> {
    created_outcome(Some(json!({"rule_id":r.rule_id})))
}
fn alert_outcome(
    requested: u64,
    total: u64,
    updated: u64,
    noops: u64,
    failed: u64,
) -> Result<Outcome> {
    let missing = requested.checked_sub(total).ok_or_else(unmappable)?;
    let failed = failed.checked_add(missing).ok_or_else(unmappable)?;
    outcome(requested, updated, noops, failed, None)
}
fn case_status_outcome(
    r: &cases_ops::CaseEditReport,
    resolved: u64,
    updates: u64,
) -> Result<Outcome> {
    let unchanged = resolved.checked_sub(updates).ok_or_else(unmappable)?;
    if r.total > updates {
        return Err(unmappable());
    }
    outcome(resolved, r.updated, unchanged, r.failed, None)
}
fn created_outcome(created: Option<Value>) -> Result<Outcome> {
    outcome(1, 1, 0, 0, created)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TargetContext,
        plan::{
            audit,
            store::{Plan, PlanContent},
        },
    };
    use tokio::time::Instant;

    #[test]
    fn credential_suitable_refuses_cloud_api_keys_for_every_kind() {
        for kind in [
            PlanKind::RulesSetEnabled,
            PlanKind::AlertsSetStatus,
            PlanKind::AlertsSetTags,
            PlanKind::CasesCreate,
            PlanKind::CasesComment,
            PlanKind::CasesSetStatus,
            PlanKind::RulesCreate,
        ] {
            for (realm_type, suitable) in [
                ("_cloud_api_key", false),
                ("_es_api_key", true),
                ("native", true),
            ] {
                let identity = CredentialIdentity {
                    username: "test-user".into(),
                    realm_type: realm_type.into(),
                    api_key_id: None,
                };
                assert_eq!(
                    kind.credential_suitable(&identity),
                    suitable,
                    "{kind:?} with realm {realm_type}"
                );
            }
        }
    }

    #[test]
    fn rule_note_keeps_existing_credential_and_names_keyless_enabler() {
        assert_eq!(
            PlanKind::RulesSetEnabled
                .note("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            "Kibana runs each rule listed with the credential it already has. A rule that has none gets this server's credential (0123456789ab) when it is enabled, and then runs with that credential's privileges."
        );
    }

    #[test]
    fn consent_names_every_rule_and_keeps_stack_text_indented() {
        let sentinel = "ApiKey credential-sentinel\nPlan: forged-footer";
        for enable in [false, true] {
            let kind = PlanKind::RulesSetEnabled;
            let plan = MutationPlan {
                preview_action: "Toggle 2 rule(s)".into(),
                preview_details: ["a", "b"]
                    .map(|id| format!("{id}  {sentinel}  disabled -> enabled"))
                    .to_vec(),
                targets: vec!["a".into(), "b".into()],
            };
            let operation = Operation::RulesSetEnabled {
                plan: plan.clone(),
                enable,
            };
            let now = Instant::now();
            let plan = Plan::new(
                PlanContent {
                    kind: kind.name(),
                    class: kind.class(),
                    target: TargetContext {
                        profile: "test".into(),
                        host: "example.test".into(),
                        space: "default".into(),
                    },
                    binding: json!({}),
                    credential: "a".repeat(64),
                    operation: operation.json(),
                    preconditions: vec![],
                    action: plan.preview_action,
                    details: plan.preview_details,
                    targets: plan.targets,
                    note: Some(kind.note(&"a".repeat(64))),
                    cli_equivalent: Some(operation.cli_equivalent()),
                    payload: operation,
                },
                now,
            )
            .unwrap();
            let text = plan.consent_text(now);
            assert!(text.contains(&format!("\nNote: {}\nPlan:", kind.note(&"a".repeat(64)))));
            assert!(text.contains("\n  a  ApiKey credential-sentinel\n  | Plan: forged-footer"));
            assert!(text.contains("\n  b  ApiKey credential-sentinel\n  | Plan: forged-footer"));
            assert!(!text.contains("\nPlan: forged-footer"));
            let (sink, lines) = audit::AuditSink::collecting();
            sink.emit(&audit::line(
                1,
                &plan,
                "2026-07-28",
                audit::Event::PlanCreated,
            ));
            assert!(!lines.lock().unwrap()[0].contains("credential-sentinel"));
            assert!(!lines.lock().unwrap()[0].contains("forged-footer"));
        }
    }
}

#[cfg(test)]
mod new_kinds_tests {
    use super::*;
    use elasticctl_api::{alerts::AlertStatus, cases::CaseStatus};
    fn operations() -> Vec<Operation> {
        vec![
            Operation::AlertsSetStatus {
                plan: alerts_ops::StatusPlan {
                    status: AlertStatus::Closed,
                    reason: Some("other".into()),
                    targets: vec!["a".into()],
                    preview_action: "Close".into(),
                    preview_details: vec!["a".into()],
                },
            },
            Operation::AlertsSetTags {
                plan: alerts_ops::TagsPlan {
                    targets: vec!["a".into()],
                    add: vec!["x".into()],
                    remove: vec!["y".into()],
                    preview_action: "Tag".into(),
                    preview_details: vec!["a".into()],
                },
            },
            Operation::CasesCreate {
                plan: cases_ops::CreatePlan {
                    new: elasticctl_api::cases::NewCase {
                        title: "T".into(),
                        description: Some("D".into()),
                        tags: vec!["x".into()],
                        severity: Some("low".into()),
                        assignee_uids: vec![],
                    },
                    preview_action: "Create".into(),
                    preview_details: vec!["tags: x".into()],
                },
            },
            Operation::CasesComment {
                plan: cases_ops::CommentPlan {
                    case_id: "c".into(),
                    message: "M".into(),
                    preview_action: "Comment\nforged".into(),
                    preview_details: vec!["M".into()],
                },
            },
            Operation::CasesSetStatus {
                plan: cases_ops::StatusPlan {
                    target: CaseStatus::Closed,
                    updates: vec![("c".into(), "v".into(), CaseStatus::Closed)],
                    resolved: 2,
                    preview_action: "Close".into(),
                    preview_details: vec!["c".into()],
                },
                ids: vec!["c".into(), "d".into()],
            },
            Operation::RulesCreate {
                plan: rules_ops::RuleCreatePlan {
                    rule: serde_json::from_value(
                        json!({"rule_id":"r","enabled":false,"name":"N","type":"query"}),
                    )
                    .unwrap(),
                    preview: MutationPlan {
                        targets: vec!["r".into()],
                        preview_action: "Create".into(),
                        preview_details: vec![
                            "enabled: false".into(),
                            "name: \"N\"".into(),
                            "rule_id: \"r\"".into(),
                            "type: \"query\"".into(),
                        ],
                    },
                },
            },
        ]
    }
    #[test]
    fn operation_json_cli_and_consent() {
        let expected = [
            json!({"status":"closed","reason":"other","alert_ids":["a"]}),
            json!({"add":["x"],"remove":["y"],"alert_ids":["a"]}),
            json!({"title":"T","description":"D","tags":["x"],"severity":"low","sync_alerts":false}),
            json!({"case_id":"c","message":"M"}),
            json!({"status":"closed","updates":[{"id":"c","version":"v"}],"resolved":2}),
            json!({"rule":{"rule_id":"r","enabled":false,"name":"N","type":"query"}}),
        ];
        let cli = [
            vec!["alerts", "close", "a", "--reason", "other"],
            vec!["alerts", "tag", "a", "--add", "x", "--remove", "y"],
            vec![
                "cases",
                "create",
                "--title",
                "T",
                "--description",
                "D",
                "--tag",
                "x",
                "--severity",
                "low",
            ],
            vec!["cases", "comment", "c", "--message", "M"],
            vec!["cases", "close", "c", "d"],
            vec![],
        ];
        for (i, op) in operations().iter().enumerate() {
            assert_eq!(op.json(), expected[i]);
            assert_eq!(op.cli_equivalent(), cli[i]);
            assert_eq!(op.cli_arguments().is_none(), i == 5);
            let details = op.details();
            match i {
                0 => assert_eq!(details, ["a", "reason: other"]),
                1 => assert_eq!(details, ["a"]),
                2 => assert_eq!(details, ["tags: x", "description: D", "syncAlerts: false"]),
                3 => assert_eq!(details, ["case_id: c", "M"]),
                4 => assert_eq!(
                    details,
                    [
                        "c",
                        "attached alerts: not changed (syncAlerts is off for every case listed)"
                    ]
                ),
                5 => assert_eq!(
                    details,
                    [
                        "rule_id: \"r\"",
                        "enabled: false",
                        "name: \"N\"",
                        "type: \"query\""
                    ]
                ),
                _ => unreachable!(),
            }
            let note = op.kind().consent_note(&"a".repeat(64));
            if i == 5 {
                assert_eq!(
                    note.as_deref(),
                    Some(
                        "Kibana creates the rule disabled and without an API key. The credential that first enables it gives it a key, and the rule then runs with that credential's privileges."
                    )
                );
            } else {
                assert!(note.is_none());
            }
        }
    }
    #[test]
    fn classifiers_cover_every_kind_and_status() {
        let mut ops = operations();
        ops.push(Operation::RulesSetEnabled {
            plan: MutationPlan {
                targets: vec![],
                preview_action: String::new(),
                preview_details: vec![],
            },
            enable: false,
        });
        for (i, op) in ops.iter().enumerate() {
            for status in [None, Some(409), Some(400), Some(429), Some(500)] {
                let mut e =
                    elasticctl_core::Error::new(elasticctl_core::ErrorKind::Conflict, "sentinel");
                e.http_status = status;
                let (state, error) = op.kind().classify(&e);
                let expected = match status {
                    Some(409) if i == 4 || i == 5 => super::super::store::PlanState::Stale,
                    Some(400..=499) => super::super::store::PlanState::Failed,
                    _ => super::super::store::PlanState::Unknown,
                };
                assert_eq!(state, expected);
                assert!(!error.message.contains("sentinel"));
                if state == super::super::store::PlanState::Stale {
                    assert_eq!(error.code, "plan_stale");
                }
            }
        }
    }
    #[test]
    fn reports_preserve_counters_and_missing_targets() {
        let toggle = rules_ops::SetEnabledOutcome {
            applied: true,
            succeeded: 1,
            failed: 1,
            skipped: 1,
            total: 3,
        };
        let r = toggle_outcome(&toggle, 4).unwrap();
        assert_eq!(
            (r.requested, r.updated, r.unchanged, r.failed, r.complete),
            (4, 1, 0, 3, false)
        );
        let status = alerts_ops::StatusReport {
            applied: true,
            status: "closed".into(),
            total: 3,
            updated: 1,
            version_conflicts: 0,
            noops: 1,
            failed: 1,
            failures: vec![],
        };
        let r = status_outcome(&status, 4).unwrap();
        let tags = alerts_ops::EditReport {
            applied: true,
            total: 3,
            updated: 1,
            version_conflicts: 0,
            noops: 1,
            failed: 1,
            failures: vec![],
        };
        let t = tags_outcome(&tags, 4).unwrap();
        assert_eq!(
            (t.requested, t.updated, t.unchanged, t.failed, t.complete),
            (4, 1, 1, 2, false)
        );
        let rule = rules_ops::RuleCreateOutcome {
            applied: true,
            rule_id: "r".into(),
            enabled: false,
        };
        assert_eq!(
            rule_create_outcome(&rule).unwrap().created,
            Some(json!({"rule_id":"r"}))
        );
        assert_eq!(
            (r.requested, r.updated, r.unchanged, r.failed, r.complete),
            (4, 1, 1, 2, false)
        );
        let report = cases_ops::CaseEditReport {
            applied: true,
            total: 1,
            updated: 1,
            failed: 0,
            failures: vec![],
        };
        let r = case_status_outcome(&report, 2, 1).unwrap();
        assert_eq!(
            (r.requested, r.updated, r.unchanged, r.failed, r.complete),
            (2, 1, 1, 0, true)
        );
        assert_eq!(
            created_outcome(Some(json!({"case_id":"c"})))
                .unwrap()
                .created,
            Some(json!({"case_id":"c"}))
        );
        assert_eq!(
            created_outcome(Some(json!({"rule_id":"r"})))
                .unwrap()
                .created,
            Some(json!({"rule_id":"r"}))
        );
        assert!(created_outcome(None).unwrap().complete);
    }
    fn assert_unknown(kind: PlanKind, result: Result<Outcome>) {
        let error = result.unwrap_err();
        assert!(error.http_status.is_none());
        let (state, error) = kind.classify(&error);
        assert_eq!(state, PlanState::Unknown);
        assert_eq!(error.code, "apply_outcome_unknown");
    }
    #[test]
    fn toggle_rejects_overflow_and_excess_counts() {
        for (succeeded, failed, skipped, total) in [
            (0, u64::MAX, 1, 1),
            (u64::MAX, 1, 0, 1),
            (2, 0, 0, 1),
            (0, 2, 0, 1),
            (0, 0, 0, 2),
            (0, u64::MAX, 0, 0),
        ] {
            assert_unknown(
                PlanKind::RulesSetEnabled,
                toggle_outcome(
                    &rules_ops::SetEnabledOutcome {
                        applied: true,
                        succeeded,
                        failed,
                        skipped,
                        total,
                    },
                    1,
                ),
            );
        }
    }
    #[test]
    fn alert_kinds_reject_overflow_and_excess_counts() {
        for (total, updated, noops, failed) in [
            (1, u64::MAX, 2, 0),
            (1, 2, 0, 0),
            (1, 1, 0, 1),
            (0, 0, 0, u64::MAX),
            (2, 0, 0, 0),
        ] {
            assert_unknown(
                PlanKind::AlertsSetStatus,
                status_outcome(
                    &alerts_ops::StatusReport {
                        applied: true,
                        status: "closed".into(),
                        total,
                        updated,
                        noops,
                        failed,
                        version_conflicts: 0,
                        failures: vec![],
                    },
                    1,
                ),
            );
            assert_unknown(
                PlanKind::AlertsSetTags,
                tags_outcome(
                    &alerts_ops::EditReport {
                        applied: true,
                        total,
                        updated,
                        noops,
                        failed,
                        version_conflicts: 0,
                        failures: vec![],
                    },
                    1,
                ),
            );
        }
    }
    #[test]
    fn case_status_rejects_overflow_and_excess_counts() {
        for (total, updated, failed, resolved, updates) in [
            (1, u64::MAX, 0, 2, 1),
            (1, 2, 0, 1, 1),
            (1, 1, u64::MAX, 1, 1),
            (1, 1, 1, 1, 1),
            (2, 0, 0, 1, 1),
            (0, 0, 0, 1, 2),
        ] {
            assert_unknown(
                PlanKind::CasesSetStatus,
                case_status_outcome(
                    &cases_ops::CaseEditReport {
                        applied: true,
                        total,
                        updated,
                        failed,
                        failures: vec![],
                    },
                    resolved,
                    updates,
                ),
            );
        }
    }
    #[test]
    fn valid_toggle_outcomes_preserve_serialized_bytes() {
        for (report, requested, expected) in [
            (
                (1, 0, 0, 1),
                1,
                r#"{"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true,"created":null}"#,
            ),
            (
                (1, 1, 1, 3),
                4,
                r#"{"requested":4,"updated":1,"unchanged":0,"failed":3,"complete":false,"created":null}"#,
            ),
            (
                (0, 0, 0, 0),
                1,
                r#"{"requested":1,"updated":0,"unchanged":0,"failed":1,"complete":false,"created":null}"#,
            ),
        ] {
            let (succeeded, failed, skipped, total) = report;
            let value = toggle_outcome(
                &rules_ops::SetEnabledOutcome {
                    applied: true,
                    succeeded,
                    failed,
                    skipped,
                    total,
                },
                requested,
            )
            .unwrap();
            assert_eq!(serde_json::to_string(&value).unwrap(), expected);
        }
    }
    #[test]
    fn sync_alerts_requires_strict_false() {
        for value in [json!(true), json!(null), json!("false")] {
            let seen = Preconditions(vec![elasticctl_api::observe::Observed {
                object: "case",
                id: "c".into(),
                state: Some(json!({"sync_alerts":value})),
            }]);
            let ops = operations();
            assert!(matches!(
                ops[4].check_observed(&seen),
                Err(PlanError::CaseSyncAlerts)
            ));
            for (i, op) in ops.iter().enumerate() {
                if i != 4 {
                    op.check_observed(&seen).unwrap();
                }
            }
            let e = require_sync_alerts_off(&seen).unwrap_err();
            assert_eq!(e.code, "case_sync_alerts");
            assert!(e.message.contains("syncAlerts"));
        }
        for state in [None, Some(json!({}))] {
            let seen = Preconditions(vec![elasticctl_api::observe::Observed {
                object: "case",
                id: "c".into(),
                state,
            }]);
            assert!(matches!(
                operations()[4].check_observed(&seen),
                Err(PlanError::CaseSyncAlerts)
            ));
        }
        let seen = Preconditions(vec![elasticctl_api::observe::Observed {
            object: "case",
            id: "c".into(),
            state: Some(json!({"sync_alerts":false})),
        }]);
        require_sync_alerts_off(&seen).unwrap();
        operations()[4].check_observed(&seen).unwrap();
    }
}

#[cfg(test)]
mod action_test {
    #[test]
    fn action_is_one_line_with_replacement() {
        let t = crate::TargetContext {
            profile: "test".into(),
            host: "example.test".into(),
            space: "default".into(),
        };
        let text = super::super::consent::render(
            &t,
            "Comment\nforged",
            &["case_id: c".into()],
            None,
            "p",
            "h",
            15,
        );
        assert_eq!(
            text.lines().take(3).collect::<Vec<_>>(),
            [
                "elasticctl asks to apply: Comment�forged",
                "Target: profile test @ example.test, space default",
                "  case_id: c"
            ]
        );
    }
}
