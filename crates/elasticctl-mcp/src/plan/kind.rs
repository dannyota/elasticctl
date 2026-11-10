//! Typed operations and their projections for stored plans.
use elasticctl_api::{
    health::CredentialIdentity, observe::Preconditions, ops::MutationPlan, rules_ops,
};
use elasticctl_core::{Result, Transport};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
pub(crate) enum PlanKind {
    RulesSetEnabled,
}
impl PlanKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RulesSetEnabled => "rules_set_enabled",
        }
    }
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::RulesSetEnabled => "rules-toggle",
        }
    }
    pub(crate) fn credential_suitable(self, identity: &CredentialIdentity) -> bool {
        match self {
            Self::RulesSetEnabled => identity.realm_type != "_cloud_api_key",
        }
    }
    pub(crate) fn note(self, credential: &str) -> String {
        format!(
            "Kibana ties each rule listed to this server's credential ({}). The rule then runs with that credential's privileges and stops if it is deleted or disabled. Undoing this change does not restore the earlier one.",
            &credential[..12]
        )
    }
}
#[derive(Clone, Debug)]
pub(crate) enum Operation {
    RulesSetEnabled { plan: MutationPlan, enable: bool },
}
impl Operation {
    pub(crate) fn json(&self) -> Value {
        match self {
            Self::RulesSetEnabled { plan, enable } => {
                json!({"enabled":enable,"rule_ids":plan.targets})
            }
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
        }
    }
    #[allow(dead_code)]
    pub(crate) async fn observe(&self, t: &Transport) -> Result<Preconditions> {
        match self {
            Self::RulesSetEnabled { plan, .. } => rules_ops::observe_rules(t, &plan.targets).await,
        }
    }
    #[allow(dead_code)]
    pub(crate) async fn apply(&self, t: &Transport) -> Result<rules_ops::SetEnabledOutcome> {
        match self {
            Self::RulesSetEnabled { plan, enable } => {
                rules_ops::apply_set_enabled(t, plan, *enable).await
            }
        }
    }
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
