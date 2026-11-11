use super::store::{Plan, PlanState};
use serde_json::{Value, json};
use tokio::time::Instant;
pub(crate) fn view<P>(p: &Plan<P>, elicitation: bool, replayed: bool, now: Instant) -> Value {
    json!({"plan":{
        "plan_id":p.id,"hash":p.hash,"kind":p.content.kind,"class":p.content.class,
        "state":p.state,"expires_in_secs":p.expires_in_secs(now),
        "credential":p.content.credential.chars().take(12).collect::<String>(),
        "action":p.content.action,"details":p.content.details,"targets":p.content.targets,
        "operation":p.content.operation,"confirmation":if elicitation {"elicitation"} else {"unavailable"},
        "cli_equivalent":p.content.cli_equivalent},
        "outcome":if p.state==PlanState::Applied {p.outcome.as_ref()} else {None},"replayed":replayed})
}
pub(crate) fn list_row<P>(p: &Plan<P>, now: Instant) -> Value {
    json!({"plan_id":p.id,"kind":p.content.kind,"class":p.content.class,"state":p.state,"action":p.content.action,"expires_in_secs":p.expires_in_secs(now)})
}
pub(crate) fn list<P>(plans: &[Plan<P>], now: Instant) -> Value {
    json!({"plans":plans.iter().map(|p|list_row(p,now)).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_view_and_list() {
        let now = tokio::time::Instant::now();
        let mut p = super::super::store::tests::sample(now);
        p.id = "pln_test".into();
        p.hash = "b".repeat(64);
        let v = view(&p, true, false, now);
        assert_eq!(
            v.to_string(),
            r#"{"plan":{"plan_id":"pln_test","hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"rules_set_enabled","class":"rules-toggle","state":"open","expires_in_secs":900,"credential":"aaaaaaaaaaaa","action":"secret-action","details":["secret-detail"],"targets":["r"],"operation":{"enabled":false,"rule_ids":["r"]},"confirmation":"elicitation","cli_equivalent":null},"outcome":null,"replayed":false}"#
        );
        assert_eq!(
            list_row(&p, now).to_string(),
            r#"{"plan_id":"pln_test","kind":"rules_set_enabled","class":"rules-toggle","state":"open","action":"secret-action","expires_in_secs":900}"#
        );
        assert_eq!(
            v.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["plan", "outcome", "replayed"]
        );
        assert_eq!(
            v["plan"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "plan_id",
                "hash",
                "kind",
                "class",
                "state",
                "expires_in_secs",
                "credential",
                "action",
                "details",
                "targets",
                "operation",
                "confirmation",
                "cli_equivalent"
            ]
        );
        assert_eq!(v["plan"]["credential"], "aaaaaaaaaaaa");
        assert_eq!(v["plan"]["expires_in_secs"], 900);
        assert!(v["outcome"].is_null());
        assert_eq!(
            list_row(&p, now)
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "plan_id",
                "kind",
                "class",
                "state",
                "action",
                "expires_in_secs"
            ]
        );
    }
    #[test]
    fn outcome_and_list_wire_values() {
        use super::super::store::{Outcome, PlanState};
        let now = tokio::time::Instant::now();
        let mut p = super::super::store::tests::sample(now);
        p.id = "pln_test".into();
        p.hash = "b".repeat(64);
        p.state = PlanState::Applied;
        p.outcome = Some(Outcome {
            requested: 2,
            updated: 1,
            unchanged: 0,
            failed: 1,
            complete: false,
            created: None,
        });
        let v = view(&p, false, true, now);
        assert_eq!(v["plan"]["expires_in_secs"], 0);
        assert_eq!(v["plan"]["state"], "applied");
        assert_eq!(v["plan"]["confirmation"], "unavailable");
        assert_eq!(
            v["outcome"].to_string(),
            r#"{"requested":2,"updated":1,"unchanged":0,"failed":1,"complete":false,"created":null}"#
        );
        assert_eq!(v["replayed"], true);
        assert_eq!(
            v.to_string(),
            r#"{"plan":{"plan_id":"pln_test","hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"rules_set_enabled","class":"rules-toggle","state":"applied","expires_in_secs":0,"credential":"aaaaaaaaaaaa","action":"secret-action","details":["secret-detail"],"targets":["r"],"operation":{"enabled":false,"rule_ids":["r"]},"confirmation":"unavailable","cli_equivalent":null},"outcome":{"requested":2,"updated":1,"unchanged":0,"failed":1,"complete":false,"created":null},"replayed":true}"#
        );
        assert_eq!(
            list(&[p.clone()], now).to_string(),
            r#"{"plans":[{"plan_id":"pln_test","kind":"rules_set_enabled","class":"rules-toggle","state":"applied","action":"secret-action","expires_in_secs":0}]}"#
        );
        p.state = PlanState::Failed;
        assert!(view(&p, true, true, now)["outcome"].is_null());
    }
}
