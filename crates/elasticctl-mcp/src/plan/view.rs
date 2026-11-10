use super::store::{Plan, PlanState};
use serde_json::{Value, json};
use tokio::time::Instant;
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) fn list_row<P>(p: &Plan<P>, now: Instant) -> Value {
    json!({"plan_id":p.id,"kind":p.content.kind,"class":p.content.class,"state":p.state,"action":p.content.action,"expires_in_secs":p.expires_in_secs(now)})
}
#[allow(dead_code)]
pub(crate) fn list<P>(plans: &[Plan<P>], now: Instant) -> Value {
    json!({"plans":plans.iter().map(|p|list_row(p,now)).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_view_and_list() {
        let now = tokio::time::Instant::now();
        let p = super::super::store::tests::sample(now);
        let v = view(&p, true, false, now);
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
        use serde_json::json;
        let now = tokio::time::Instant::now();
        let mut p = super::super::store::tests::sample(now);
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
        assert_eq!(list(&[p.clone()], now), json!({"plans":[list_row(&p,now)]}));
        p.state = PlanState::Failed;
        assert!(view(&p, true, true, now)["outcome"].is_null());
    }
}
