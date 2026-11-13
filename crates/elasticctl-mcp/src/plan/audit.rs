use super::store::{ClosedPlan, Plan};
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Clone, Copy)]
pub(crate) enum Answer {
    Confirmed,
    NotConfirmed,
    Declined,
    Timeout,
    Unavailable,
}
impl Answer {
    fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::NotConfirmed => "not_confirmed",
            Self::Declined => "declined",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Event {
    PlanCreated,
    ConfirmationRequested(u8),
    ConfirmationAnswered(Answer),
    ApplyStarted,
    ApplyFinished(Option<u16>),
    ApplyInterrupted,
    PlanClosed,
}
pub(crate) fn line<P>(ts: u64, p: &Plan<P>, protocol: &str, event: Event) -> String {
    let name = match event {
        Event::PlanCreated => "plan_created",
        Event::ConfirmationRequested(_) => "confirmation_requested",
        Event::ConfirmationAnswered(_) => "confirmation_answered",
        Event::ApplyStarted => "apply_started",
        Event::ApplyFinished(_) => "apply_finished",
        Event::ApplyInterrupted => "apply_interrupted",
        Event::PlanClosed => "plan_closed",
    };
    let mut v = json!({"ts":ts,"event":name,"plan_id":p.id,"hash":p.hash,"kind":p.content.kind,"class":p.content.class,"profile":p.content.target.profile,"host":p.content.target.host,"space":p.content.target.space,"credential":p.content.credential.chars().take(12).collect::<String>(),"protocol":protocol});
    match event {
        Event::PlanCreated => v["targets"] = json!(p.content.targets),
        Event::ConfirmationRequested(n) => v["prompt"] = json!(n),
        Event::ConfirmationAnswered(answer) => v["result"] = json!(answer.as_str()),
        Event::ApplyFinished(status) => {
            v["state"] = json!(p.state);
            v["outcome"]=p.outcome.as_ref().map(|o|json!({"requested":o.requested,"updated":o.updated,"unchanged":o.unchanged,"failed":o.failed,"complete":o.complete})).unwrap_or(Value::Null);
            v["http_status"] = json!(status);
        }
        Event::PlanClosed => v["state"] = json!(p.state),
        _ => {}
    }
    json!({"audit":v}).to_string()
}
pub(crate) fn closed_line(ts: u64, p: &ClosedPlan, protocol: &str) -> String {
    json!({"audit":{"ts":ts,"event":"plan_closed","plan_id":p.id,"hash":p.hash,
        "kind":p.kind,"class":p.class,"profile":p.target.profile,"host":p.target.host,
        "space":p.target.space,"credential":p.credential,"protocol":protocol,"state":p.state}})
    .to_string()
}
pub(crate) fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[derive(Clone)]
pub(crate) struct AuditSink(Arc<dyn Fn(&str) + Send + Sync>);
impl AuditSink {
    pub(crate) fn production(writer: impl Fn(&str) + Send + Sync + 'static) -> Self {
        Self(Arc::new(move |line| writer(&format!("{line}\n"))))
    }
    pub(crate) fn emit(&self, line: &str) {
        (self.0)(line);
    }
    #[cfg(test)]
    pub(crate) fn collecting() -> (Self, CollectedLines) {
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = lines.clone();
        (
            Self(Arc::new(move |line| {
                captured.lock().unwrap().push(line.into())
            })),
            lines,
        )
    }
}
#[cfg(test)]
type CollectedLines = Arc<std::sync::Mutex<Vec<String>>>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_snapshot_formats_complete_audit_line() {
        use super::super::store::PlanStore;
        use std::time::Duration;
        let now = tokio::time::Instant::now();
        let mut p = super::super::store::tests::sample(now);
        p.id = "pln_test".into();
        p.hash = "b".repeat(64);
        let mut store = PlanStore::default();
        store.insert(p, now).unwrap();
        store.list(now + Duration::from_secs(900));
        let snapshots = store.take_closed();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            closed_line(123, &snapshots[0], "2026-07-28"),
            r#"{"audit":{"ts":123,"event":"plan_closed","plan_id":"pln_test","hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"rules_set_enabled","class":"rules-toggle","profile":"analyst","host":"kibana.example.test","space":"default","credential":"aaaaaaaaaaaa","protocol":"2026-07-28","state":"expired"}}"#
        );
        assert!(store.take_closed().is_empty());
    }
    #[test]
    fn event_keys_and_escaping() {
        let now = tokio::time::Instant::now();
        let mut p = super::super::store::tests::sample(now);
        p.content.targets = vec!["r\"\n\u{1}".into()];
        let common = [
            "ts",
            "event",
            "plan_id",
            "hash",
            "kind",
            "class",
            "profile",
            "host",
            "space",
            "credential",
            "protocol",
        ];
        for (event, extras) in [
            (Event::PlanCreated, vec!["targets"]),
            (Event::ConfirmationRequested(1), vec!["prompt"]),
            (
                Event::ConfirmationAnswered(Answer::Confirmed),
                vec!["result"],
            ),
            (Event::ApplyStarted, vec![]),
            (
                Event::ApplyFinished(None),
                vec!["state", "outcome", "http_status"],
            ),
            (Event::ApplyInterrupted, vec![]),
            (Event::PlanClosed, vec!["state"]),
        ] {
            let line = line(123, &p, "2026-07-28", event);
            assert!(!line.contains('\n'));
            assert!(!line.contains("secret-action"));
            assert!(!line.contains("secret-detail"));
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            let keys: Vec<_> = v["audit"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, [common.to_vec(), extras].concat());
        }
        let (sink, lines) = AuditSink::collecting();
        sink.emit("one");
        sink.clone().emit("two");
        assert_eq!(*lines.lock().unwrap(), vec!["one", "two"]);
    }
    #[test]
    fn finished_outcome_omits_created_and_writer_gets_newline() {
        use super::super::store::{Outcome, PlanState};
        let mut p = super::super::store::tests::sample(tokio::time::Instant::now());
        p.state = PlanState::Applied;
        p.outcome = Some(Outcome {
            requested: 1,
            updated: 1,
            unchanged: 0,
            failed: 0,
            complete: true,
            created: Some(json!({"case_id":"created-secret"})),
        });
        let text = line(123, &p, "2026-07-28", Event::ApplyFinished(Some(200)));
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["audit"]["outcome"].to_string(),
            r#"{"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true}"#
        );
        assert!(!text.contains("created-secret"));
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = lines.clone();
        AuditSink::production(move |text| captured.lock().unwrap().push(text.to_string()))
            .emit("{}");
        assert_eq!(*lines.lock().unwrap(), vec!["{}\n"]);
    }
}
