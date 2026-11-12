use super::{
    MAX_FINAL_RECORDS, MAX_OBJECTS_PER_PLAN, MAX_OPEN_PLANS, MAX_PLAN_BODY_BYTES,
    MAX_PROMPTS_PER_PLAN, PlanError, consent, hash,
};
use crate::{TargetContext, ToolError};
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, ToolError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PlanState {
    Open,
    Applying,
    Applied,
    Failed,
    Unknown,
    Declined,
    Stale,
    Expired,
    Discarded,
}
impl PlanState {
    pub(crate) fn is_final(self) -> bool {
        !matches!(self, Self::Open | Self::Applying)
    }
    pub(crate) fn replayed(self) -> Result<bool> {
        match self {
            Self::Open => Ok(false),
            Self::Applying | Self::Applied | Self::Failed | Self::Unknown => Ok(true),
            _ => Err(self.error()),
        }
    }
    fn error(self) -> ToolError {
        match self {
            Self::Expired => PlanError::Expired,
            Self::Stale => PlanError::Stale,
            Self::Declined => PlanError::Declined,
            Self::Discarded => PlanError::Discarded,
            _ => PlanError::NotOpen,
        }
        .tool_error()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Outcome {
    pub(crate) requested: u64,
    pub(crate) updated: u64,
    pub(crate) unchanged: u64,
    pub(crate) failed: u64,
    pub(crate) complete: bool,
    pub(crate) created: Option<Value>,
}
#[derive(Clone, Debug)]
pub(crate) struct PlanContent<P = Value> {
    pub(crate) kind: &'static str,
    pub(crate) class: &'static str,
    pub(crate) target: TargetContext,
    pub(crate) binding: Value,
    pub(crate) credential: String,
    pub(crate) operation: Value,
    pub(crate) preconditions: Vec<Value>,
    pub(crate) action: String,
    pub(crate) details: Vec<String>,
    pub(crate) targets: Vec<String>,
    pub(crate) note: Option<String>,
    pub(crate) cli_equivalent: Option<Vec<String>>,
    pub(crate) payload: P,
}
#[derive(Clone, Debug)]
pub(crate) struct Plan<P = Value> {
    pub(crate) id: String,
    pub(crate) hash: String,
    pub(crate) content: PlanContent<P>,
    pub(crate) state: PlanState,
    pub(crate) outcome: Option<Outcome>,
    created: Instant,
    life: Duration,
    prompts: u8,
    handle: Option<String>,
}
impl<P> Plan<P> {
    #[cfg(test)]
    pub(crate) fn new(content: PlanContent<P>, now: Instant) -> Result<Self> {
        Self::with_life(content, now, Duration::from_secs(super::PLAN_LIFE_SECS))
    }
    pub(crate) fn with_life(
        mut content: PlanContent<P>,
        now: Instant,
        life: Duration,
    ) -> Result<Self> {
        if content.targets.len() > MAX_OBJECTS_PER_PLAN
            || content.preconditions.len() > MAX_OBJECTS_PER_PLAN
        {
            return Err(PlanError::InvalidArgument.tool_error());
        }
        content.preconditions.sort_by(|a, b| {
            (a["object"].as_str(), a["id"].as_str()).cmp(&(b["object"].as_str(), b["id"].as_str()))
        });
        let body = json!({"v":1,"kind":content.kind,"class":content.class,"target":content.binding,"credential":content.credential,"operation":content.operation,"preconditions":content.preconditions});
        let bytes = hash::canonical_bytes(&body);
        if bytes.len() > MAX_PLAN_BODY_BYTES {
            return Err(PlanError::TooLarge.tool_error());
        }
        let id = hash::new_plan_id().map_err(|_| PlanError::Randomness.tool_error())?;
        let hash = hash::sha256_hex(&bytes);
        let plan = Self {
            id,
            hash,
            content,
            state: PlanState::Open,
            outcome: None,
            created: now,
            life,
            prompts: 0,
            handle: None,
        };
        consent::validate(&plan.consent_text(now)).map_err(PlanError::tool_error)?;
        Ok(plan)
    }
    pub(crate) fn expires_in_secs(&self, now: Instant) -> u64 {
        if self.state != PlanState::Open {
            return 0;
        }
        self.life
            .saturating_sub(now.saturating_duration_since(self.created))
            .as_secs()
    }
    pub(crate) fn consent_text(&self, now: Instant) -> String {
        let remaining = self
            .life
            .saturating_sub(now.saturating_duration_since(self.created));
        let minutes = remaining.as_secs().div_ceil(60)
            + u64::from(remaining.subsec_nanos() != 0 && remaining.as_secs().is_multiple_of(60));
        consent::render(
            &self.content.target,
            &self.content.action,
            &self.content.details,
            self.content.note.as_deref(),
            &self.id,
            &self.hash,
            minutes.max(1),
        )
    }
    pub(crate) fn prompt_count(&self) -> u8 {
        self.prompts
    }
}
#[derive(Clone, Debug)]
pub(crate) struct ClosedPlan {
    pub(crate) id: String,
    pub(crate) hash: String,
    pub(crate) kind: &'static str,
    pub(crate) class: &'static str,
    pub(crate) target: TargetContext,
    pub(crate) credential: String,
    pub(crate) state: PlanState,
}
#[derive(Debug)]
pub(crate) struct PlanStore<P = Value> {
    plans: Vec<Plan<P>>,
    finals: VecDeque<String>,
    closed: Vec<ClosedPlan>,
}
impl<P> Default for PlanStore<P> {
    fn default() -> Self {
        Self {
            plans: Vec::new(),
            finals: VecDeque::new(),
            closed: Vec::new(),
        }
    }
}
impl<P: Clone> PlanStore<P> {
    pub(crate) fn take_closed(&mut self) -> Vec<ClosedPlan> {
        std::mem::take(&mut self.closed)
    }
    fn expire(&mut self, now: Instant) {
        let mut closed = Vec::new();
        for p in &mut self.plans {
            if p.state == PlanState::Open && now.saturating_duration_since(p.created) >= p.life {
                p.state = PlanState::Expired;
                p.handle = None;
                self.closed.push(ClosedPlan {
                    id: p.id.clone(),
                    hash: p.hash.clone(),
                    kind: p.content.kind,
                    class: p.content.class,
                    target: p.content.target.clone(),
                    credential: p.content.credential.chars().take(12).collect(),
                    state: p.state,
                });
                closed.push(p.id.clone());
            }
        }
        for id in closed {
            self.record_final(id);
        }
    }
    fn record_final(&mut self, id: String) {
        self.finals.push_back(id);
        while self.finals.len() > MAX_FINAL_RECORDS {
            if let Some(id) = self.finals.pop_front() {
                self.plans.retain(|p| p.id != id);
            }
        }
    }
    fn index(&self, id: &str) -> Result<usize> {
        self.plans
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| PlanError::NotFound.tool_error())
    }
    fn open_index(&mut self, id: &str, now: Instant) -> Result<usize> {
        self.expire(now);
        let i = self.index(id)?;
        if self.plans[i].state != PlanState::Open {
            return Err(self.plans[i].state.error());
        }
        Ok(i)
    }
    pub(crate) fn insert(&mut self, plan: Plan<P>, now: Instant) -> Result<()> {
        self.expire(now);
        if self.plans.iter().filter(|p| !p.state.is_final()).count() >= MAX_OPEN_PLANS {
            return Err(PlanError::TooManyPlans.tool_error());
        }
        if self.plans.iter().any(|p| p.id == plan.id) || plan.state != PlanState::Open {
            return Err(PlanError::InvalidArgument.tool_error());
        }
        self.plans.push(plan);
        self.expire(now);
        Ok(())
    }
    pub(crate) fn get(&mut self, id: &str, now: Instant) -> Result<&Plan<P>> {
        self.expire(now);
        let i = self.index(id)?;
        Ok(&self.plans[i])
    }
    pub(crate) fn issue_prompt(
        &mut self,
        id: &str,
        handle: bool,
        now: Instant,
    ) -> Result<Option<String>> {
        let i = self.open_index(id, now)?;
        if self.plans[i].prompts >= MAX_PROMPTS_PER_PLAN {
            self.close(id, PlanState::Declined, now)?;
            return Err(PlanError::Declined.tool_error());
        }
        let handle = if handle {
            Some(hash::new_handle().map_err(|_| PlanError::Randomness.tool_error())?)
        } else {
            None
        };
        self.plans[i].prompts += 1;
        self.plans[i].handle = handle.clone();
        Ok(handle)
    }
    pub(crate) fn take_handle(
        &mut self,
        id: &str,
        handle: Option<&str>,
        now: Instant,
    ) -> Result<()> {
        let i = self.open_index(id, now)?;
        let expected = self.plans[i].handle.take();
        if expected.is_none() || expected.as_deref() != handle {
            return Err(PlanError::NotConfirmed.tool_error());
        }
        Ok(())
    }
    pub(crate) fn begin_apply(&mut self, id: &str, now: Instant) -> Result<()> {
        let i = self.open_index(id, now)?;
        self.plans[i].state = PlanState::Applying;
        self.plans[i].handle = None;
        Ok(())
    }
    pub(crate) fn finish(
        &mut self,
        id: &str,
        state: PlanState,
        outcome: Option<Outcome>,
        now: Instant,
    ) -> Result<()> {
        self.expire(now);
        let i = self.index(id)?;
        if self.plans[i].state != PlanState::Applying
            || !matches!(
                state,
                PlanState::Applied | PlanState::Failed | PlanState::Unknown | PlanState::Stale
            )
            || (state != PlanState::Applied && outcome.is_some())
        {
            return Err(PlanError::NotOpen.tool_error());
        }
        self.plans[i].state = state;
        self.plans[i].outcome = outcome;
        self.record_final(id.into());
        Ok(())
    }
    pub(crate) fn close(&mut self, id: &str, state: PlanState, now: Instant) -> Result<()> {
        let i = self.open_index(id, now)?;
        if !matches!(
            state,
            PlanState::Declined | PlanState::Stale | PlanState::Discarded
        ) {
            return Err(PlanError::NotOpen.tool_error());
        }
        self.plans[i].state = state;
        self.plans[i].handle = None;
        self.record_final(id.into());
        Ok(())
    }
    pub(crate) fn discard(&mut self, id: &str, now: Instant) -> Result<&Plan<P>> {
        let state = self.get(id, now)?.state;
        match state {
            PlanState::Open => self.close(id, PlanState::Discarded, now)?,
            PlanState::Applying => return Err(PlanError::NotOpen.tool_error()),
            _ => {}
        }
        self.get(id, now)
    }
    pub(crate) fn list(&mut self, now: Instant) -> Vec<Plan<P>> {
        self.expire(now);
        self.plans
            .iter()
            .rev()
            .filter(|p| !p.state.is_final())
            .chain(
                self.finals
                    .iter()
                    .rev()
                    .filter_map(|id| self.plans.iter().find(|p| p.id == *id)),
            )
            .cloned()
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    pub(crate) fn sample(now: Instant) -> Plan {
        Plan::new(PlanContent { kind: "rules_set_enabled", class: "rules-toggle", target: crate::TargetContext {profile:"analyst".into(),host:"kibana.example.test".into(),space:"default".into()}, binding: json!({"profile":"analyst","kibana_url":"https://kibana.example.test","es_url":null,"space":"default"}), credential: "a".repeat(64), operation: json!({"enabled":false,"rule_ids":["r"]}), preconditions: vec![], action: "secret-action".into(), details: vec!["secret-detail".into()], targets: vec!["r".into()], note: None, cli_equivalent: None, payload: json!({}) }, now).unwrap()
    }
    #[tokio::test(start_paused = true)]
    async fn expiry_and_capacity() {
        let now = Instant::now();
        let mut s = PlanStore::default();
        let p = sample(now);
        let id = p.id.clone();
        s.insert(p, now).unwrap();
        for _ in 1..8 {
            s.insert(sample(now), now).unwrap();
        }
        assert_eq!(
            s.insert(sample(now), now).unwrap_err().code,
            "too_many_plans"
        );
        tokio::time::advance(Duration::from_secs(899)).await;
        assert_eq!(s.get(&id, Instant::now()).unwrap().state, PlanState::Open);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            s.get(&id, Instant::now()).unwrap().state,
            PlanState::Expired
        );
        assert!(s.insert(sample(Instant::now()), Instant::now()).is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn expiry_snapshots_survive_eviction_and_drain_once() {
        let now = Instant::now();
        let mut s = PlanStore::default();
        let mut ids = Vec::new();
        let mut hashes = Vec::new();
        for _ in 0..8 {
            let p = sample(now);
            ids.push(p.id.clone());
            hashes.push(p.hash.clone());
            s.insert(p, now).unwrap();
        }
        tokio::time::advance(Duration::from_secs(900)).await;
        let later = Instant::now();
        s.insert(sample(later), later).unwrap();
        assert_eq!(s.closed.len(), 8);
        for _ in 0..32 {
            let p = sample(later);
            let id = p.id.clone();
            s.insert(p, later).unwrap();
            s.close(&id, PlanState::Discarded, later).unwrap();
        }
        for id in &ids {
            assert_eq!(s.get(id, later).unwrap_err().code, "plan_not_found");
        }
        let closed = s.take_closed();
        assert_eq!(closed.len(), 8);
        for ((snapshot, id), hash) in closed.iter().zip(ids).zip(hashes) {
            assert_eq!(snapshot.id, id);
            assert_eq!(snapshot.hash, hash);
            assert_eq!(snapshot.kind, "rules_set_enabled");
            assert_eq!(snapshot.class, "rules-toggle");
            assert_eq!(snapshot.state, PlanState::Expired);
            assert_eq!(snapshot.credential, "aaaaaaaaaaaa");
        }
        assert!(s.take_closed().is_empty());
    }
    #[test]
    fn pending_writes_reserve_capacity() {
        let now = Instant::now();
        let mut s = PlanStore::default();
        for _ in 0..32 {
            let p = sample(now);
            let id = p.id.clone();
            s.insert(p, now).unwrap();
            s.close(&id, PlanState::Discarded, now).unwrap();
            assert!(s.plans.len() <= 40);
        }
        let mut pending = Vec::new();
        for _ in 0..8 {
            let p = sample(now);
            let id = p.id.clone();
            s.insert(p, now).unwrap();
            s.begin_apply(&id, now).unwrap();
            pending.push(id);
            assert!(s.plans.len() <= 40);
        }
        let later = now + Duration::from_secs(900);
        assert_eq!(
            s.insert(sample(later), later).unwrap_err().code,
            "too_many_plans"
        );
        assert_eq!(s.plans.len(), 40);
        for id in pending {
            s.finish(&id, PlanState::Applied, None, later).unwrap();
            assert!(s.plans.len() <= 40);
            let p = sample(later);
            let id = p.id.clone();
            s.insert(p, later).unwrap();
            s.begin_apply(&id, later).unwrap();
            assert!(s.plans.len() <= 40);
        }
        assert_eq!(s.plans.len(), 40);
    }
    #[test]
    fn transitions() {
        let now = Instant::now();
        for end in [
            PlanState::Applied,
            PlanState::Failed,
            PlanState::Unknown,
            PlanState::Stale,
        ] {
            let mut s = PlanStore::default();
            let p = sample(now);
            let id = p.id.clone();
            s.insert(p, now).unwrap();
            s.begin_apply(&id, now).unwrap();
            assert_eq!(
                s.get(&id, now + Duration::from_secs(900)).unwrap().state,
                PlanState::Applying
            );
            s.finish(&id, end, None, now).unwrap();
            assert!(s.begin_apply(&id, now).is_err());
            assert!(s.close(&id, PlanState::Discarded, now).is_err());
            assert_eq!(s.get(&id, now).unwrap().state, end);
        }
        for end in [PlanState::Declined, PlanState::Stale, PlanState::Discarded] {
            let mut s = PlanStore::default();
            let p = sample(now);
            let id = p.id.clone();
            s.insert(p, now).unwrap();
            s.close(&id, end, now).unwrap();
            assert!(s.begin_apply(&id, now).is_err());
        }
    }
    #[test]
    fn prompts_and_handles() {
        let now = Instant::now();
        let mut s = PlanStore::default();
        let p = sample(now);
        let id = p.id.clone();
        s.insert(p, now).unwrap();
        let h = s.issue_prompt(&id, true, now).unwrap().unwrap();
        assert!(s.take_handle(&id, Some("wrong"), now).is_err());
        assert!(s.take_handle(&id, Some(&h), now).is_err());
        let h = s.issue_prompt(&id, true, now).unwrap().unwrap();
        s.take_handle(&id, Some(&h), now).unwrap();
        assert!(s.take_handle(&id, Some(&h), now).is_err());
        s.issue_prompt(&id, true, now).unwrap();
        assert!(s.get(&id, now).unwrap().handle.is_some());
        assert_eq!(
            s.issue_prompt(&id, true, now).unwrap_err().code,
            "plan_declined"
        );
        let p = s.get(&id, now).unwrap();
        assert_eq!(p.state, PlanState::Declined);
        assert_eq!(p.prompt_count(), 3);
        assert_eq!(p.handle, None);
        assert_eq!(p.outcome, None);
    }
    #[test]
    fn final_eviction_and_race() {
        let now = Instant::now();
        let mut s = PlanStore::default();
        let p = sample(now);
        let first = p.id.clone();
        s.insert(p, now).unwrap();
        s.close(&first, PlanState::Discarded, now).unwrap();
        for _ in 0..32 {
            let p = sample(now);
            let id = p.id.clone();
            s.insert(p, now).unwrap();
            s.close(&id, PlanState::Discarded, now).unwrap();
        }
        assert_eq!(s.get(&first, now).unwrap_err().code, "plan_not_found");
        assert_eq!(s.list(now).len(), 32);
        let p = sample(now);
        let id = p.id.clone();
        s.insert(p, now).unwrap();
        let s = std::sync::Arc::new(std::sync::Mutex::new(s));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let s = s.clone();
                let id = id.clone();
                std::thread::spawn(move || s.lock().unwrap().begin_apply(&id, now).is_ok())
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .filter(|h| h.thread().id() != std::thread::current().id())
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn all_transition_pairs() {
        let states = [
            PlanState::Open,
            PlanState::Applying,
            PlanState::Applied,
            PlanState::Failed,
            PlanState::Unknown,
            PlanState::Declined,
            PlanState::Stale,
            PlanState::Expired,
            PlanState::Discarded,
        ];
        let now = Instant::now();
        for from in states {
            for to in states {
                for finish in [false, true] {
                    let mut s = PlanStore::default();
                    let mut p = sample(now);
                    p.state = from;
                    p.prompts = 2;
                    p.handle = Some("pending-handle".into());
                    p.outcome = Some(Outcome {
                        requested: 2,
                        updated: 1,
                        unchanged: 0,
                        failed: 1,
                        complete: false,
                        created: None,
                    });
                    let before = p.clone();
                    let id = p.id.clone();
                    s.plans.push(p);
                    let legal = if finish {
                        from == PlanState::Applying
                            && matches!(
                                to,
                                PlanState::Applied
                                    | PlanState::Failed
                                    | PlanState::Unknown
                                    | PlanState::Stale
                            )
                    } else {
                        from == PlanState::Open
                            && matches!(
                                to,
                                PlanState::Declined | PlanState::Stale | PlanState::Discarded
                            )
                    };
                    let result = if finish {
                        s.finish(&id, to, None, now)
                    } else {
                        s.close(&id, to, now)
                    };
                    assert_eq!(result.is_ok(), legal, "{from:?} -> {to:?}");
                    assert_eq!(
                        s.get(&id, now).unwrap().state,
                        if legal { to } else { from }
                    );
                    if !legal {
                        let after = s.get(&id, now).unwrap();
                        assert_eq!(after.outcome, before.outcome);
                        assert_eq!(after.prompt_count(), before.prompt_count());
                        assert_eq!(after.handle, before.handle);
                    }
                }
            }
            let mut s = PlanStore::default();
            let mut p = sample(now);
            p.state = from;
            p.prompts = 2;
            p.handle = Some("pending-handle".into());
            p.outcome = Some(Outcome {
                requested: 2,
                updated: 1,
                unchanged: 0,
                failed: 1,
                complete: false,
                created: None,
            });
            let before = p.clone();
            let id = p.id.clone();
            s.plans.push(p);
            assert_eq!(s.begin_apply(&id, now).is_ok(), from == PlanState::Open);
            assert_eq!(
                s.get(&id, now).unwrap().state,
                if from == PlanState::Open {
                    PlanState::Applying
                } else {
                    from
                }
            );
            if from != PlanState::Open {
                let after = s.get(&id, now).unwrap();
                assert_eq!(after.outcome, before.outcome);
                assert_eq!(after.prompt_count(), before.prompt_count());
                assert_eq!(after.handle, before.handle);
            }
            match from {
                PlanState::Open => assert!(!from.replayed().unwrap()),
                PlanState::Applying
                | PlanState::Applied
                | PlanState::Failed
                | PlanState::Unknown => assert!(from.replayed().unwrap()),
                PlanState::Declined => {
                    assert_eq!(from.replayed().unwrap_err().code, "plan_declined")
                }
                PlanState::Stale => assert_eq!(from.replayed().unwrap_err().code, "plan_stale"),
                PlanState::Expired => assert_eq!(from.replayed().unwrap_err().code, "plan_expired"),
                PlanState::Discarded => {
                    assert_eq!(from.replayed().unwrap_err().code, "plan_discarded")
                }
            }
        }
    }
    #[test]
    fn body_consent_and_object_limits() {
        let now = Instant::now();
        let content = sample(now).content;
        let mut large = content.clone();
        large.operation = json!({"text":""});
        let p = Plan::new(large.clone(), now).unwrap();
        let body = json!({"v":1,"kind":large.kind,"class":large.class,"target":large.binding,"credential":large.credential,"operation":large.operation,"preconditions":large.preconditions});
        let overhead = hash::canonical_bytes(&body).len();
        large.operation["text"] = json!("x".repeat(MAX_PLAN_BODY_BYTES - overhead));
        assert!(Plan::new(large.clone(), now).is_ok());
        large.operation["text"].as_str().unwrap();
        large.operation["text"] = json!("x".repeat(MAX_PLAN_BODY_BYTES - overhead + 1));
        assert_eq!(Plan::new(large, now).unwrap_err().code, "plan_too_large");
        let mut large = content.clone();
        let base = p.consent_text(now).len() - p.content.action.len();
        large.action = "x".repeat(super::super::MAX_CONSENT_TEXT_BYTES - base);
        assert!(Plan::new(large.clone(), now).is_ok());
        large.action.push('x');
        assert_eq!(Plan::new(large, now).unwrap_err().code, "plan_too_large");
        let mut large = content;
        large.targets = vec!["r".into(); 20];
        assert!(Plan::new(large.clone(), now).is_ok());
        large.targets.push("r".into());
        assert_eq!(Plan::new(large, now).unwrap_err().code, "invalid_argument");
    }
    #[test]
    fn binding_hash_and_discard() {
        let now = Instant::now();
        let p = sample(now);
        let mut c = p.content.clone();
        c.action = "different preview".into();
        let p2 = Plan::new(c.clone(), now + Duration::from_secs(1)).unwrap();
        assert_eq!(p.hash, p2.hash);
        assert_ne!(p.id, p2.id);
        for field in ["target", "credential", "operation", "preconditions"] {
            let mut changed = c.clone();
            match field {
                "target" => changed.binding["space"] = json!("other"),
                "credential" => changed.credential = "b".repeat(64),
                "operation" => changed.operation = json!({}),
                _ => changed
                    .preconditions
                    .push(json!({"object":"rule","id":"r","state":null})),
            }
            assert_ne!(Plan::new(changed, now).unwrap().hash, p.hash);
        }
        c.preconditions = vec![
            json!({"object":"rule","id":"z","state":null}),
            json!({"object":"alert","id":"a","state":{}}),
        ];
        let a = Plan::new(c.clone(), now).unwrap();
        c.preconditions.reverse();
        assert_eq!(a.hash, Plan::new(c, now).unwrap().hash);
        let mut s = PlanStore::default();
        let id = p.id.clone();
        s.insert(p, now).unwrap();
        assert_eq!(s.discard(&id, now).unwrap().state, PlanState::Discarded);
        assert_eq!(s.discard(&id, now).unwrap().state, PlanState::Discarded);
    }
}
