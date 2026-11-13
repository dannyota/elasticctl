use super::ListPlan;
use elasticctl_core::Error;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Applied,
    Failed,
    Unknown,
    NotReached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sent {
    Accepted,
    Refused,
    Uncertain,
    NotSent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    CreateValueList,
    UpdateValueList,
    AddValues,
    RemoveValues,
    ReadBack,
    NotReached,
    DeleteValueList,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOf {
    Values,
    Container,
}

#[derive(Clone, Debug, Serialize)]
pub struct Failure {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub message: String,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            kind: error.kind.as_str().into(),
            status: error.http_status,
            message: error.message,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub action: Action,
    pub rule_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<Sent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub phase_verified: bool,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<ReadOf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatched: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<Failure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planned_adds: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planned_removes: Option<usize>,
}

impl Evidence {
    pub(super) fn new(action: Action, id: &str, name: &str) -> Self {
        Self {
            action,
            rule_id: id.into(),
            name: name.into(),
            values: Some(Vec::new()),
            sent: Some(Sent::NotSent),
            status: None,
            phase_verified: false,
            outcome: Outcome::NotReached,
            of: None,
            observed: None,
            missing: None,
            extra: None,
            mismatched: None,
            read_error: None,
            planned_adds: None,
            planned_removes: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ListOutcome {
    pub id: String,
    pub outcome: Outcome,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Failure>,
}

impl ListOutcome {
    pub(super) fn finish(&mut self, outcome: Outcome, error: Option<Error>) {
        self.outcome = outcome;
        self.error = error.map(Into::into);
        for entry in &mut self.evidence {
            entry.outcome = outcome;
        }
    }

    pub(super) fn not_reached(plan: &ListPlan) -> Self {
        let c = &plan.local.container;
        let mut entry = Evidence::new(Action::NotReached, &c.id, &c.name);
        entry.values = None;
        entry.planned_adds = Some(plan.adds.len());
        entry.planned_removes = Some(plan.removes.len());
        Self {
            id: c.id.clone(),
            outcome: Outcome::NotReached,
            evidence: vec![entry],
            error: None,
        }
    }
}
