//! Rule creation plans and outcomes.

use super::*;
use crate::Preconditions;

/// A rule creation plan with its preview.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleCreatePlan {
    /// The rule to create.
    pub rule: Rule,
    /// The mutation preview.
    pub preview: MutationPlan,
}

/// The outcome of creating a disabled rule.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuleCreateOutcome {
    /// Whether the rule was created.
    pub applied: bool,
    /// The created rule ID.
    pub rule_id: String,
    /// Whether the created rule is enabled.
    pub enabled: bool,
}

/// Plan creation of a disabled rule and read its absence.
pub async fn plan_create(t: &Transport, mut rule: Rule) -> Result<(RuleCreatePlan, Preconditions)> {
    let id = rule.rule_id()?.to_owned();
    for key in ["name", "type"] {
        if !rule.as_map().get(key).is_some_and(Value::is_string) {
            return Err(Error::new(
                ErrorKind::Error,
                "name and type must be strings",
            ));
        }
    }
    if crate::model::VOLATILE_FIELDS
        .iter()
        .any(|key| rule.as_map().contains_key(*key))
    {
        return Err(Error::new(
            ErrorKind::Error,
            "rule contains a volatile field",
        ));
    }
    if rule
        .as_map()
        .get("enabled")
        .is_some_and(|v| v != &json!(false))
    {
        return Err(Error::new(ErrorKind::Error, "rule must be disabled"));
    }
    for key in ["exceptions_list", "actions", "response_actions"] {
        if rule
            .as_map()
            .get(key)
            .is_some_and(|v| !v.as_array().is_some_and(Vec::is_empty))
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "rule dependencies must be empty arrays",
            ));
        }
    }
    rule.as_map_mut().insert("enabled".into(), json!(false));
    match rules::get(t, &id).await {
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::Conflict,
                "a rule with this rule_id already exists",
            ));
        }
        Err(err) if err.kind == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut keys: Vec<_> = rule.as_map().keys().collect();
    keys.sort_unstable();
    let preview_details = keys
        .into_iter()
        .map(|key| {
            let mut value = rule.as_map()[key].clone();
            sort_value(&mut value);
            format!(
                "{key}: {}",
                serde_json::to_string(&value).expect("JSON values serialize")
            )
        })
        .collect();
    let preview = MutationPlan {
        preview_action: "Create 1 rule (disabled)".into(),
        targets: vec![id.clone()],
        preview_details,
    };
    let seen = Preconditions(vec![crate::observe::Observed {
        object: "rule",
        id,
        state: None,
    }]);
    Ok((RuleCreatePlan { rule, preview }, seen))
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for value in map.values_mut() {
                sort_value(value);
            }
            map.sort_keys();
        }
        Value::Array(values) => {
            for value in values {
                sort_value(value);
            }
        }
        _ => {}
    }
}

/// Create the disabled rule in the plan.
pub async fn apply_create(t: &Transport, plan: &RuleCreatePlan) -> Result<RuleCreateOutcome> {
    if plan.rule.as_map().get("enabled") != Some(&json!(false)) {
        return Err(Error::new(ErrorKind::Error, "rule must be disabled"));
    }
    let id = plan.rule.rule_id()?;
    let response = rules::create(t, &plan.rule).await?;
    if response.rule_id().ok() != Some(id)
        || response.as_map().get("enabled") != Some(&json!(false))
    {
        return Err(Error::new(
            ErrorKind::Http,
            "created rule has unexpected identity or enabled state",
        ));
    }
    Ok(RuleCreateOutcome {
        applied: true,
        rule_id: id.to_owned(),
        enabled: false,
    })
}
