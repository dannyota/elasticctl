use crate::ops::MutationPlan;
use crate::rules::{self, RuleFilter, RuleSource};
use elasticctl_core::{Error, ErrorKind, Feature, Result, Transport};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PREPACKAGED_STATUS: &str = "/api/detection_engine/rules/prepackaged/_status";
const PREPACKAGED: &str = "/api/detection_engine/rules/prepackaged";

#[derive(Deserialize)]
struct StatusWire {
    rules_installed: u64,
    rules_custom_installed: u64,
    rules_not_installed: u64,
    rules_not_updated: u64,
    timelines_installed: u64,
    timelines_not_installed: u64,
    timelines_not_updated: u64,
}

#[derive(Deserialize)]
struct InstallOutcomeWire {
    rules_installed: u64,
    rules_updated: u64,
    timelines_installed: u64,
    timelines_updated: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrebuiltStatus {
    pub installed: u64,
    pub not_installed: u64,
    pub not_updated: u64,
    pub custom_installed: u64,
    pub customized: u64,
    pub timelines_installed: u64,
    pub timelines_not_installed: u64,
    pub timelines_not_updated: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrebuiltInstallOutcome {
    pub applied: bool,
    pub rules_installed: u64,
    pub rules_updated: u64,
    pub timelines_installed: u64,
    pub timelines_updated: u64,
}

pub async fn status(t: &Transport) -> Result<PrebuiltStatus> {
    t.require_feature(Feature::PrebuiltRules).await?;
    let body = t.get(PREPACKAGED_STATUS).await?;
    let mut status = decode_status(body, 0)?;
    status.customized = customized_count(t).await?;
    Ok(status)
}

fn decode_status(body: Value, customized: u64) -> Result<PrebuiltStatus> {
    validate_counters(
        &body,
        PREPACKAGED_STATUS,
        &[
            "rules_installed",
            "rules_custom_installed",
            "rules_not_installed",
            "rules_not_updated",
            "timelines_installed",
            "timelines_not_installed",
            "timelines_not_updated",
        ],
    )?;
    let body: StatusWire = serde_json::from_value(body)
        .map_err(|error| response_decode_error(PREPACKAGED_STATUS, error))?;
    Ok(PrebuiltStatus {
        installed: body.rules_installed,
        not_installed: body.rules_not_installed,
        not_updated: body.rules_not_updated,
        custom_installed: body.rules_custom_installed,
        customized,
        timelines_installed: body.timelines_installed,
        timelines_not_installed: body.timelines_not_installed,
        timelines_not_updated: body.timelines_not_updated,
    })
}

async fn customized_count(t: &Transport) -> Result<u64> {
    let filter = RuleFilter {
        source: RuleSource::Customized,
        ..Default::default()
    };
    let (_, total) = rules::find_page(t, &filter, 1, 1).await?;
    Ok(total)
}

pub async fn plan_install(t: &Transport) -> Result<(MutationPlan, PrebuiltStatus)> {
    let s = status(t).await?;

    let plan = MutationPlan {
        preview_action: format!(
            "Install {} missing and update {} outdated prebuilt rule(s)",
            s.not_installed, s.not_updated
        ),
        preview_details: vec![
            format!("{} missing rule(s) to install", s.not_installed),
            format!("{} outdated rule(s) to update", s.not_updated),
        ],
        targets: Vec::new(),
    };

    Ok((plan, s))
}

pub async fn apply_install(t: &Transport) -> Result<PrebuiltInstallOutcome> {
    t.require_feature(Feature::PrebuiltRules).await?;
    let body = t.put(PREPACKAGED, &Value::Null).await?;
    decode_install_outcome(body)
}

fn decode_install_outcome(body: Value) -> Result<PrebuiltInstallOutcome> {
    validate_counters(
        &body,
        PREPACKAGED,
        &[
            "rules_installed",
            "rules_updated",
            "timelines_installed",
            "timelines_updated",
        ],
    )?;
    let body: InstallOutcomeWire =
        serde_json::from_value(body).map_err(|error| response_decode_error(PREPACKAGED, error))?;
    Ok(PrebuiltInstallOutcome {
        applied: true,
        rules_installed: body.rules_installed,
        rules_updated: body.rules_updated,
        timelines_installed: body.timelines_installed,
        timelines_updated: body.timelines_updated,
    })
}

fn response_decode_error(endpoint: &str, error: serde_json::Error) -> Error {
    Error::new(
        ErrorKind::Http,
        format!("invalid prebuilt response from {endpoint}: {error}"),
    )
}

fn validate_counters(body: &Value, endpoint: &str, fields: &[&str]) -> Result<()> {
    let object = body.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::Http,
            format!("invalid prebuilt response from {endpoint}: expected an object"),
        )
    })?;
    for field in fields {
        if object.get(*field).and_then(Value::as_u64).is_none() {
            return Err(Error::new(
                ErrorKind::Http,
                format!(
                    "invalid prebuilt response from {endpoint}: field `{field}` must be a non-negative integer"
                ),
            ));
        }
    }
    Ok(())
}
