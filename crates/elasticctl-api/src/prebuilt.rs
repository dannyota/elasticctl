//! Prebuilt-rule status and installation (spec 4.6).
//!
//! `status` reads the public prepackaged status route and adds the customized
//! count from one filtered `_find`. `install` is one verb because
//! `PUT .../rules/prepackaged` installs missing rules and updates outdated ones
//! in one request. The route takes no selection.

use crate::ops::MutationPlan;
use crate::rules::{self, RuleFilter, RuleSource};
use elasticctl_core::{Result, Transport};
use serde::Serialize;
use serde_json::Value;

const PREPACKAGED_STATUS: &str = "/api/detection_engine/rules/prepackaged/_status";
const PREPACKAGED: &str = "/api/detection_engine/rules/prepackaged";

/// The report `rules prebuilt status` renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrebuiltStatus {
    pub installed: u64,
    pub not_installed: u64,
    pub not_updated: u64,
    pub custom_installed: u64,
    /// Prebuilt rules edited on the stack. Costs one extra `_find`. Spec 4.6.
    pub customized: u64,
    pub timelines_installed: u64,
    pub timelines_not_installed: u64,
    pub timelines_not_updated: u64,
}

/// The report an `install` apply renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PrebuiltInstallOutcome {
    pub applied: bool,
    pub rules_installed: u64,
    pub rules_updated: u64,
    pub timelines_installed: u64,
    pub timelines_updated: u64,
}

pub async fn status(t: &Transport) -> Result<PrebuiltStatus> {
    let body = t.get(PREPACKAGED_STATUS).await?;
    let customized = customized_count(t).await?;
    Ok(PrebuiltStatus {
        installed: body["rules_installed"].as_u64().unwrap_or(0),
        not_installed: body["rules_not_installed"].as_u64().unwrap_or(0),
        not_updated: body["rules_not_updated"].as_u64().unwrap_or(0),
        custom_installed: body["rules_custom_installed"].as_u64().unwrap_or(0),
        customized,
        timelines_installed: body["timelines_installed"].as_u64().unwrap_or(0),
        timelines_not_installed: body["timelines_not_installed"].as_u64().unwrap_or(0),
        timelines_not_updated: body["timelines_not_updated"].as_u64().unwrap_or(0),
    })
}

/// The number of prebuilt rules edited on the stack. Read `total` only: a
/// prebuilt rule edited in the Kibana UI is invisible to a custom-scoped
/// mirror, and an unrecorded edit is exactly what a detection engineer needs
/// to see (spec 4.6).
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

    // The preview is client-computed from `_status`, not from a server dry
    // run: `PUT .../prepackaged` has no `dry_run` parameter. Every other
    // guarded path in this codebase previews server-side; this is the one
    // that cannot, so a "nothing to do" status would hide real updates. Name
    // both counts always, even when one is zero.
    let plan = MutationPlan {
        preview_action: format!(
            "Install {} missing and update {} outdated prebuilt rule(s)",
            s.not_installed, s.not_updated
        ),
        preview_details: vec![
            format!("{} missing rule(s) to install", s.not_installed),
            format!("{} outdated rule(s) to update", s.not_updated),
        ],
        // The route takes no selection, so there are no object identities.
        targets: Vec::new(),
    };

    Ok((plan, s))
}

pub async fn apply_install(t: &Transport) -> Result<PrebuiltInstallOutcome> {
    // The route takes no selection, so the body is empty. `Transport::put`
    // always sends one, and `null` is the empty JSON body.
    let body = t.put(PREPACKAGED, &Value::Null).await?;
    Ok(PrebuiltInstallOutcome {
        applied: true,
        rules_installed: body["rules_installed"].as_u64().unwrap_or(0),
        rules_updated: body["rules_updated"].as_u64().unwrap_or(0),
        timelines_installed: body["timelines_installed"].as_u64().unwrap_or(0),
        timelines_updated: body["timelines_updated"].as_u64().unwrap_or(0),
    })
}
