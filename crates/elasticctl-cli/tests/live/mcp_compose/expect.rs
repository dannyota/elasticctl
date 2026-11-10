//! Expected values for each call of design section 12.3. Every function
//! first runs the exact-field shape check, then compares values with the
//! objects this run provisioned.

use std::collections::BTreeSet;

use serde_json::Value;

use super::fill::{FILL_TARGET, RuleFill};
use super::objects::{ComposeIds, Provisioned, WORK_PACKAGES};
use super::shape;
use crate::mcp_smoke::validate_case_row;
use crate::{LIVE_TAG, TestResult};

/// Rules a default `detection_coverage` call must read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Corpus {
    /// The lab after the fill.
    Exact(u64),
    /// Serverless and Hosted: at least the prebuilt rules.
    AtLeast(u64),
}

/// What the call phase compares against.
pub(crate) struct Expected<'a> {
    pub(crate) ids: &'a ComposeIds,
    pub(crate) provisioned: &'a Provisioned,
    pub(crate) fill: Option<&'a RuleFill>,
}

impl Expected<'_> {
    pub(crate) fn corpus(&self) -> Corpus {
        match self.fill {
            Some(_) => Corpus::Exact(FILL_TARGET),
            None => Corpus::AtLeast(self.provisioned.prebuilt_total),
        }
    }

    fn fill_count(&self) -> u64 {
        self.fill.map_or(0, |fill| fill.count as u64)
    }
}

fn at<'a>(content: &'a Value, pointer: &str) -> &'a Value {
    content.pointer(pointer).unwrap_or(&Value::Null)
}

fn require(condition: bool, message: &'static str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn findings(content: &Value) -> Vec<&str> {
    strings(at(content, "/data/findings"))
}

/// The alert projection holds the owned alert of `rule_id`.
fn owned_alert(alert: &Value, alert_id: &str, rule_id: &str) -> TestResult {
    let source = &alert["source"];
    require(
        alert["id"] == alert_id
            && source["kibana.alert.rule.rule_id"] == rule_id
            && source["kibana.alert.rule.name"] == ComposeIds::name_of(rule_id).as_str()
            && source["kibana.alert.workflow_status"] == "open",
        "MCP compose alert did not match the owned alert.",
    )
}

/// The rule context of an executed, enabled marker rule.
fn executed_rule(rule: &Value, rule_id: &str) -> TestResult {
    require(
        rule["rule_id"] == rule_id && rule["enabled"] == true && rule["execution"].is_object(),
        "MCP compose rule context did not show an executed owned rule.",
    )
}

/// The exception rows of rule W: five lists in rule order, all `ok`.
fn work_lists(coverage: &Value, ids: &ComposeIds) -> TestResult {
    let rows = coverage["lists"].as_array().map_or(&[][..], Vec::as_slice);
    require(
        coverage["referenced"] == ids.work_lists.len() as u64
            && coverage["truncated"] == false
            && rows.len() == ids.work_lists.len(),
        "MCP compose exception coverage did not list the five work lists.",
    )?;
    for (row, list) in rows.iter().zip(&ids.work_lists) {
        require(
            row["list_id"] == list.list_id.as_str()
                && row["status"] == "ok"
                && row["item_count"] == list.item_ids.len() as u64,
            "MCP compose work list row did not hold its item count.",
        )?;
    }
    Ok(())
}

pub(crate) fn alert_context_work(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::alert_context(content)?;
    let ids = e.ids;
    owned_alert(
        at(content, "/data/alert"),
        &e.provisioned.work_alert,
        &ids.work_rule,
    )?;
    for part in ["rule", "exceptions", "cases", "activity"] {
        require(
            at(content, &format!("/data/{part}/status")) == "ok",
            "MCP alert_context left a maximum-work part short of ok.",
        )?;
    }
    executed_rule(at(content, "/data/rule/value"), &ids.work_rule)?;
    work_lists(at(content, "/data/exceptions/value"), ids)?;
    let cases = at(content, "/data/cases/value");
    let rows = cases["cases"].as_array().map_or(&[][..], Vec::as_slice);
    require(
        cases["total"] == e.provisioned.cases.len() as u64
            && cases["truncated"] == false
            && rows.len() == e.provisioned.cases.len(),
        "MCP alert_context did not return the five owned cases.",
    )?;
    let returned: BTreeSet<&str> = rows.iter().filter_map(|r| r["id"].as_str()).collect();
    let owned: BTreeSet<&str> = e
        .provisioned
        .cases
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();
    require(returned == owned, "MCP alert_context returned other cases.")?;
    for row in rows {
        let (id, title) = e
            .provisioned
            .cases
            .iter()
            .find(|(id, _)| row["id"] == id.as_str())
            .ok_or_else(|| "MCP alert_context returned another case.".to_string())?;
        require(
            row["status"] == "ok" && row["title"] == title.as_str(),
            "MCP alert_context case row was not ok.",
        )?;
        let case = row["case"]
            .as_object()
            .ok_or_else(|| "MCP alert_context case row omitted its case.".to_string())?;
        validate_case_row(case, id, Some(title))?;
    }
    let activity = at(content, "/data/activity/value");
    require(
        activity["window"] == "24h"
            && activity["total"].as_u64().is_some_and(|t| t >= 1)
            && activity["by_status"]["open"]
                .as_u64()
                .is_some_and(|o| o >= 1),
        "MCP alert_context activity did not count the owned alert.",
    )?;
    require(
        at(content, "/data/partial") == false && findings(content) == ["has_related_case"],
        "MCP alert_context findings differed for the maximum-work alert.",
    )
}

pub(crate) fn alert_context_degraded(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::alert_context(content)?;
    let ids = e.ids;
    owned_alert(
        at(content, "/data/alert"),
        &e.provisioned.degraded_alert,
        &ids.degraded_rule,
    )?;
    require(
        at(content, "/data/rule/status") == "ok",
        "MCP alert_context did not read rule D.",
    )?;
    executed_rule(at(content, "/data/rule/value"), &ids.degraded_rule)?;
    let lists = at(content, "/data/exceptions/value/lists");
    require(
        at(content, "/data/exceptions/value/referenced") == 2
            && lists[0]["list_id"] == ids.degraded_list.list_id.as_str()
            && lists[0]["status"] == "ok"
            && lists[0]["item_count"] == 1
            && lists[1]["list_id"] == ids.missing_list.as_str()
            && lists[1]["status"] == "unavailable"
            && lists[1]["error"]["code"] == "elastic_not_found",
        "MCP alert_context did not degrade only the missing list row.",
    )?;
    require(
        at(content, "/data/cases/status") == "ok"
            && at(content, "/data/cases/value/total") == 0
            && at(content, "/data/cases/value/truncated") == false
            && at(content, "/data/cases/value/cases")
                .as_array()
                .is_some_and(Vec::is_empty),
        "MCP alert_context found a case for the rule D alert.",
    )?;
    require(
        at(content, "/data/activity/status") == "ok",
        "MCP alert_context did not read rule D activity.",
    )?;
    require(
        at(content, "/data/partial") == true && findings(content) == ["exception_list_missing"],
        "MCP alert_context findings differed for the degradation alert.",
    )
}

pub(crate) fn rule_health_work(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::rule_health(content)?;
    let ids = e.ids;
    let rule = at(content, "/data/rule");
    executed_rule(rule, &ids.work_rule)?;
    require(
        rule["name"] == ids.work_name().as_str(),
        "MCP rule_health did not resolve rule W by name.",
    )?;
    require(
        at(content, "/data/alerts/status") == "ok"
            && at(content, "/data/exceptions/status") == "ok",
        "MCP rule_health left a maximum-work part short of ok.",
    )?;
    let alerts = at(content, "/data/alerts/value");
    let recent = alerts["recent"].as_array().map_or(&[][..], Vec::as_slice);
    require(
        alerts["window"] == "24h" && alerts["total"].as_u64().is_some_and(|t| t >= 1),
        "MCP rule_health counted no alert in the window.",
    )?;
    let owned = recent
        .iter()
        .find(|alert| alert["id"] == e.provisioned.work_alert.as_str())
        .ok_or_else(|| "MCP rule_health recent alerts omitted the owned alert.".to_string())?;
    owned_alert(owned, &e.provisioned.work_alert, &ids.work_rule)?;
    work_lists(at(content, "/data/exceptions/value"), ids)?;
    let allowed = ["last_execution_partial_failure", "execution_gap"];
    require(
        at(content, "/data/partial") == false
            && findings(content).iter().all(|code| allowed.contains(code)),
        "MCP rule_health findings differed for the maximum-work rule.",
    )
}

pub(crate) fn readiness_work(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::rule_readiness(content)?;
    let ids = e.ids;
    require(
        at(content, "/data/rule/rule_id") == ids.work_rule.as_str()
            && at(content, "/data/rule/enabled") == true
            && at(content, "/data/index_source") == "index"
            && at(content, "/data/data_views/status") == "ok"
            && at(content, "/data/patterns/status") == "ok"
            && at(content, "/data/integrations/status") == "ok",
        "MCP rule_readiness left a maximum-work part short of ok.",
    )?;
    let patterns = at(content, "/data/patterns/value");
    let rows = patterns["rows"].as_array().map_or(&[][..], Vec::as_slice);
    let expected = ids.work_patterns();
    require(
        patterns["total"] == expected.len() as u64
            && patterns["truncated"] == false
            && rows.len() == expected.len(),
        "MCP rule_readiness did not resolve all 16 patterns.",
    )?;
    for (position, (row, pattern)) in rows.iter().zip(&expected).enumerate() {
        let state = if position == 0 { "matches" } else { "no_match" };
        require(
            row["pattern"] == pattern.as_str() && row["state"] == state,
            "MCP rule_readiness pattern row differed.",
        )?;
    }
    require(
        strings(&rows[0]["data_view_ids"]).contains(&ids.data_view.as_str()),
        "MCP rule_readiness did not name the marker data view.",
    )?;
    let integrations = at(content, "/data/integrations/value");
    let packages = integrations["rows"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let names: Vec<&str> = packages
        .iter()
        .filter_map(|row| row["package"].as_str())
        .collect();
    require(
        integrations["total"] == WORK_PACKAGES.len() as u64
            && integrations["truncated"] == false
            && names == WORK_PACKAGES
            && packages.iter().all(|row| row["status"] == "ok"),
        "MCP rule_readiness did not read all eight packages.",
    )?;
    require(
        packages[0]["install_status"] == "installed"
            && packages[0]["policies"].as_u64().is_some_and(|p| p >= 1),
        "MCP rule_readiness system row did not show the Fleet fixture.",
    )?;
    let allowed = ["integration_not_installed", "integration_without_policy"];
    require(
        at(content, "/data/partial") == false
            && findings(content).iter().all(|code| allowed.contains(code)),
        "MCP rule_readiness findings differed for the maximum-work rule.",
    )
}

pub(crate) fn readiness_degraded(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::rule_readiness(content)?;
    let ids = e.ids;
    let rows = at(content, "/data/patterns/value/rows");
    let packages = at(content, "/data/integrations/value/rows");
    require(
        at(content, "/data/rule/rule_id") == ids.degraded_rule.as_str()
            && at(content, "/data/index_source") == "index"
            && at(content, "/data/patterns/value/total") == 2
            && rows[0]["pattern"] == ids.index.as_str()
            && rows[0]["state"] == "matches"
            && rows[1]["pattern"] == ids.exclusion.as_str()
            && rows[1]["state"] == "exclusion",
        "MCP rule_readiness did not report the exclusion row.",
    )?;
    require(
        at(content, "/data/integrations/value/total") == 1
            && packages[0]["package"] == ids.unknown_package.as_str()
            && packages[0]["status"] == "unavailable",
        "MCP rule_readiness did not degrade the unknown package row.",
    )?;
    require(
        at(content, "/data/partial") == true && findings(content).is_empty(),
        "MCP rule_readiness findings differed for rule D.",
    )
}

pub(crate) fn readiness_view(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::rule_readiness(content)?;
    let ids = e.ids;
    let view = at(content, "/data/data_views/value/rule_data_view");
    let rows = at(content, "/data/patterns/value/rows");
    require(
        at(content, "/data/rule/rule_id") == ids.view_rule.as_str()
            && at(content, "/data/index_source") == "data_view"
            && view["id"] == ids.data_view.as_str()
            && view["found"] == true
            && view["title"] == ids.index.as_str(),
        "MCP rule_readiness did not find the marker data view.",
    )?;
    require(
        at(content, "/data/patterns/value/total") == 1
            && rows[0]["pattern"] == ids.index.as_str()
            && rows[0]["state"] == "matches"
            && at(content, "/data/integrations/value/total") == 0,
        "MCP rule_readiness did not resolve the data view pattern.",
    )?;
    require(
        at(content, "/data/partial") == false && findings(content) == ["rule_disabled"],
        "MCP rule_readiness findings differed for rule V.",
    )
}

fn row<'a>(rows: &'a [Value], key: &str) -> Option<&'a Value> {
    rows.iter().find(|row| row["key"] == key)
}

fn counts(rows: &[Value], key: &str) -> Option<(u64, u64)> {
    row(rows, key).and_then(|row| {
        Some((
            row["enabled_rules"].as_u64()?,
            row["disabled_rules"].as_u64()?,
        ))
    })
}

/// `source: custom` for one grouping: the marker keys with their counts.
pub(crate) fn coverage_custom(content: &Value, group_by: &str, e: &Expected<'_>) -> TestResult {
    shape::detection_coverage(content)?;
    let ids = e.ids;
    require(
        at(content, "/data/group_by") == group_by && at(content, "/page/has_more") == false,
        "MCP detection_coverage did not return every custom group.",
    )?;
    let rows = at(content, "/data/rows")
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let present = match group_by {
        "technique" => {
            row(rows, "T1059").is_some_and(|row| {
                row["enabled_rules"].as_u64().is_some_and(|n| n >= 1)
                    && strings(&row["tactics"]).contains(&"TA0002")
            }) && row(rows, "T1059.001").is_none()
        }
        "tactic" => counts(rows, "TA0002").is_some_and(|(enabled, _)| enabled >= 1),
        "index_pattern" => {
            counts(rows, &ids.index) == Some((2, e.fill_count()))
                && ids
                    .work_wildcards
                    .iter()
                    .all(|key| counts(rows, key) == Some((1, 0)))
                && counts(rows, &ids.exclusion) == Some((1, 0))
                && counts(rows, &format!("data_view:{}", ids.data_view)) == Some((0, 1))
        }
        "integration" => {
            counts(rows, &ids.unknown_package) == Some((1, 0))
                && WORK_PACKAGES
                    .iter()
                    .all(|key| counts(rows, key).is_some_and(|(enabled, _)| enabled >= 1))
        }
        _ => false,
    };
    require(
        present,
        "MCP detection_coverage marker keys differed from the expected counts.",
    )
}

/// A default call. Returns the rules it read.
pub(crate) fn coverage_default(content: &Value, e: &Expected<'_>) -> TestResult<u64> {
    shape::detection_coverage(content)?;
    let rules = at(content, "/data/summary/rules")
        .as_u64()
        .ok_or_else(|| "MCP detection_coverage omitted its rule count.".to_string())?;
    let read_all = match e.corpus() {
        Corpus::Exact(expected) => rules == expected,
        Corpus::AtLeast(floor) => rules >= floor,
    };
    require(
        at(content, "/data/group_by") == "technique" && at(content, "/page/limit") == 50,
        "MCP detection_coverage defaults differed.",
    )?;
    require(
        read_all,
        "MCP detection_coverage did not read the expected corpus.",
    )?;
    Ok(rules)
}

/// Pages a corpus read sends: `ceil(rules / 500)`.
pub(crate) fn corpus_pages(rules: u64) -> u64 {
    rules.div_ceil(500)
}

/// A threat-filtered `rules_list` scoped to the marker tag: rule W only.
pub(crate) fn rules_list_threat(content: &Value, e: &Expected<'_>) -> TestResult {
    shape::rules_list(content, 10)?;
    let rows = at(content, "/data/rules");
    require(
        rows.as_array().is_some_and(|rows| rows.len() == 1)
            && rows[0]["rule_id"] == e.ids.work_rule.as_str()
            && rows[0]["enabled"] == true
            && strings(&rows[0]["tags"]).contains(&LIVE_TAG)
            && at(content, "/page/total") == 1,
        "MCP rules_list threat filter did not return rule W alone.",
    )
}

pub(crate) fn rules_list_default(content: &Value) -> TestResult {
    shape::rules_list(content, 50)
}

#[cfg(test)]
mod tests {
    use super::super::shape::samples::*;
    use super::*;
    use elasticctl_core::Flavor;
    use serde_json::json;

    fn provisioned(ids: &ComposeIds) -> Provisioned {
        Provisioned {
            flavor: Flavor::SelfManaged,
            work_alert: "work-alert".to_string(),
            degraded_alert: "degraded-alert".to_string(),
            cases: ids
                .case_titles
                .iter()
                .enumerate()
                .map(|(n, title)| (format!("case-{n}"), title.clone()))
                .collect(),
            prebuilt_total: 1_000,
        }
    }

    fn work_alert_context(ids: &ComposeIds, p: &Provisioned) -> Value {
        let list_ids: Vec<&str> = ids.work_lists.iter().map(|l| l.list_id.as_str()).collect();
        let rows: Vec<Value> = ids
            .work_lists
            .iter()
            .map(|l| list_row(&l.list_id, l.item_ids.len() as u64))
            .collect();
        let cases: Vec<Value> = p
            .cases
            .iter()
            .map(|(id, title)| case_row(id, title))
            .collect();
        envelope(
            json!({
                "alert": alert(&p.work_alert, &ids.work_rule, &ids.work_name()),
                "rule": ok(rule(&ids.work_rule, &ids.work_name(), true, &list_ids)),
                "exceptions": ok(json!({"referenced": 5, "truncated": false, "lists": rows})),
                "cases": ok(json!({"total": 5, "truncated": false, "cases": cases})),
                "activity": ok(activity(3, None)),
                "partial": false,
                "findings": ["has_related_case"],
            }),
            Value::Null,
        )
    }

    #[test]
    fn maximum_work_expectations_accept_the_designed_answer_only() {
        let ids = ComposeIds::new();
        let p = provisioned(&ids);
        let e = Expected {
            ids: &ids,
            provisioned: &p,
            fill: None,
        };
        let sample = work_alert_context(&ids, &p);
        alert_context_work(&sample, &e).unwrap();

        let mut missing_case = sample.clone();
        missing_case["data"]["cases"]["value"]["cases"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(alert_context_work(&missing_case, &e).is_err());
        let mut wrong_count = sample.clone();
        wrong_count["data"]["exceptions"]["value"]["lists"][0]["item_count"] = json!(1);
        assert!(alert_context_work(&wrong_count, &e).is_err());
        let mut extra_finding = sample;
        extra_finding["data"]["findings"] = json!(["rule_disabled", "has_related_case"]);
        assert!(alert_context_work(&extra_finding, &e).is_err());
    }

    #[test]
    fn custom_index_pattern_coverage_counts_the_fill_on_the_marker_index() {
        let ids = ComposeIds::new();
        let p = provisioned(&ids);
        let fill = RuleFill {
            prefix: "elasticctl-sample-fill-n-".to_string(),
            count: 1_200,
            pre_total: 2_800,
        };
        let e = Expected {
            ids: &ids,
            provisioned: &p,
            fill: Some(&fill),
        };
        let mut rows = vec![json!({"key": ids.index, "enabled_rules": 2, "disabled_rules": 1_200})];
        let mut ones: Vec<String> = ids.work_wildcards.clone();
        ones.push(ids.exclusion.clone());
        ones.sort();
        rows.extend(
            ones.iter()
                .map(|key| json!({"key": key, "enabled_rules": 1, "disabled_rules": 0})),
        );
        rows.push(json!({"key": format!("data_view:{}", ids.data_view), "enabled_rules": 0, "disabled_rules": 1}));
        let total = rows.len();
        let sample = envelope(
            json!({"group_by": "index_pattern",
                "summary": {"rules": 1_203, "enabled_rules": 2, "disabled_rules": 1_201, "unmapped_rules": 0, "groups": total},
                "rows": rows}),
            coverage_page(200, total, total as u64),
        );
        coverage_custom(&sample, "index_pattern", &e).unwrap();
        let unfilled = Expected { fill: None, ..e };
        assert!(coverage_custom(&sample, "index_pattern", &unfilled).is_err());
        assert_eq!(unfilled.corpus(), Corpus::AtLeast(1_000));
        assert_eq!(e.corpus(), Corpus::Exact(4_000));
        assert_eq!(corpus_pages(4_000), 8);
        assert_eq!(corpus_pages(2_263), 5);
        assert_eq!(corpus_pages(0), 0);
    }
}
