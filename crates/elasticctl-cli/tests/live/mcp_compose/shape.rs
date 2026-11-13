use serde_json::{Map, Value};

use crate::TestResult;

type Object = Map<String, Value>;

const ERROR_MESSAGES: [(&str, &str); 9] = [
    (
        "auth",
        "The selected credential could not be authenticated.",
    ),
    (
        "permission",
        "The selected credential cannot read this data.",
    ),
    ("not_found", "The selected resource was not found."),
    (
        "conflict",
        "The selected resource conflicts with current state.",
    ),
    (
        "unsupported",
        "The selected deployment does not support this operation.",
    ),
    ("http", "The selected deployment returned an HTTP error."),
    (
        "connection",
        "The selected deployment could not be reached.",
    ),
    (
        "timeout",
        "The selected deployment did not respond before the timeout.",
    ),
    ("error", "The request could not be completed."),
];
const SKIP_REASONS: [&str; 3] = ["not_applicable", "dependency_unavailable", "not_configured"];
pub(crate) const ALERT_FINDINGS: [&str; 6] = [
    "alert_not_open",
    "rule_missing",
    "rule_disabled",
    "rule_last_execution_failed",
    "exception_list_missing",
    "has_related_case",
];
pub(crate) const HEALTH_FINDINGS: [&str; 7] = [
    "rule_disabled",
    "never_executed",
    "last_execution_failed",
    "last_execution_partial_failure",
    "execution_gap",
    "no_alerts_in_window",
    "exception_list_missing",
];
pub(crate) const READINESS_FINDINGS: [&str; 9] = [
    "rule_disabled",
    "no_index_source",
    "data_view_missing",
    "no_pattern_matches",
    "pattern_unresolved",
    "integration_not_installed",
    "integration_without_policy",
    "patterns_truncated",
    "integrations_truncated",
];
pub(crate) const GROUPINGS: [&str; 4] = ["technique", "tactic", "index_pattern", "integration"];
const RULE_FIELDS: [&str; 13] = [
    "name",
    "type",
    "enabled",
    "severity",
    "risk_score",
    "tags",
    "description",
    "language",
    "query",
    "index",
    "from",
    "interval",
    "exceptions_list",
];
const RULE_ROW_FIELDS: [&str; 6] = ["name", "type", "enabled", "severity", "risk_score", "tags"];
const ALERT_SOURCE_FIELDS: [&str; 8] = [
    "@timestamp",
    "kibana.alert.rule.rule_id",
    "kibana.alert.rule.name",
    "kibana.alert.severity",
    "kibana.alert.risk_score",
    "kibana.alert.workflow_status",
    "kibana.alert.reason",
    "kibana.alert.workflow_tags",
];
const CASE_FIELDS: [&str; 8] = [
    "title",
    "status",
    "severity",
    "tags",
    "description",
    "created_at",
    "updated_at",
    "totalComment",
];
const METRICS: [&str; 4] = [
    "total_search_duration_ms",
    "total_indexing_duration_ms",
    "total_enrichment_duration_ms",
    "execution_gap_duration_s",
];
const MESSAGE_BYTES: usize = 2_048;
const MAX_LISTS: u64 = 5;
const MAX_CASES: u64 = 5;
const MAX_RECENT: usize = 5;
const MAX_PATTERNS: u64 = 16;
const MAX_PACKAGES: u64 = 8;

fn fail<T>(context: &'static str, what: &'static str) -> TestResult<T> {
    Err(format!("MCP {context} {what}."))
}

fn object<'a>(value: &'a Value, context: &'static str) -> TestResult<&'a Object> {
    value
        .as_object()
        .map_or_else(|| fail(context, "was not an object"), Ok)
}

fn keys(map: &Object, required: &[&str], optional: &[&str], context: &'static str) -> TestResult {
    if required.iter().any(|key| !map.contains_key(*key)) {
        return fail(context, "omitted a required field");
    }
    if map
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return fail(context, "contained unexpected fields");
    }
    Ok(())
}

fn string<'a>(map: &'a Object, key: &str, context: &'static str) -> TestResult<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .map_or_else(|| fail(context, "had a missing or non-string field"), Ok)
}

fn count(map: &Object, key: &str, context: &'static str) -> TestResult<u64> {
    map.get(key)
        .and_then(Value::as_u64)
        .map_or_else(|| fail(context, "had a missing or non-integer count"), Ok)
}

fn boolean(map: &Object, key: &str, context: &'static str) -> TestResult<bool> {
    map.get(key)
        .and_then(Value::as_bool)
        .map_or_else(|| fail(context, "had a missing or non-boolean field"), Ok)
}

fn array<'a>(map: &'a Object, key: &str, context: &'static str) -> TestResult<&'a Vec<Value>> {
    map.get(key)
        .and_then(Value::as_array)
        .map_or_else(|| fail(context, "had a missing or non-array field"), Ok)
}

fn optional(map: &Object, key: &str, kind: Kind, context: &'static str) -> TestResult {
    let Some(value) = map.get(key) else {
        return Ok(());
    };
    let valid = match kind {
        Kind::Str => value.is_string(),
        Kind::Bool => value.is_boolean(),
        Kind::Number => value.is_number(),
        Kind::Count => value.as_u64().is_some(),
        Kind::Strings => value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string)),
    };
    if valid {
        Ok(())
    } else {
        fail(context, "had an optional field of the wrong type")
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Str,
    Bool,
    Number,
    Count,
    Strings,
}

fn null_page<'a>(content: &'a Value, tool: &'static str) -> TestResult<&'a Object> {
    if content.get("page") != Some(&Value::Null) {
        return fail(tool, "included page metadata");
    }
    object(&content["data"], tool)
}

pub(crate) fn tool_error(value: &Value, context: &'static str) -> TestResult<String> {
    let error = object(value, context)?;
    keys(
        error,
        &["kind", "http_status", "code", "message"],
        &[],
        context,
    )?;
    let kind = string(error, "kind", context)?;
    let Some((_, message)) = ERROR_MESSAGES.iter().find(|(known, _)| *known == kind) else {
        return fail(context, "had an unknown error kind");
    };
    if string(error, "code", context)? != format!("elastic_{kind}")
        || string(error, "message", context)? != *message
    {
        return fail(
            context,
            "had an error code or message outside the static mapping",
        );
    }
    match &error["http_status"] {
        Value::Null => {}
        status if status.as_u64().is_some_and(|s| (100..=599).contains(&s)) => {}
        _ => return fail(context, "had an invalid error status"),
    }
    Ok(kind.to_string())
}

pub(crate) enum Part<'a> {
    Ok(&'a Value),
    Unavailable,
    Skipped,
}

fn part<'a>(map: &'a Object, key: &str, context: &'static str) -> TestResult<Part<'a>> {
    let part = object(
        map.get(key)
            .map_or_else(|| fail(context, "omitted a part"), Ok)?,
        context,
    )?;
    match part.get("status").and_then(Value::as_str) {
        Some("ok") => {
            keys(part, &["status", "value"], &[], context)?;
            Ok(Part::Ok(&part["value"]))
        }
        Some("unavailable") => {
            keys(part, &["status", "error"], &[], context)?;
            tool_error(&part["error"], context)?;
            Ok(Part::Unavailable)
        }
        Some("skipped") => {
            keys(part, &["status", "skip_reason"], &[], context)?;
            if !SKIP_REASONS.contains(&string(part, "skip_reason", context)?) {
                return fail(context, "had an unknown skip reason");
            }
            Ok(Part::Skipped)
        }
        _ => fail(context, "had an invalid part status"),
    }
}

fn row_status(row: &Object, ok_only: &[&str], context: &'static str) -> TestResult<bool> {
    match string(row, "status", context)? {
        "ok" if !row.contains_key("error") => Ok(true),
        "unavailable" if ok_only.iter().all(|key| !row.contains_key(*key)) => {
            tool_error(
                row.get("error")
                    .map_or_else(|| fail(context, "omitted its row error"), Ok)?,
                context,
            )?;
            Ok(false)
        }
        _ => fail(context, "had an invalid row status"),
    }
}

fn findings(map: &Object, allowed: &[&str], context: &'static str) -> TestResult {
    let mut last = None;
    for code in array(map, "findings", context)? {
        let position = code
            .as_str()
            .and_then(|code| allowed.iter().position(|known| *known == code));
        match position {
            Some(position) if last.is_none_or(|last| position > last) => last = Some(position),
            _ => return fail(context, "had an unknown, repeated, or misordered finding"),
        }
    }
    Ok(())
}

fn partial(map: &Object, expected: bool, context: &'static str) -> TestResult {
    if boolean(map, "partial", context)? != expected {
        return fail(context, "had a partial flag that disagrees with its parts");
    }
    Ok(())
}

fn alert(value: &Value, context: &'static str) -> TestResult {
    let alert = object(value, context)?;
    keys(alert, &["id", "source"], &["index"], context)?;
    string(alert, "id", context)?;
    optional(alert, "index", Kind::Str, context)?;
    let source = object(&alert["source"], context)?;
    keys(source, &[], &ALERT_SOURCE_FIELDS, context)?;
    for field in [
        "@timestamp",
        "kibana.alert.rule.rule_id",
        "kibana.alert.rule.name",
        "kibana.alert.severity",
        "kibana.alert.workflow_status",
        "kibana.alert.reason",
    ] {
        optional(source, field, Kind::Str, context)?;
    }
    optional(source, "kibana.alert.risk_score", Kind::Number, context)?;
    optional(source, "kibana.alert.workflow_tags", Kind::Strings, context)
}

fn rule_context(value: &Value, context: &'static str) -> TestResult {
    let rule = object(value, context)?;
    keys(rule, &["rule_id", "execution"], &RULE_FIELDS, context)?;
    string(rule, "rule_id", context)?;
    for field in [
        "name",
        "type",
        "severity",
        "description",
        "language",
        "query",
        "from",
        "interval",
    ] {
        optional(rule, field, Kind::Str, context)?;
    }
    optional(rule, "enabled", Kind::Bool, context)?;
    optional(rule, "risk_score", Kind::Number, context)?;
    optional(rule, "tags", Kind::Strings, context)?;
    optional(rule, "index", Kind::Strings, context)?;
    if let Some(references) = rule.get("exceptions_list") {
        for reference in references
            .as_array()
            .map_or_else(|| fail(context, "had a non-array reference list"), Ok)?
        {
            let reference = object(reference, context)?;
            keys(
                reference,
                &[],
                &["list_id", "namespace_type", "type"],
                context,
            )?;
            for field in ["list_id", "namespace_type", "type"] {
                optional(reference, field, Kind::Str, context)?;
            }
        }
    }
    execution(&rule["execution"], context)
}

fn execution(value: &Value, context: &'static str) -> TestResult {
    if value.is_null() {
        return Ok(());
    }
    let execution = object(value, context)?;
    keys(
        execution,
        &["status", "date", "message_truncated", "metrics"],
        &["status_order", "message"],
        context,
    )?;
    string(execution, "status", context)?;
    string(execution, "date", context)?;
    boolean(execution, "message_truncated", context)?;
    optional(execution, "status_order", Kind::Number, context)?;
    optional(execution, "message", Kind::Str, context)?;
    if execution
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.len() > MESSAGE_BYTES)
    {
        return fail(context, "returned an execution message above the cap");
    }
    let metrics = object(&execution["metrics"], context)?;
    keys(metrics, &[], &METRICS, context)?;
    for metric in METRICS {
        optional(metrics, metric, Kind::Number, context)?;
    }
    Ok(())
}

fn exception_coverage(value: &Value, context: &'static str) -> TestResult<bool> {
    let coverage = object(value, context)?;
    keys(
        coverage,
        &["referenced", "truncated", "lists"],
        &[],
        context,
    )?;
    let referenced = count(coverage, "referenced", context)?;
    let lists = array(coverage, "lists", context)?;
    if boolean(coverage, "truncated", context)? != (referenced > MAX_LISTS)
        || lists.len() as u64 != referenced.min(MAX_LISTS)
    {
        return fail(context, "had list counts that disagree with the cap");
    }
    let mut unavailable = false;
    for row in lists {
        let row = object(row, context)?;
        keys(
            row,
            &["list_id", "namespace_type", "status"],
            &["type", "error", "name", "list_type", "item_count"],
            context,
        )?;
        string(row, "list_id", context)?;
        string(row, "namespace_type", context)?;
        optional(row, "type", Kind::Str, context)?;
        if row_status(row, &["name", "list_type", "item_count"], context)? {
            count(row, "item_count", context)?;
            optional(row, "name", Kind::Str, context)?;
            optional(row, "list_type", Kind::Str, context)?;
        } else {
            unavailable = true;
        }
    }
    Ok(unavailable)
}

fn related_cases(value: &Value, context: &'static str) -> TestResult<bool> {
    let cases = object(value, context)?;
    keys(cases, &["total", "truncated", "cases"], &[], context)?;
    let total = count(cases, "total", context)?;
    let rows = array(cases, "cases", context)?;
    if boolean(cases, "truncated", context)? != (total > MAX_CASES)
        || rows.len() as u64 != total.min(MAX_CASES)
    {
        return fail(context, "had case counts that disagree with the cap");
    }
    let mut unavailable = false;
    for row in rows {
        let row = object(row, context)?;
        keys(row, &["id", "status"], &["title", "error", "case"], context)?;
        if string(row, "id", context)?.is_empty() {
            return fail(context, "had an empty case id");
        }
        optional(row, "title", Kind::Str, context)?;
        if row_status(row, &["case"], context)? {
            let case = object(
                row.get("case")
                    .map_or_else(|| fail(context, "omitted the case of an ok row"), Ok)?,
                context,
            )?;
            keys(case, &["id"], &CASE_FIELDS, context)?;
            string(case, "id", context)?;
            for field in [
                "title",
                "status",
                "severity",
                "description",
                "created_at",
                "updated_at",
            ] {
                optional(case, field, Kind::Str, context)?;
            }
            optional(case, "tags", Kind::Strings, context)?;
            optional(case, "totalComment", Kind::Count, context)?;
        } else {
            unavailable = true;
        }
    }
    Ok(unavailable)
}

fn activity(value: &Value, with_recent: bool, context: &'static str) -> TestResult {
    let activity = object(value, context)?;
    let required: &[&str] = if with_recent {
        &["window", "total", "by_status", "recent"]
    } else {
        &["window", "total", "by_status"]
    };
    keys(activity, required, &[], context)?;
    string(activity, "window", context)?;
    let total = count(activity, "total", context)?;
    let by_status = object(&activity["by_status"], context)?;
    keys(
        by_status,
        &["open", "acknowledged", "closed", "other"],
        &[],
        context,
    )?;
    let mut sum = 0_u64;
    for status in ["open", "acknowledged", "closed", "other"] {
        sum = sum.saturating_add(count(by_status, status, context)?);
    }
    if sum > total {
        return fail(context, "had status counts above its total");
    }
    if with_recent {
        let recent = array(activity, "recent", context)?;
        if recent.len() > MAX_RECENT {
            return fail(context, "returned more than five recent alerts");
        }
        for row in recent {
            alert(row, context)?;
        }
    }
    Ok(())
}

pub(crate) fn alert_context(content: &Value) -> TestResult {
    const CONTEXT: &str = "alert_context data";
    let data = null_page(content, "alert_context")?;
    keys(
        data,
        &[
            "alert",
            "rule",
            "exceptions",
            "cases",
            "activity",
            "partial",
            "findings",
        ],
        &[],
        CONTEXT,
    )?;
    alert(&data["alert"], "alert_context alert")?;
    let mut unavailable = false;
    match part(data, "rule", "alert_context rule")? {
        Part::Ok(value) => rule_context(value, "alert_context rule")?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    match part(data, "exceptions", "alert_context exceptions")? {
        Part::Ok(value) => unavailable |= exception_coverage(value, "alert_context exceptions")?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    match part(data, "cases", "alert_context cases")? {
        Part::Ok(value) => unavailable |= related_cases(value, "alert_context cases")?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    match part(data, "activity", "alert_context activity")? {
        Part::Ok(value) => activity(value, false, "alert_context activity")?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    partial(data, unavailable, CONTEXT)?;
    findings(data, &ALERT_FINDINGS, CONTEXT)
}

pub(crate) fn rule_health(content: &Value) -> TestResult {
    const CONTEXT: &str = "rule_health data";
    let data = null_page(content, "rule_health")?;
    keys(
        data,
        &["rule", "alerts", "exceptions", "partial", "findings"],
        &[],
        CONTEXT,
    )?;
    rule_context(&data["rule"], "rule_health rule")?;
    let mut unavailable = false;
    match part(data, "alerts", "rule_health alerts")? {
        Part::Ok(value) => activity(value, true, "rule_health alerts")?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    match part(data, "exceptions", "rule_health exceptions")? {
        Part::Ok(value) => unavailable |= exception_coverage(value, "rule_health exceptions")?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    partial(data, unavailable, CONTEXT)?;
    findings(data, &HEALTH_FINDINGS, CONTEXT)
}

pub(crate) fn rule_readiness(content: &Value) -> TestResult {
    const CONTEXT: &str = "rule_readiness data";
    let data = null_page(content, "rule_readiness")?;
    keys(
        data,
        &[
            "rule",
            "index_source",
            "data_views",
            "patterns",
            "integrations",
            "partial",
            "findings",
        ],
        &[],
        CONTEXT,
    )?;
    let rule = object(&data["rule"], "rule_readiness rule")?;
    keys(
        rule,
        &["rule_id"],
        &["name", "type", "enabled"],
        "rule_readiness rule",
    )?;
    string(rule, "rule_id", "rule_readiness rule")?;
    optional(rule, "name", Kind::Str, "rule_readiness rule")?;
    optional(rule, "type", Kind::Str, "rule_readiness rule")?;
    optional(rule, "enabled", Kind::Bool, "rule_readiness rule")?;
    let source = string(data, "index_source", CONTEXT)?;
    if !["index", "data_view", "none"].contains(&source) {
        return fail(CONTEXT, "had an unknown index source");
    }
    let mut unavailable = false;
    let views_ok = match part(data, "data_views", "rule_readiness data_views")? {
        Part::Ok(value) => {
            data_views(value, source == "data_view")?;
            true
        }
        Part::Unavailable => {
            unavailable = true;
            false
        }
        Part::Skipped => false,
    };
    match part(data, "patterns", "rule_readiness patterns")? {
        Part::Ok(value) => unavailable |= patterns(value, views_ok)?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    match part(data, "integrations", "rule_readiness integrations")? {
        Part::Ok(value) => unavailable |= integrations(value)?,
        Part::Unavailable => unavailable = true,
        Part::Skipped => {}
    }
    partial(data, unavailable, CONTEXT)?;
    findings(data, &READINESS_FINDINGS, CONTEXT)
}

fn data_views(value: &Value, rule_view: bool) -> TestResult {
    const CONTEXT: &str = "rule_readiness data_views";
    let views = object(value, CONTEXT)?;
    if rule_view {
        keys(views, &["count", "rule_data_view"], &[], CONTEXT)?;
        let view = object(&views["rule_data_view"], CONTEXT)?;
        keys(view, &["id", "found"], &["title", "name"], CONTEXT)?;
        string(view, "id", CONTEXT)?;
        boolean(view, "found", CONTEXT)?;
        optional(view, "title", Kind::Str, CONTEXT)?;
        optional(view, "name", Kind::Str, CONTEXT)?;
    } else {
        keys(views, &["count"], &[], CONTEXT)?;
    }
    count(views, "count", CONTEXT).map(|_| ())
}

fn patterns(value: &Value, views_ok: bool) -> TestResult<bool> {
    const CONTEXT: &str = "rule_readiness patterns";
    let patterns = object(value, CONTEXT)?;
    keys(patterns, &["total", "truncated", "rows"], &[], CONTEXT)?;
    let total = count(patterns, "total", CONTEXT)?;
    let rows = array(patterns, "rows", CONTEXT)?;
    if boolean(patterns, "truncated", CONTEXT)? != (total > MAX_PATTERNS)
        || rows.len() as u64 != total.min(MAX_PATTERNS)
    {
        return fail(CONTEXT, "had pattern counts that disagree with the cap");
    }
    let view_ids: &[&str] = if views_ok { &["data_view_ids"] } else { &[] };
    let mut unresolved = false;
    for row in rows {
        let row = object(row, CONTEXT)?;
        string(row, "pattern", CONTEXT)?;
        match string(row, "state", CONTEXT)? {
            state @ ("matches" | "no_match") => {
                let mut required = vec!["pattern", "state", "indices", "aliases", "data_streams"];
                required.extend_from_slice(view_ids);
                keys(row, &required, &[], CONTEXT)?;
                let mut sum = 0_u64;
                for field in ["indices", "aliases", "data_streams"] {
                    sum = sum.saturating_add(count(row, field, CONTEXT)?);
                }
                if (state == "matches") != (sum > 0) {
                    return fail(CONTEXT, "had a state that disagrees with its counts");
                }
            }
            "exclusion" => {
                let mut required = vec!["pattern", "state"];
                required.extend_from_slice(view_ids);
                keys(row, &required, &[], CONTEXT)?;
            }
            "unresolved" => {
                let mut required = vec!["pattern", "state"];
                required.extend_from_slice(view_ids);
                keys(row, &required, &["error"], CONTEXT)?;
                if let Some(error) = row.get("error") {
                    tool_error(error, CONTEXT)?;
                }
                unresolved = true;
            }
            _ => return fail(CONTEXT, "had an unknown pattern state"),
        }
        if let Some(ids) = row.get("data_view_ids") {
            let ids = ids
                .as_array()
                .map_or_else(|| fail(CONTEXT, "had non-array data view ids"), Ok)?;
            let ids: Option<Vec<&str>> = ids.iter().map(Value::as_str).collect();
            let sorted = ids.is_some_and(|ids| ids.windows(2).all(|pair| pair[0] < pair[1]));
            if !sorted {
                return fail(CONTEXT, "had unsorted or non-string data view ids");
            }
        }
    }
    Ok(unresolved)
}

fn integrations(value: &Value) -> TestResult<bool> {
    const CONTEXT: &str = "rule_readiness integrations";
    let integrations = object(value, CONTEXT)?;
    keys(integrations, &["total", "truncated", "rows"], &[], CONTEXT)?;
    let total = count(integrations, "total", CONTEXT)?;
    let rows = array(integrations, "rows", CONTEXT)?;
    if boolean(integrations, "truncated", CONTEXT)? != (total > MAX_PACKAGES)
        || rows.len() as u64 != total.min(MAX_PACKAGES)
    {
        return fail(CONTEXT, "had package counts that disagree with the cap");
    }
    let ok_fields = ["install_status", "installed_version", "policies"];
    let mut unavailable = false;
    for row in rows {
        let row = object(row, CONTEXT)?;
        keys(
            row,
            &["package", "status"],
            &[
                "version",
                "error",
                "install_status",
                "installed_version",
                "policies",
            ],
            CONTEXT,
        )?;
        string(row, "package", CONTEXT)?;
        optional(row, "version", Kind::Str, CONTEXT)?;
        if row_status(row, &ok_fields, CONTEXT)? {
            string(row, "install_status", CONTEXT)?;
            count(row, "policies", CONTEXT)?;
            optional(row, "installed_version", Kind::Str, CONTEXT)?;
        } else {
            unavailable = true;
        }
    }
    Ok(unavailable)
}

pub(crate) fn detection_coverage(content: &Value) -> TestResult {
    const CONTEXT: &str = "detection_coverage data";
    let data = object(&content["data"], CONTEXT)?;
    keys(data, &["group_by", "summary", "rows"], &[], CONTEXT)?;
    let group_by = string(data, "group_by", CONTEXT)?;
    if !GROUPINGS.contains(&group_by) {
        return fail(CONTEXT, "had an unknown grouping");
    }
    let summary = object(&data["summary"], "detection_coverage summary")?;
    let fields = [
        "rules",
        "enabled_rules",
        "disabled_rules",
        "unmapped_rules",
        "groups",
    ];
    keys(summary, &fields, &[], "detection_coverage summary")?;
    for field in fields {
        count(summary, field, "detection_coverage summary")?;
    }
    if summary["enabled_rules"].as_u64().unwrap_or_default()
        + summary["disabled_rules"].as_u64().unwrap_or_default()
        != summary["rules"].as_u64().unwrap_or_default()
    {
        return fail("detection_coverage summary", "had counts that do not sum");
    }
    let optional_fields: &[&str] = match group_by {
        "technique" => &["name", "tactics"],
        "tactic" => &["name"],
        _ => &[],
    };
    let rows = array(data, "rows", CONTEXT)?;
    let mut previous: Option<(u64, u64, &str)> = None;
    for row in rows {
        let row = object(row, "detection_coverage row")?;
        let mut required = vec!["key", "enabled_rules", "disabled_rules"];
        if group_by == "technique" {
            required.push("tactics");
        }
        keys(row, &required, optional_fields, "detection_coverage row")?;
        let key = string(row, "key", "detection_coverage row")?;
        let enabled = count(row, "enabled_rules", "detection_coverage row")?;
        let disabled = count(row, "disabled_rules", "detection_coverage row")?;
        optional(row, "name", Kind::Str, "detection_coverage row")?;
        if let Some(tactics) = row.get("tactics") {
            let tactics: Option<Vec<&str>> = tactics
                .as_array()
                .and_then(|t| t.iter().map(Value::as_str).collect());
            if !tactics.is_some_and(|t| t.windows(2).all(|pair| pair[0] < pair[1])) {
                return fail("detection_coverage row", "had unsorted or invalid tactics");
            }
        }
        if let Some((p_enabled, p_disabled, p_key)) = previous {
            let ordered = (p_enabled, p_disabled) > (enabled, disabled)
                || ((p_enabled, p_disabled) == (enabled, disabled) && p_key < key);
            if !ordered {
                return fail("detection_coverage row", "was out of order");
            }
        }
        previous = Some((enabled, disabled, key));
    }
    let page = object(&content["page"], "detection_coverage page")?;
    list_page(page, rows.len(), "detection_coverage page")?;
    if page["total"] != summary["groups"] || page["limit"].as_u64().is_none_or(|l| l > 200) {
        return fail("detection_coverage page", "disagreed with its summary");
    }
    Ok(())
}

fn list_page(page: &Object, returned: usize, context: &'static str) -> TestResult {
    keys(
        page,
        &["limit", "returned", "total", "has_more", "truncated"],
        &[],
        context,
    )?;
    let limit = count(page, "limit", context)?;
    let total = count(page, "total", context)?;
    let truncated = boolean(page, "truncated", context)?;
    if count(page, "returned", context)? != returned as u64
        || returned as u64 > limit
        || boolean(page, "has_more", context)? != truncated
        || truncated != ((returned as u64) < total)
    {
        return fail(context, "did not describe its rows");
    }
    Ok(())
}

pub(crate) fn rules_list(content: &Value, limit: u64) -> TestResult {
    const CONTEXT: &str = "rules_list data";
    let data = object(&content["data"], CONTEXT)?;
    keys(data, &["rules"], &[], CONTEXT)?;
    let rows = array(data, "rules", CONTEXT)?;
    for row in rows {
        let row = object(row, "rules_list row")?;
        keys(row, &["rule_id"], &RULE_ROW_FIELDS, "rules_list row")?;
        string(row, "rule_id", "rules_list row")?;
        for field in ["name", "type", "severity"] {
            optional(row, field, Kind::Str, "rules_list row")?;
        }
        optional(row, "enabled", Kind::Bool, "rules_list row")?;
        optional(row, "risk_score", Kind::Number, "rules_list row")?;
        optional(row, "tags", Kind::Strings, "rules_list row")?;
    }
    let page = object(&content["page"], "rules_list page")?;
    list_page(page, rows.len(), "rules_list page")?;
    if page["limit"] != limit {
        return fail("rules_list page", "had another limit");
    }
    Ok(())
}

#[cfg(test)]
#[path = "shape_samples.rs"]
pub(crate) mod samples;
#[cfg(test)]
#[path = "shape_tests.rs"]
mod tests;
