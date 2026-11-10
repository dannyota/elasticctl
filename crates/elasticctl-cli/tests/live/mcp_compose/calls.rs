//! The call phase. Two `elasticctl mcp serve` children, as in the eleventh
//! contract: the default catalog on the current protocol, then a second
//! child on the legacy protocol. Each task tool is called by name, each
//! result passes its exact-field validator, and every call is timed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use elasticctl_core::Flavor;
use serde_json::{Value, json};

use super::expect::{self, Expected};
use super::shape::GROUPINGS;
use crate::mcp_smoke::{McpChild, McpChildHarness, McpProtocolPath, run_mcp_children};
use crate::{LIVE_TAG, TestResult, unique_name};

const CONTRACT: &str = "mcp_answers_across_verticals";

/// The default catalog with the four task tools, in order (design section 7).
const DEFAULT_CATALOG: [&str; 24] = [
    "alert_context",
    "alerts_get",
    "alerts_list",
    "cases_get",
    "cases_list",
    "dashboards_get",
    "dashboards_list",
    "data_views_default_get",
    "data_views_get",
    "data_views_list",
    "detection_coverage",
    "exceptions_get",
    "exceptions_list",
    "fleet_agent_policies_get",
    "fleet_agent_policies_list",
    "fleet_integration_policies_get",
    "fleet_integration_policies_list",
    "rule_health",
    "rule_readiness",
    "rules_get",
    "rules_list",
    "rules_prebuilt_status",
    "stack_doctor",
    "stack_info",
];

/// Which timings feed the latency gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Measure {
    /// A call on the maximum-work objects.
    MaxWork,
    /// One of the two consecutive default `detection_coverage` calls.
    Coverage,
    Other,
}

#[derive(Clone, Debug)]
pub(crate) struct Timing {
    pub(crate) tool: &'static str,
    pub(crate) call: &'static str,
    pub(crate) protocol: &'static str,
    pub(crate) elapsed: Duration,
    pub(crate) pages: Option<u64>,
    pub(crate) measure: Measure,
}

#[derive(Default, Debug)]
pub(crate) struct Timings {
    pub(crate) rows: Vec<Timing>,
}

/// Round up, so a public line never shows a call as faster than it was.
pub(crate) fn whole_seconds(elapsed: Duration) -> u64 {
    elapsed.as_secs() + u64::from(elapsed.subsec_nanos() > 0)
}

impl Timings {
    /// Every call with its full wall time, for the owner-only log.
    pub(crate) fn private_lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| {
                format!(
                    "{CONTRACT} tool={} call={} protocol={} micros={} pages={}",
                    row.tool,
                    row.call,
                    row.protocol,
                    row.elapsed.as_micros(),
                    row.pages
                        .map_or_else(|| "-".to_string(), |pages| pages.to_string())
                )
            })
            .collect()
    }

    /// One line per tool in whole seconds: the slowest maximum-work call, and
    /// for `detection_coverage` both default calls with their page count.
    pub(crate) fn public_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for tool in ["alert_context", "rule_health", "rule_readiness"] {
            let slowest = self
                .rows
                .iter()
                .filter(|row| row.tool == tool && row.measure == Measure::MaxWork)
                .map(|row| row.elapsed)
                .max();
            if let Some(slowest) = slowest {
                lines.push(format!(
                    "{CONTRACT} timing {tool} {}s",
                    whole_seconds(slowest)
                ));
            }
        }
        let coverage: Vec<&Timing> = self
            .rows
            .iter()
            .filter(|row| row.tool == "detection_coverage" && row.measure == Measure::Coverage)
            .collect();
        if !coverage.is_empty() {
            let mut line = format!("{CONTRACT} timing detection_coverage");
            for row in &coverage {
                line.push_str(&format!(" {}s", whole_seconds(row.elapsed)));
            }
            if let Some(pages) = coverage.iter().find_map(|row| row.pages) {
                line.push_str(&format!(" pages {pages}"));
            }
            lines.push(line);
        }
        lines
    }
}

/// The owner-only log beside the conformance runner's private logs. The
/// probe's flavor names the file, so concurrent matrix legs do not collide.
pub(crate) fn private_timing_path(flavor: Flavor) -> PathBuf {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .parent()
        .map_or_else(|| PathBuf::from("target"), Path::to_path_buf);
    target
        .join("conformance-private")
        .join("timings")
        .join(format!("{CONTRACT}-{}.log", flavor.as_str()))
}

pub(crate) fn write_private_lines(path: &Path, lines: &[String]) -> TestResult {
    let parent = path
        .parent()
        .ok_or_else(|| "Compose timing log path is invalid.".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|_| "Compose timing log directory could not be created.".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "Compose timing log could not be restricted.".to_string())?;
        }
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Compose timing log could not be opened.".to_string())?;
    for line in lines {
        writeln!(file, "{line}").map_err(|_| "Compose timing log write failed.".to_string())?;
    }
    Ok(())
}

/// Write straight to stdout: the test harness captures `println!` output of
/// a passing test, and these lines belong in every run's output.
pub(crate) fn emit_public_lines(lines: &[String]) {
    let mut stdout = std::io::stdout().lock();
    // The harness has already written `test <name> ... ` without a newline;
    // start a fresh line so the first timing line stands on its own.
    let _ = writeln!(stdout);
    for line in lines {
        let _ = writeln!(stdout, "{line}");
    }
    let _ = stdout.flush();
}

fn protocol_label(path: McpProtocolPath) -> &'static str {
    match path {
        McpProtocolPath::Current => "current",
        McpProtocolPath::Legacy => "legacy",
    }
}

/// The exact catalog for a child, with the cache hints its protocol requires.
pub(crate) fn validate_compose_catalog(
    catalog: &Value,
    allow_query_tools: bool,
    protocol: McpProtocolPath,
) -> TestResult {
    let result = catalog
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| "MCP compose tools/list response has no catalog.".to_string())?;
    if result
        .keys()
        .any(|key| !["tools", "nextCursor", "ttlMs", "cacheScope"].contains(&key.as_str()))
    {
        return Err("MCP compose tools/list response contained unexpected fields.".to_string());
    }
    let hints_valid = match protocol {
        McpProtocolPath::Current => {
            result.get("ttlMs") == Some(&json!(0))
                && result.get("cacheScope") == Some(&json!("private"))
        }
        McpProtocolPath::Legacy => {
            !result.contains_key("ttlMs") && !result.contains_key("cacheScope")
        }
    };
    if !hints_valid {
        return Err("MCP compose catalog cache hints did not match the protocol.".to_string());
    }
    if result
        .get("nextCursor")
        .is_some_and(|cursor| !cursor.is_null())
    {
        return Err("MCP compose catalog included a continuation cursor.".to_string());
    }
    let names: Option<Vec<&str>> = result
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .map(|tool| tool.get("name").and_then(Value::as_str))
                .collect::<Option<Vec<_>>>()
        })
        .unwrap_or_default();
    let mut required = DEFAULT_CATALOG.to_vec();
    if allow_query_tools {
        required.splice(22..22, ["search_dsl", "search_esql"]);
    }
    if names.as_deref() != Some(required.as_slice()) {
        return Err("MCP compose catalog differs from the required catalog.".to_string());
    }
    Ok(())
}

/// The two-child harness for the shared two-protocol runner.
pub(crate) struct ComposeChildren<'a> {
    pub(crate) config: &'a Path,
    pub(crate) expected: &'a Expected<'a>,
    pub(crate) timings: &'a mut Timings,
}

impl McpChildHarness for ComposeChildren<'_> {
    type Child = McpChild;

    fn spawn(&mut self, allow_query_tools: bool) -> TestResult<Self::Child> {
        McpChild::spawn(self.config, allow_query_tools)
    }

    fn exercise(&mut self, child: &mut Self::Child, allow_query_tools: bool) -> TestResult {
        if allow_query_tools {
            legacy_calls(child, self.expected, self.timings)
        } else {
            current_calls(child, self.expected, self.timings)
        }
    }

    fn shutdown(&mut self, child: &mut Self::Child) -> TestResult {
        child.shutdown()
    }
}

/// Run both children. Timings are kept even when a call fails.
pub(crate) fn run_calls(
    config: &Path,
    expected: &Expected<'_>,
    timings: &mut Timings,
) -> TestResult {
    run_mcp_children(&mut ComposeChildren {
        config,
        expected,
        timings,
    })
}

/// One child and the timings of its calls.
struct Session<'a> {
    child: &'a mut McpChild,
    timings: &'a mut Timings,
}

impl Session<'_> {
    fn record(&mut self, tool: &'static str, call: &'static str, measure: Measure, since: Instant) {
        self.timings.rows.push(Timing {
            tool,
            call,
            protocol: protocol_label(self.child.protocol_path),
            elapsed: since.elapsed(),
            pages: None,
            measure,
        });
    }

    /// Call a tool by name and record its wall time, whatever the outcome.
    fn call(
        &mut self,
        tool: &'static str,
        call: &'static str,
        measure: Measure,
        arguments: Value,
    ) -> TestResult<Value> {
        let started = Instant::now();
        let result = self.child.tool(tool, arguments);
        self.record(tool, call, measure, started);
        result
    }

    fn catalog(&mut self, allow_query_tools: bool) -> TestResult {
        let catalog = self.child.request("tools/list", json!({}))?;
        validate_compose_catalog(&catalog, allow_query_tools, self.child.protocol_path)
    }
}

/// The reads of design section 12.3 on the current protocol.
fn current_calls(child: &mut McpChild, e: &Expected<'_>, timings: &mut Timings) -> TestResult {
    let discovery = child.request("server/discover", json!({}))?;
    if discovery.pointer("/result/supportedVersions") != Some(&json!(["2026-07-28", "2025-11-25"]))
    {
        return Err("MCP discovery did not advertise the supported protocols.".to_string());
    }
    let mut s = Session { child, timings };
    s.catalog(false)?;
    let (ids, p) = (e.ids, e.provisioned);
    let other = Measure::Other;

    let work = json!({"alert_id": p.work_alert});
    let content = s.call("alert_context", "work", Measure::MaxWork, work)?;
    expect::alert_context_work(&content, e)?;
    let degraded = json!({"alert_id": p.degraded_alert});
    let content = s.call("alert_context", "degraded", other, degraded)?;
    expect::alert_context_degraded(&content, e)?;
    let started = Instant::now();
    let absent = json!({"alert_id": unique_name("compose-missing-alert")});
    let absent = s.child.not_found("alert_context", absent, None);
    s.record("alert_context", "absent", other, started);
    absent?;

    let by_name = json!({"selector": ids.work_name()});
    let content = s.call("rule_health", "work", Measure::MaxWork, by_name.clone())?;
    expect::rule_health_work(&content, e)?;
    let content = s.call("rule_readiness", "work", Measure::MaxWork, by_name)?;
    expect::readiness_work(&content, e)?;
    let degraded = json!({"selector": ids.degraded_rule});
    let content = s.call("rule_readiness", "degraded", other, degraded)?;
    expect::readiness_degraded(&content, e)?;
    let view = json!({"selector": ids.view_rule});
    let content = s.call("rule_readiness", "view", other, view)?;
    expect::readiness_view(&content, e)?;

    for group_by in GROUPINGS {
        let arguments = json!({"group_by": group_by, "source": "custom", "limit": 200});
        let content = s.call("detection_coverage", group_by, other, arguments)?;
        expect::coverage_custom(&content, group_by, e)?;
    }
    for call in ["default-1", "default-2"] {
        let content = s.call("detection_coverage", call, Measure::Coverage, json!({}))?;
        let rules = expect::coverage_default(&content, e)?;
        if let Some(row) = s.timings.rows.last_mut() {
            row.pages = Some(expect::corpus_pages(rules));
        }
    }

    for (call, mut arguments) in [
        ("technique", json!({"technique": "T1059"})),
        ("tactic", json!({"tactic": "TA0002"})),
        ("subtechnique", json!({"technique": "T1059.001"})),
    ] {
        arguments["tag"] = json!(LIVE_TAG);
        arguments["limit"] = json!(10);
        let content = s.call("rules_list", call, other, arguments)?;
        expect::rules_list_threat(&content, e)?;
    }
    let content = s.call("rules_list", "default", other, json!({}))?;
    expect::rules_list_default(&content)?;
    super::resources::current_checks(s.child, e)
}

/// One call of each task tool on the legacy protocol.
fn legacy_calls(child: &mut McpChild, e: &Expected<'_>, timings: &mut Timings) -> TestResult {
    let initialize = child.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "elasticctl-live-compose", "version": env!("CARGO_PKG_VERSION")},
        }),
    )?;
    if initialize
        .pointer("/result/protocolVersion")
        .and_then(Value::as_str)
        != Some("2025-11-25")
    {
        return Err("MCP initialize did not negotiate the legacy protocol.".to_string());
    }
    child.notify("notifications/initialized", json!({}))?;
    let mut s = Session { child, timings };
    s.catalog(true)?;
    let work = json!({"alert_id": e.provisioned.work_alert});
    let content = s.call("alert_context", "work", Measure::MaxWork, work)?;
    expect::alert_context_work(&content, e)?;
    let by_name = json!({"selector": e.ids.work_name()});
    let content = s.call("rule_health", "work", Measure::MaxWork, by_name.clone())?;
    expect::rule_health_work(&content, e)?;
    let content = s.call("rule_readiness", "work", Measure::MaxWork, by_name)?;
    expect::readiness_work(&content, e)?;
    let arguments = json!({"group_by": "index_pattern", "source": "custom", "limit": 200});
    let content = s.call(
        "detection_coverage",
        "index_pattern",
        Measure::Other,
        arguments,
    )?;
    expect::coverage_custom(&content, "index_pattern", e)?;
    super::resources::not_found_checks(s.child)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(tool: &'static str, call: &'static str, millis: u64, measure: Measure) -> Timing {
        Timing {
            tool,
            call,
            protocol: "current",
            elapsed: Duration::from_millis(millis),
            pages: None,
            measure,
        }
    }

    #[test]
    fn the_public_timing_line_carries_whole_seconds_only() {
        let mut timings = Timings::default();
        timings
            .rows
            .push(row("alert_context", "work", 1_234, Measure::MaxWork));
        timings
            .rows
            .push(row("alert_context", "work", 2_000, Measure::MaxWork));
        timings
            .rows
            .push(row("alert_context", "degraded", 9_999, Measure::Other));
        timings
            .rows
            .push(row("rule_health", "work", 999, Measure::MaxWork));
        timings
            .rows
            .push(row("rule_readiness", "work", 14_001, Measure::MaxWork));
        timings.rows.push(row(
            "detection_coverage",
            "technique",
            30_500,
            Measure::Other,
        ));
        let mut first = row("detection_coverage", "default-1", 3_250, Measure::Coverage);
        first.pages = Some(8);
        timings.rows.push(first);
        let mut second = row("detection_coverage", "default-2", 2_750, Measure::Coverage);
        second.pages = Some(8);
        timings.rows.push(second);

        let public = timings.public_lines();
        assert_eq!(
            public,
            [
                "mcp_answers_across_verticals timing alert_context 2s",
                "mcp_answers_across_verticals timing rule_health 1s",
                "mcp_answers_across_verticals timing rule_readiness 15s",
                "mcp_answers_across_verticals timing detection_coverage 4s 3s pages 8",
            ]
        );
        for line in &public {
            assert!(!line.contains('.') && !line.contains("ms") && !line.contains("micros"));
        }
        let private = timings.private_lines();
        assert_eq!(private.len(), 8);
        assert_eq!(
            private[0],
            "mcp_answers_across_verticals tool=alert_context call=work protocol=current micros=1234000 pages=-"
        );
        assert!(private[6].ends_with("micros=3250000 pages=8"));
        assert_eq!(whole_seconds(Duration::ZERO), 0);
        assert_eq!(whole_seconds(Duration::from_nanos(1)), 1);
    }

    #[test]
    fn private_timings_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("timings.log");
        write_private_lines(&path, &["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let path = private_timing_path(Flavor::SelfManaged);
        assert!(path.ends_with(
            "conformance-private/timings/mcp_answers_across_verticals-self-managed.log"
        ));
    }

    #[test]
    fn the_compose_catalog_is_exact_for_both_children() {
        let tools = |names: &[&str]| -> Vec<Value> {
            names.iter().map(|name| json!({"name": name})).collect()
        };
        let current = json!({"result": {"tools": tools(&DEFAULT_CATALOG), "nextCursor": null,
            "ttlMs": 0, "cacheScope": "private"}});
        validate_compose_catalog(&current, false, McpProtocolPath::Current).unwrap();
        let mut query = DEFAULT_CATALOG.to_vec();
        query.splice(22..22, ["search_dsl", "search_esql"]);
        let legacy = json!({"result": {"tools": tools(&query)}});
        validate_compose_catalog(&legacy, true, McpProtocolPath::Legacy).unwrap();

        let old = json!({"result": {"tools": tools(&DEFAULT_CATALOG[1..]), "nextCursor": null}});
        assert!(validate_compose_catalog(&old, false, McpProtocolPath::Legacy).is_err());
        assert!(validate_compose_catalog(&legacy, false, McpProtocolPath::Legacy).is_err());
        assert!(validate_compose_catalog(&current, false, McpProtocolPath::Legacy).is_err());
        let mut extra = current.clone();
        extra["result"]["_meta"] = json!({});
        assert!(validate_compose_catalog(&extra, false, McpProtocolPath::Current).is_err());
    }
}
