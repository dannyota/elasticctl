use elasticctl_api::{ListFilter, RuleFilter, RuleSource};
use elasticctl_api_test_support::fleet::FleetState;
use elasticctl_core::{Capabilities, Error, ErrorKind, Feature, Transport};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TargetState {
    pub(super) custom: u64,
    pub(super) prebuilt: u64,
    pub(super) customized: u64,
    pub(super) marked_rules: u64,
    pub(super) marked_lists: usize,
    pub(super) marked_indices: usize,
    pub(super) marked_data_views: usize,
    pub(super) marked_dashboards: u64,
    pub(super) default_data_view: Option<String>,
    /// Open (non-`closed`) `elasticctl-live-*` marker alerts. Closed marker
    /// alerts are never counted here at all — the capture query below
    /// excludes them, which *is* the triage contract's accepted alert-residue
    /// tolerance (design spec `elasticctl-triage-design.md` section 9): a
    /// closed marker alert is inert and stays out of every baseline count.
    pub(super) open_marked_alerts: u64,
    /// `elasticctl-live-marker`-tagged cases. Unlike alerts, cases delete
    /// cleanly through a public API, so this carries no such tolerance and
    /// must be zero like every other partition (same spec section).
    pub(super) marked_cases: u64,
    pub(super) fleet: Option<FleetState>,
}

/// Whether a feature is available on the measured target.
///
/// This mirrors the per-contract skip gate exactly: both use the same
/// `Capabilities::require_feature` floor. A below-floor target reports every
/// feature as unavailable, so `TargetState::capture` defaults the gated
/// partitions to 0 instead of failing the baseline before the skip
/// classification can run.
///
/// Exception: `open_marked_alerts` and `marked_cases` are *not* gated by this
/// function at all — no `Feature::Alerts`/`Feature::Cases` variant exists,
/// because every supported stack (9.5.1+) serves `signals/search` and
/// `cases/_find` unconditionally. A target that cannot answer those routes
/// cannot be audited for triage residue either, so `capture` fails the whole
/// baseline for it instead of defaulting the two triage partitions to 0 —
/// silently reporting "clean" when the harness could not actually check
/// would be the dishonest outcome, not the fail.
pub(super) fn feature_available(capabilities: &Capabilities, feature: Feature) -> bool {
    capabilities.require_feature(feature).is_ok()
}

impl TargetState {
    pub(super) async fn capture(
        transport: &Transport,
        capabilities: &Capabilities,
    ) -> elasticctl_core::Result<Self> {
        async fn rule_total(
            transport: &Transport,
            source: RuleSource,
            tag: Option<&str>,
        ) -> elasticctl_core::Result<u64> {
            let (_, total) = elasticctl_api::rules::find_page(
                transport,
                &RuleFilter {
                    source,
                    tag: tag.map(str::to_string),
                    ..Default::default()
                },
                1,
                1,
            )
            .await?;
            Ok(total)
        }

        let source_scoped = feature_available(capabilities, Feature::RuleSourceScoping);
        let custom = if source_scoped {
            rule_total(transport, RuleSource::Custom, None).await?
        } else {
            0
        };
        let prebuilt = if source_scoped {
            rule_total(transport, RuleSource::Prebuilt, None).await?
        } else {
            0
        };
        let customized = if source_scoped {
            rule_total(transport, RuleSource::Customized, None).await?
        } else {
            0
        };
        let marked_rules =
            rule_total(transport, RuleSource::All, Some("elasticctl-live-marker")).await?;
        let mut marked_lists = 0;
        if feature_available(capabilities, Feature::ExceptionLists) {
            for namespace in ["single", "agnostic"] {
                marked_lists += elasticctl_api::exceptions::find_lists(
                    transport,
                    &ListFilter {
                        tag: Some("elasticctl-live-marker".to_string()),
                        namespace: Some(namespace.to_string()),
                        ..Default::default()
                    },
                )
                .await?
                .len();
            }
        }
        let marked_indices = match transport
            .get_absolute_es("/_resolve/index/elasticctl-live-*")
            .await
        {
            Ok(body) => body
                .get("indices")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Http,
                        "invalid marked-index response: indices must be an array",
                    )
                })?
                .len(),
            Err(Error {
                kind: ErrorKind::NotFound,
                ..
            }) => 0,
            Err(error) => return Err(error),
        };
        let marked_data_views = elasticctl_api::data_views::list(transport)
            .await?
            .into_iter()
            .filter(|view| view.id.starts_with("elasticctl-live-"))
            .count();
        let marked_dashboards = if feature_available(capabilities, Feature::Dashboards) {
            elasticctl_api::dashboards_ops::list_op(
                transport,
                &elasticctl_api::dashboards_ops::DashboardFilter::default(),
            )
            .await?
            .dashboards
            .into_iter()
            .filter(|dashboard| dashboard.id.starts_with("elasticctl-live-"))
            .count() as u64
        } else {
            0
        };
        let default_data_view = elasticctl_api::data_views::get_default(transport).await?;

        // Same prefix + must_not-closed body live.rs's own baseline counter
        // sends (crates/elasticctl-cli/tests/live.rs::open_marker_alert_count):
        // every `elasticctl-live-`-prefixed marker rule's alerts, excluding
        // `workflow_status: closed`. Un-gated by `Feature`: every supported
        // stack serves `signals/search`.
        let open_marked_alerts = {
            let body = serde_json::json!({
                "query": {"bool": {
                    "filter": [{"prefix": {"kibana.alert.rule.rule_id": "elasticctl-live-"}}],
                    "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}],
                }},
                "size": 0,
                "track_total_hits": true,
            });
            transport
                .post(elasticctl_api::alerts::SEARCH_PATH, Some(&body))
                .await?
                .pointer("/hits/total/value")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Http,
                        "invalid alert-count response: hits.total.value must be a number",
                    )
                })?
        };

        // Same tag-filtered find query live.rs's own baseline counter sends
        // (crates/elasticctl-cli/tests/live.rs::marker_case_count).
        let marked_cases = {
            let query = elasticctl_api::cases_ops::find_query(
                &elasticctl_api::cases_ops::CaseFilter {
                    tag: Some("elasticctl-live-marker".to_string()),
                    ..Default::default()
                },
                1,
                1,
            );
            let (_cases, total) = elasticctl_api::cases::find_page(transport, &query).await?;
            total
        };
        let fleet = capture_fleet_state(transport, capabilities).await?;

        Ok(Self {
            custom,
            prebuilt,
            customized,
            marked_rules,
            marked_lists,
            marked_indices,
            marked_data_views,
            marked_dashboards,
            default_data_view,
            open_marked_alerts,
            marked_cases,
            fleet,
        })
    }

    /// `open_marked_alerts` is already the *open* count only — `capture`'s
    /// query excludes `workflow_status: closed`, so a closed marker alert
    /// never reaches this field at all. Requiring it to be zero here still
    /// tolerates closed residue without a separate branch: the exclusion at
    /// capture time *is* the tolerance (triage spec section 9). `marked_cases`
    /// carries no such deviation and is held to zero unconditionally.
    fn markers_are_clean(&self) -> bool {
        self.marked_rules == 0
            && self.marked_lists == 0
            && self.marked_indices == 0
            && self.marked_data_views == 0
            && self.marked_dashboards == 0
            && self.open_marked_alerts == 0
            && self.marked_cases == 0
            && self.fleet.as_ref().is_none_or(FleetState::markers_empty)
    }

    pub(super) fn assert_clean_start(&self) -> Result<(), String> {
        if self.markers_are_clean() {
            Ok(())
        } else {
            Err("conformance baseline is not marker-clean".to_string())
        }
    }

    pub(super) fn assert_clean_against(&self, baseline: &Self) -> Result<(), String> {
        if self.markers_are_clean()
            && self.custom == baseline.custom
            && self.prebuilt == baseline.prebuilt
            && self.customized == baseline.customized
            && self.default_data_view == baseline.default_data_view
            && self.fleet == baseline.fleet
        {
            Ok(())
        } else {
            Err("conformance cleanup audit failed".to_string())
        }
    }
}

async fn capture_fleet_state(
    transport: &Transport,
    capabilities: &Capabilities,
) -> elasticctl_core::Result<Option<FleetState>> {
    if !feature_available(capabilities, Feature::FleetPolicies) {
        return Ok(None);
    }
    FleetState::capture(transport).await.map(Some)
}

pub(super) async fn setup_fleet(transport: &Transport) -> elasticctl_core::Result<()> {
    let body = transport
        .post_once("/api/fleet/setup", Some(&serde_json::json!({})))
        .await?;
    if body
        .get("isInitialized")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Http, "invalid Fleet setup response"))
    }
}
