//! Probe deployment capabilities at connection time.
//!
//! Commands can then report unsupported features before a 404 response.

use crate::error::{Error, ErrorKind, Result};
use crate::transport::Transport;
use semver::Version;
use serde_json::Value;

/// Hostname suffixes used by Elastic Cloud Hosted deployments.
///
/// This is a fallback, not the primary signal; see `probe`. It identifies
/// deployments reached through proxies that strip Cloud edge headers.
const ECH_SUFFIXES: [&str; 4] = [
    "elastic-cloud.com",
    "found.io",
    "cloud.es.io",
    "elastic.cloud",
];

/// Sent by the Elastic Cloud edge proxy. Present on Hosted and Serverless;
/// absent from unproxied stacks.
const CLOUD_EDGE_HEADER: &str = "x-found-handling-cluster";

/// Return the URL host without its port.
///
/// Matching the full URL would treat a suffix in its path or query as a
/// deployment signal.
fn host_of(url: &str) -> &str {
    // `config::scheme_anchor` handles a doubled scheme and a `://` in the path,
    // query, or fragment; a URL with no `://` passes through unchanged.
    let after_scheme = match crate::config::scheme_anchor(url) {
        Some(pos) => &url[pos..],
        None => url,
    };
    // The first `/`, `?`, `#`, or `:` ends the authority. `:` drops a port.
    after_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or("")
}

/// Whether `host` equals `suffix` or is its subdomain.
///
/// A bare `ends_with` would match `notfound.io` as `found.io`.
fn host_matches(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    SelfManaged,
    ElasticCloudHosted,
    Serverless,
}

/// Public feature areas whose availability depends on the measured stack
/// contract rather than on the existence of one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Dashboards,
    ExceptionLists,
    FleetPolicies,
    PrebuiltRules,
    RuleSourceScoping,
}

impl Feature {
    fn label(self) -> &'static str {
        match self {
            Self::Dashboards => "dashboards",
            Self::ExceptionLists => "exception lists",
            Self::FleetPolicies => "fleet policies",
            Self::PrebuiltRules => "prebuilt rules",
            Self::RuleSourceScoping => "rule source scoping",
        }
    }
}

impl Flavor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SelfManaged => "self-managed",
            Self::ElasticCloudHosted => "elastic-cloud-hosted",
            Self::Serverless => "serverless",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub flavor: Flavor,
    pub version: String,
}

/// Parse the numeric `major.minor.patch` from a reported version string.
///
/// A leading `v` and any pre-release or build suffix are ignored, so a lab or
/// snapshot build is not refused. A version with no numeric
/// `major.minor.patch` is unreadable.
fn numeric_version(version: &str) -> Option<Version> {
    let numeric = version
        .trim_start_matches(&['v', 'V'][..])
        .split(&['-', '+'][..])
        .next()
        .unwrap_or_default();
    Version::parse(numeric).ok()
}

impl Capabilities {
    pub async fn probe(t: &Transport, kibana_url: &str) -> Result<Capabilities> {
        let responded = t.get_with_headers("/api/status").await?;
        Ok(Self::classify(
            &responded.body,
            responded.header(CLOUD_EDGE_HEADER).is_some(),
            kibana_url,
        ))
    }

    /// Classify the flavor and version from one status response.
    ///
    /// This is separate from `probe` so recorded fixtures, not only mocks,
    /// test the response shapes for each flavor.
    ///
    /// Test Serverless before the Cloud edge signal. Hosted and self-managed
    /// stacks can both report `build_flavor: "traditional"`, while Serverless
    /// sends the same edge header as Hosted.
    pub fn classify(status: &Value, cloud_edge: bool, kibana_url: &str) -> Capabilities {
        let version = status["version"]["number"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let build_flavor = status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default");

        // `||` checks the hostname only when the edge header is absent.
        let host = host_of(kibana_url)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let cloud = cloud_edge
            || ECH_SUFFIXES
                .iter()
                .any(|suffix| host_matches(&host, suffix));

        let flavor = if build_flavor == "serverless" {
            Flavor::Serverless
        } else if cloud {
            Flavor::ElasticCloudHosted
        } else {
            Flavor::SelfManaged
        };

        Capabilities { flavor, version }
    }

    /// Return an unsupported error that names the feature and deployment
    /// flavor.
    pub fn require(&self, feature: &str, supported: bool) -> Result<()> {
        if supported {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "{feature} is not available on {} deployments",
                self.flavor.as_str()
            ),
        ))
    }

    /// Require a feature only on stack versions for which this client has
    /// complete fixture evidence.
    pub fn require_feature(&self, feature: Feature) -> Result<()> {
        let floor = Version::new(9, 5, 1);
        let supported = numeric_version(&self.version).is_some_and(|version| version >= floor);
        if supported {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "{} is not verified on {} {}; elasticctl requires Kibana {} or newer for this feature",
                feature.label(),
                self.flavor.as_str(),
                self.version,
                floor
            ),
        ))
    }
}

/// Return space IDs visible to this credential, or `None` when unavailable.
///
/// This is separate from `Capabilities::probe` because `doctor` and `config
/// test` do not report spaces or license tiers. `None` means the spaces could
/// not be determined; it never substitutes a configured space.
pub async fn probe_spaces(t: &Transport) -> Option<Vec<String>> {
    let body = t.get("/api/spaces/space").await.ok()?;
    let spaces = body.as_array()?;
    Some(
        spaces
            .iter()
            .filter_map(|s| s.get("id")?.as_str().map(str::to_owned))
            .collect(),
    )
}

/// Return the license tier, or `None` when it is unavailable.
///
/// Serverless uses project tiers, so it never calls the license endpoint.
/// Elsewhere, a failure leaves the tier unknown so `info` can continue.
pub async fn probe_license_tier(t: &Transport, flavor: Flavor) -> Option<String> {
    if flavor == Flavor::Serverless {
        return None;
    }
    let body = t.get_absolute_es("/_license").await.ok()?;
    body["license"]["type"].as_str().map(str::to_owned)
}
