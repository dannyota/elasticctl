//! One probe at connect time, so commands can fail with a clear
//! "not available on this deployment" instead of a confusing 404.

use crate::error::{Error, ErrorKind, Result};
use crate::transport::Transport;
use serde_json::Value;

/// Hostname suffixes used by Elastic Cloud Hosted deployments.
///
/// A fallback, not the primary signal — see `probe`. Kept for a deployment
/// reached through a proxy that strips the Cloud edge headers, where the
/// hostname is the only thing left to go on.
const ECH_SUFFIXES: [&str; 4] = [
    "elastic-cloud.com",
    "found.io",
    "cloud.es.io",
    "elastic.cloud",
];

/// Injected by the Elastic Cloud edge proxy. Present on Hosted and on
/// Serverless, absent from a stack nothing proxies.
const CLOUD_EDGE_HEADER: &str = "x-found-handling-cluster";

/// Host portion of a URL: after the last `://`, before the first `/`, minus
/// any `:port`. Matching the raw URL would let a suffix in a path or query
/// string decide the deployment flavor.
fn host_of(url: &str) -> &str {
    let after_scheme = match url.rfind("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let host = after_scheme.split('/').next().unwrap_or("");
    host.split(':').next().unwrap_or(host)
}

/// True when `host` is exactly `suffix` or a subdomain of it. A bare
/// `ends_with` would also match `notfound.io` against `found.io`.
fn host_matches(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    SelfManaged,
    ElasticCloudHosted,
    Serverless,
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

impl Capabilities {
    pub async fn probe(t: &Transport, kibana_url: &str) -> Result<Capabilities> {
        let responded = t.get_with_headers("/api/status").await?;
        Ok(Self::classify(
            &responded.body,
            responded.header(CLOUD_EDGE_HEADER).is_some(),
            kibana_url,
        ))
    }

    /// Flavor and version from one status response.
    ///
    /// Split out from `probe` so the decision can be tested against a recorded
    /// fixture rather than only against a mock server — the fixtures are the
    /// evidence that each flavor reports what this claims it does.
    ///
    /// The order of the tests is load-bearing. Elastic Cloud Hosted reports
    /// `build_flavor: "traditional"`, exactly what a self-managed stack
    /// reports, so the body alone cannot separate them and the edge header
    /// must decide. Serverless sits behind that same edge proxy and carries
    /// the same header, so testing the header first would classify every
    /// Serverless project as Hosted.
    pub fn classify(status: &Value, cloud_edge: bool, kibana_url: &str) -> Capabilities {
        let version = status["version"]["number"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let build_flavor = status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default");

        // `||` short-circuits, so the header still decides before the hostname
        // is ever examined — the fallback only runs for a deployment whose
        // edge headers never arrived.
        let cloud = cloud_edge
            || ECH_SUFFIXES
                .iter()
                .any(|s| host_matches(host_of(kibana_url), s));

        let flavor = if build_flavor == "serverless" {
            Flavor::Serverless
        } else if cloud {
            Flavor::ElasticCloudHosted
        } else {
            Flavor::SelfManaged
        };

        Capabilities { flavor, version }
    }

    /// Gate a feature on this deployment. The error names both the feature and
    /// the flavor, so the user knows why it is unavailable rather than
    /// guessing at a 404.
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
}

/// The ids of the spaces this credential can see, or `None` when the stack
/// will not say.
///
/// Deliberately not part of `Capabilities::probe`: `doctor` and `config test`
/// read capabilities and report neither a space list nor a licence tier, and
/// neither should pay a round trip for a field it does not print. `None` means
/// "could not determine" — never a fabricated list, which would read exactly
/// like a probe result and is not one.
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

/// The licence tier, or `None` where there is not one to read.
///
/// Serverless has no licence tiers — features gate on project tier instead —
/// so the endpoint is not called there at all. Anywhere else a failure is
/// reported as unknown rather than as an error: a missing licence tier must
/// not fail `info`.
pub async fn probe_license_tier(t: &Transport, flavor: Flavor) -> Option<String> {
    if flavor == Flavor::Serverless {
        return None;
    }
    let body = t.get_absolute_es("/_license").await.ok()?;
    body["license"]["type"].as_str().map(str::to_owned)
}
