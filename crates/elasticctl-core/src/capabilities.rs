//! Probe deployment capabilities at connection time.
//!
//! Commands can then report unsupported features before a 404 response.

use crate::error::{Error, ErrorKind, Result};
use crate::transport::Transport;
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
    let after_scheme = match url.rfind("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let host = after_scheme.split('/').next().unwrap_or("");
    host.split(':').next().unwrap_or(host)
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
