//! One probe at connect time, so commands can fail with a clear
//! "not available on this deployment" instead of a confusing 404.

use crate::error::{Error, ErrorKind, Result};
use crate::transport::Transport;

/// Hostname suffixes used by Elastic Cloud Hosted deployments.
const ECH_SUFFIXES: [&str; 4] = [
    "elastic-cloud.com",
    "found.io",
    "cloud.es.io",
    "elastic.cloud",
];

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
        let status = t.get("/api/status").await?;

        let version = status["version"]["number"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let build_flavor = status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default");

        let flavor = if build_flavor == "serverless" {
            Flavor::Serverless
        } else if ECH_SUFFIXES
            .iter()
            .any(|s| host_matches(host_of(kibana_url), s))
        {
            Flavor::ElasticCloudHosted
        } else {
            Flavor::SelfManaged
        };

        Ok(Capabilities { flavor, version })
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
