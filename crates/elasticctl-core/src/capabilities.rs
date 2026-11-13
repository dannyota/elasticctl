use crate::error::{Error, ErrorKind, Result};
use crate::transport::Transport;
use semver::Version;
use serde_json::Value;

const ECH_SUFFIXES: [&str; 4] = [
    "elastic-cloud.com",
    "found.io",
    "cloud.es.io",
    "elastic.cloud",
];

const CLOUD_EDGE_HEADER: &str = "x-found-handling-cluster";

fn host_of(url: &str) -> &str {
    let after_scheme = match crate::config::scheme_anchor(url) {
        Some(pos) => &url[pos..],
        None => url,
    };
    after_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or("")
}

fn host_matches(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    SelfManaged,
    ElasticCloudHosted,
    Serverless,
}

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

    pub fn classify(status: &Value, cloud_edge: bool, kibana_url: &str) -> Capabilities {
        let version = status["version"]["number"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let build_flavor = status["version"]["build_flavor"]
            .as_str()
            .unwrap_or("default");

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

pub async fn probe_license_tier(t: &Transport, flavor: Flavor) -> Option<String> {
    if flavor == Flavor::Serverless {
        return None;
    }
    let body = t.get_absolute_es("/_license").await.ok()?;
    body["license"]["type"].as_str().map(str::to_owned)
}
