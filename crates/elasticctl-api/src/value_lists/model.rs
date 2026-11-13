use std::collections::BTreeSet;
use std::fmt;

use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ValueListType {
    Keyword,
    Ip,
    IpRange,
    Text,
    Unsupported(String),
}

impl From<String> for ValueListType {
    fn from(name: String) -> Self {
        match name.as_str() {
            "keyword" => Self::Keyword,
            "ip" => Self::Ip,
            "ip_range" => Self::IpRange,
            "text" => Self::Text,
            _ => Self::Unsupported(name),
        }
    }
}

impl From<ValueListType> for String {
    fn from(value: ValueListType) -> Self {
        value.to_string()
    }
}

impl fmt::Display for ValueListType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Keyword => "keyword",
            Self::Ip => "ip",
            Self::IpRange => "ip_range",
            Self::Text => "text",
            Self::Unsupported(name) => name,
        })
    }
}

impl ValueListType {
    pub fn require_supported(&self) -> Result<()> {
        if let Self::Unsupported(name) = self {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "unsupported value-list type {name:?}; supported types: keyword, ip, ip_range, text"
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    pub id: String,
    #[serde(rename = "type")]
    pub list_type: ValueListType,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Map<String, Value>>,
}

pub type ValueSet = BTreeSet<String>;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LocalPair {
    pub stem: String,
    pub container: Container,
    pub values: ValueSet,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct StoredValues {
    pub values: Vec<String>,
}

impl StoredValues {
    pub fn new(values: Vec<String>) -> Self {
        Self { values }
    }

    pub fn set(&self) -> ValueSet {
        self.values.iter().cloned().collect()
    }

    pub fn dash_count(&self) -> usize {
        self.values
            .iter()
            .filter(|value| value.contains('-'))
            .count()
    }
}
