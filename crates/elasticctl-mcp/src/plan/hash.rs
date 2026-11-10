use elasticctl_api::health::CredentialIdentity;
use elasticctl_core::{Error, ErrorKind, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                Value::Object(
                    keys.into_iter()
                        .map(|k| (k.clone(), sorted(&map[k])))
                        .collect(),
                )
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).expect("JSON values serialize")
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn new_plan_id() -> Result<String> {
    random_id("pln_")
}
#[allow(dead_code)]
pub(crate) fn new_handle() -> Result<String> {
    random_id("cfm_")
}
fn random_id(prefix: &str) -> Result<String> {
    random_id_with(prefix, getrandom::fill)
}
fn random_id_with(
    prefix: &str,
    fill: impl FnOnce(&mut [u8]) -> std::result::Result<(), getrandom::Error>,
) -> Result<String> {
    let mut bytes = [0; 16];
    fill(&mut bytes).map_err(|_| Error::new(ErrorKind::Error, "OS randomness is unavailable."))?;
    Ok(format!("{prefix}{}", hex(&bytes)))
}
#[allow(dead_code)]
pub(crate) fn credential_hash(identity: &CredentialIdentity) -> String {
    sha256_hex(
        format!(
            "v1\n{}\n{}\n{}",
            identity.realm_type,
            identity.username,
            identity.api_key_id.as_deref().unwrap_or("")
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_api::health::CredentialIdentity;
    #[test]
    fn exact_vectors() {
        let v = serde_json::json!({"b":1,"a":{"d":[2,{"z":0,"y":1}],"c":null}});
        assert_eq!(
            canonical_bytes(&v),
            br#"{"a":{"c":null,"d":[2,{"y":1,"z":0}]},"b":1}"#
        );
        assert_eq!(
            sha256_hex(&canonical_bytes(&v)),
            "1a41b906999ec1a8d96163a96fa166a39549c77cde50e413db0b5421612300a1"
        );
        let id = CredentialIdentity {
            realm_type: "_es_api_key".into(),
            username: "sample-user".into(),
            api_key_id: Some("sample-key-id".into()),
        };
        assert_eq!(
            credential_hash(&id),
            "712a8b246cbd4c9cf183a6d60bbf758ac028d7236f9b7f21a92cd61bd3edb5cb"
        );
        let id = CredentialIdentity {
            api_key_id: None,
            ..id
        };
        assert_eq!(
            credential_hash(&id),
            sha256_hex(b"v1\n_es_api_key\nsample-user\n")
        );
    }
    #[test]
    fn random_ids() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            for (prefix, id) in [
                ("pln_", new_plan_id().unwrap()),
                ("cfm_", new_handle().unwrap()),
            ] {
                assert!(id.starts_with(prefix));
                assert_eq!(id.len(), 36);
                assert!(
                    id[4..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                );
                assert!(seen.insert(id));
            }
        }
    }
}

#[cfg(test)]
mod failure_tests {
    #[test]
    fn randomness_failure_is_an_error() {
        let error =
            super::random_id_with("pln_", |_| Err(getrandom::Error::UNSUPPORTED)).unwrap_err();
        assert_eq!(error.message, "OS randomness is unavailable.");
    }
}
