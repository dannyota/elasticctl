use std::collections::BTreeMap;

use elasticctl_core::Result;

use super::{invalid, sha256};

pub(super) fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
        return Err(invalid(
            "value-list id must be non-empty, at most 512 UTF-8 bytes, and contain no control character",
        ));
    }
    Ok(())
}

/// A portable, bounded name carrying a hash whenever the id is not safe as-is.
pub fn file_stem(id: &str) -> String {
    let safe = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
        && !id.starts_with('.')
        && !id.ends_with('.')
        && !device_name(id);
    if safe {
        return id.to_owned();
    }
    // Same character mapping as state::safe_filename, without an extension.
    let mut prefix: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_lowercase();
    let mut end = prefix.len().min(48);
    while !prefix.is_char_boundary(end) {
        end -= 1;
    }
    prefix.truncate(end);
    let prefix = prefix.trim_end_matches('.');
    format!("{prefix}-{}", &sha256::hex(id.as_bytes())[..12])
}

fn device_name(id: &str) -> bool {
    let base = id
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(base.as_str(), "con" | "prn" | "aux" | "nul")
        || ((base.starts_with("com") || base.starts_with("lpt"))
            && base.len() == 4
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

/// Return every colliding pair of identities, comparing stems without case.
/// This also accepts names planned by the rule and exception writers.
pub fn stem_collisions<'a>(
    names: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<(String, String)> {
    let mut by_name: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut collisions = Vec::new();
    for (id, stem) in names {
        let previous = by_name.entry(stem.to_lowercase()).or_default();
        for other in previous.iter() {
            if *other != id {
                collisions.push(((*other).to_owned(), id.to_owned()));
            }
        }
        previous.push(id);
    }
    collisions
}

pub fn plan_stems<'a>(ids: impl IntoIterator<Item = &'a str>) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeMap::new();
    for id in ids {
        validate_id(id)?;
        names.insert(id.to_owned(), file_stem(id));
    }
    let collisions = stem_collisions(names.iter().map(|(id, stem)| (id.as_str(), stem.as_str())));
    if !collisions.is_empty() {
        let pairs: Vec<String> = collisions
            .iter()
            .map(|(a, b)| format!("{a:?} and {b:?}"))
            .collect();
        return Err(invalid(format!(
            "case-insensitive file stem collisions: {}",
            pairs.join("; ")
        )));
    }
    Ok(names)
}
