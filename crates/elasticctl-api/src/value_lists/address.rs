use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use elasticctl_core::Result;

use super::{ValueListType, invalid};

/// Return the canonical spelling of a readable, parsed value.
///
/// A mixed-family range is readable but has no single canonical spelling,
/// so it returns `None`. This function never rewrites a stored value.
pub fn canonical_value(kind: &ValueListType, value: &str) -> Result<Option<String>> {
    kind.require_supported()?;
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() {
        return Err(invalid("empty value"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!("control character in value {value:?}")));
    }
    match kind {
        ValueListType::Keyword | ValueListType::Text => Ok(Some(value.to_owned())),
        ValueListType::Ip => Ok(Some(address(value)?.to_string())),
        ValueListType::IpRange => range(value),
        ValueListType::Unsupported(_) => unreachable!(),
    }
}

fn address(value: &str) -> Result<IpAddr> {
    value
        .parse()
        .map_err(|_| invalid(format!("invalid IP address {value:?}")))
}

fn range(value: &str) -> Result<Option<String>> {
    if let Some((start, end)) = value.split_once('-') {
        let (start, end) = (address(start)?, address(end)?);
        if start.is_ipv4() != end.is_ipv4() {
            return Ok(None);
        }
        if start > end {
            return Err(invalid(format!("reversed IP range {value:?}")));
        }
        return Ok(Some(format!("{start}-{end}")));
    }
    if let Some((ip, prefix)) = value.split_once('/') {
        let ip = address(ip)?;
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        let prefix: u32 = prefix
            .parse()
            .ok()
            .filter(|length| *length <= bits)
            .filter(|_| !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| invalid(format!("invalid CIDR prefix in {value:?}")))?;
        let network = match ip {
            IpAddr::V4(ip) => {
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
            }
            IpAddr::V6(ip) => {
                let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
            }
        };
        return Ok(Some(format!("{network}/{prefix}")));
    }
    let ip = address(value)?;
    Ok(Some(format!(
        "{ip}/{}",
        if ip.is_ipv4() { 32 } else { 128 }
    )))
}

pub(super) fn rewrite_bare_range(kind: &ValueListType, value: &str) -> String {
    if *kind == ValueListType::IpRange
        && let Ok(ip) = value.parse::<IpAddr>()
    {
        return format!("{value}/{}", if ip.is_ipv4() { 32 } else { 128 });
    }
    value.to_owned()
}
