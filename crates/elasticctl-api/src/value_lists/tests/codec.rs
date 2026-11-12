use super::super::*;
use elasticctl_core::ErrorKind;
use serde_json::json;

pub(super) const YAML: &str =
    "id: blocked\ntype: keyword\nname: Blocked\ndescription: Policy\nmeta:\n  owner: soc\n";

#[test]
fn container_round_trip_keeps_only_container_fields_and_object_meta() {
    let container = decode_container(YAML).unwrap();
    assert_eq!(container.id, "blocked");
    assert_eq!(container.list_type, ValueListType::Keyword);
    assert_eq!(container.meta.as_ref().unwrap()["owner"], json!("soc"));
    assert_eq!(
        decode_container(&encode_container(&container).unwrap()).unwrap(),
        container
    );
    let without = decode_container("id: x\ntype: long\nname: X\ndescription: ''\n").unwrap();
    assert_eq!(without.list_type, ValueListType::Unsupported("long".into()));
    assert!(!encode_container(&without).unwrap().contains("meta:"));
    for name in ["keyword", "text", "ip", "ip_range", "long"] {
        let kind = ValueListType::from(name.to_owned());
        assert_eq!(serde_json::to_value(&kind).unwrap(), json!(name));
        assert_eq!(
            serde_json::from_value::<ValueListType>(json!(name)).unwrap(),
            kind
        );
    }
}

#[test]
fn container_rejects_unknown_missing_and_wrongly_typed_keys() {
    for (yaml, key) in [
        (format!("{YAML}typo: x\n"), "typo"),
        (format!("{YAML}_version: x\n"), "_version"),
        (YAML.replace("id: blocked\n", ""), "id"),
        (YAML.replace("type: keyword\n", ""), "type"),
        (YAML.replace("name: Blocked\n", ""), "name"),
        (YAML.replace("description: Policy\n", ""), "description"),
        (YAML.replace("id: blocked", "id: 12"), "id"),
        (YAML.replace("type: keyword", "type: true"), "type"),
        (YAML.replace("name: Blocked", "name: []"), "name"),
        (
            YAML.replace("description: Policy", "description: null"),
            "description",
        ),
        (YAML.replace("meta:\n  owner: soc", "meta: []"), "meta"),
        (YAML.replace("meta:\n  owner: soc", "meta: null"), "meta"),
        (format!("{YAML}id: duplicate\n"), "id"),
    ] {
        let err = decode_container(&yaml).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Error);
        assert!(err.message.contains(key), "{err}");
    }
}

#[test]
fn parsing_normalizes_crlf_trims_edges_and_preserves_text() {
    let values = decode_values(&ValueListType::Keyword, " z \r\n\ta,b\t\r\nünïcode\nz\n").unwrap();
    assert_eq!(encode_values(&values), "a,b\nz\nünïcode\n");
    assert_eq!(
        encode_values(&decode_values(&ValueListType::Text, "two words").unwrap()),
        "two words\n"
    );
    assert!(decode_values(&ValueListType::Text, "").unwrap().is_empty());
}

#[test]
fn parsing_refuses_first_failing_step_with_line_and_value() {
    for (text, reason, value) in [
        ("valid\n \t\r\n", "empty", ""),
        ("valid\n\n", "empty", ""),
        ("valid\nbad\tvalue\n", "control", "bad"),
        ("valid\nbad\r\r\n", "control", "bad"),
        ("valid\n\u{85}\n", "control", ""),
    ] {
        let err = decode_values(&ValueListType::Keyword, text).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Error);
        assert!(err.message.contains("line 2"), "{err}");
        assert!(err.message.contains(reason), "{err}");
        assert!(err.message.contains(value), "{err}");
    }
    let err = decode_values(&ValueListType::Ip, "10.0.0.1\nnot-ip\n").unwrap_err();
    assert!(err.message.contains("line 2") && err.message.contains("not-ip"));
    assert!(decode_values(&ValueListType::Ip, " \t10.0.0.1\t \r\n").is_ok());
}

#[test]
fn readable_and_canonical_levels_cover_address_spellings() {
    for (kind, value, canonical) in [
        (ValueListType::Ip, "10.0.0.1", Some("10.0.0.1")),
        (ValueListType::Ip, "2001:DB8::1", Some("2001:db8::1")),
        (
            ValueListType::Ip,
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            Some("2001:db8::1"),
        ),
        (
            ValueListType::Ip,
            "2001:0:0:1:0:0:1:1",
            Some("2001::1:0:0:1:1"),
        ),
        (
            ValueListType::Ip,
            "2001:db8:0:1:1:1:1:1",
            Some("2001:db8:0:1:1:1:1:1"),
        ),
        (
            ValueListType::Ip,
            "::FFFF:192.0.2.1",
            Some("::ffff:192.0.2.1"),
        ),
        (ValueListType::IpRange, "10.0.0.7/24", Some("10.0.0.0/24")),
        (
            ValueListType::IpRange,
            "2001:DB8::7/32",
            Some("2001:db8::/32"),
        ),
        (
            ValueListType::IpRange,
            "10.0.0.1-10.0.0.9",
            Some("10.0.0.1-10.0.0.9"),
        ),
        (
            ValueListType::IpRange,
            "2001:DB8::1-2001:db8::2",
            Some("2001:db8::1-2001:db8::2"),
        ),
        (ValueListType::IpRange, "10.0.0.1-2001:db8::1", None),
        (
            ValueListType::IpRange,
            "10.0.0.5-10.0.0.5",
            Some("10.0.0.5-10.0.0.5"),
        ),
        (
            ValueListType::IpRange,
            "2001:DB8::1-2001:DB8::1",
            Some("2001:db8::1-2001:db8::1"),
        ),
        (ValueListType::IpRange, "0.0.0.0/0", Some("0.0.0.0/0")),
        (ValueListType::IpRange, "::/0", Some("::/0")),
        (ValueListType::IpRange, "10.0.0.5/32", Some("10.0.0.5/32")),
        (
            ValueListType::IpRange,
            "2001:db8::1/128",
            Some("2001:db8::1/128"),
        ),
    ] {
        let values = decode_values(&kind, &format!("{value}\n")).unwrap();
        assert!(values.contains(value));
        assert_eq!(
            canonical_value(&kind, value).unwrap().as_deref(),
            canonical,
            "{value}"
        );
        let yaml = YAML.replace("keyword", &kind.to_string());
        let local = validate_local_pair("blocked", yaml.as_bytes(), Some(value.as_bytes()));
        assert!(local.findings.refusals.is_empty(), "{value}");
        assert_eq!(
            local
                .findings
                .warnings
                .iter()
                .any(|warning| warning.kind == WarningKind::NonCanonical),
            canonical != Some(value),
            "{value}"
        );
        assert_eq!(
            !validate_additions(&kind, &values).refusals.is_empty(),
            canonical != Some(value),
            "{value}"
        );
    }
    for (kind, value) in [
        (ValueListType::Ip, "10.0.0.0/8"),
        (ValueListType::Ip, "not-an-ip"),
        (ValueListType::Ip, "10.0.0.1-10.0.0.2"),
        (ValueListType::IpRange, "10.0.0.9-10.0.0.1"),
        (ValueListType::IpRange, "2001:db8::2-2001:db8::1"),
        (ValueListType::IpRange, "10.0.0.0/33"),
        (ValueListType::IpRange, "::/129"),
        (ValueListType::IpRange, "10.0.0.0/-1"),
        (ValueListType::IpRange, "bad"),
    ] {
        assert!(decode_values(&kind, value).is_err(), "{value}");
    }
}

#[test]
fn mixed_family_ranges_check_order_in_ipv4_mapped_space() {
    let kind = ValueListType::IpRange;
    for value in [
        "10.0.0.1-2001:db8::1",
        "::1-10.0.0.1",
        "10.0.0.1-::ffff:10.0.0.1",
        "::ffff:10.0.0.1-10.0.0.1",
    ] {
        let values = decode_values(&kind, value).unwrap();
        assert!(values.contains(value));
        assert_eq!(canonical_value(&kind, value).unwrap(), None);
        let yaml = YAML.replace("keyword", "ip_range");
        let local = validate_local_pair("blocked", yaml.as_bytes(), Some(value.as_bytes()));
        assert!(local.findings.refusals.is_empty());
        assert!(
            local
                .findings
                .warnings
                .iter()
                .any(|warning| warning.kind == WarningKind::NonCanonical)
        );
        assert!(!validate_additions(&kind, &values).refusals.is_empty());
    }
    for value in [
        "2001:db8::1-10.0.0.1",
        "10.0.0.1-::1",
        "::ffff:10.0.0.2-10.0.0.1",
    ] {
        let error = decode_values(&kind, &format!("10.0.0.0/8\n{value}\n")).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Error);
        assert!(error.message.contains("line 2"), "{error}");
        assert!(error.message.contains(value), "{error}");
        assert!(error.message.contains("reversed IP range"), "{error}");
    }
}

#[test]
fn bare_range_addresses_rewrite_without_changing_spelling() {
    let values = decode_values(&ValueListType::IpRange, "10.0.0.5\n2001:DB8::1\n").unwrap();
    assert_eq!(encode_values(&values), "10.0.0.5/32\n2001:DB8::1/128\n");
}

#[test]
fn stored_views_keep_duplicates_and_exact_spellings() {
    let stored = StoredValues::new(vec![
        "2001:DB8::1".into(),
        "2001:db8::1".into(),
        "2001:DB8::1".into(),
    ]);
    assert_eq!(stored.values.len(), 3);
    assert_eq!(stored.set().len(), 2);
    let local = decode_values(&ValueListType::Ip, "2001:DB8::1\n2001:db8::1\n").unwrap();
    assert_eq!(stored.set(), local);
    assert_eq!(encode_values(&local), "2001:DB8::1\n2001:db8::1\n");
    let additions = local.difference(&stored.set()).cloned().collect();
    let removals = stored.set().difference(&local).cloned().collect();
    assert!(
        validate_additions(&ValueListType::Ip, &additions)
            .refusals
            .is_empty()
    );
    for order in [PhaseOrder::AddsFirst, PhaseOrder::RemovesFirst] {
        let states = project_states(&stored, &additions, &removals, order);
        for projected in [states.current, states.between, states.final_values] {
            assert_eq!(
                projected.values,
                ["2001:DB8::1", "2001:db8::1", "2001:DB8::1"]
            );
        }
    }
}
