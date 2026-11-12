use super::super::*;
use elasticctl_core::ErrorKind;

fn set(values: &[&str]) -> ValueSet {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn dash_values(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("10.0.0.{i}-10.0.0.{i}"))
        .collect()
}

#[test]
fn local_pair_checks_identity_stem_supported_type_encoding_and_presence() {
    let yaml = super::codec::YAML;
    let valid = validate_local_pair("blocked", yaml.as_bytes(), Some(b"value\n"));
    assert!(valid.findings.refusals.is_empty());
    assert!(valid.pair.is_some());
    for (stem, yaml, bytes, kind, message) in [
        (
            "wrong",
            yaml.to_owned(),
            Some(b"value".as_slice()),
            ErrorKind::Error,
            "stem",
        ),
        (
            "blocked",
            yaml.replace("id: blocked", "id: ''"),
            Some(b"value".as_slice()),
            ErrorKind::Error,
            "id",
        ),
        (
            "blocked",
            yaml.replace("id: blocked", &format!("id: {}", "x".repeat(513))),
            Some(b"value".as_slice()),
            ErrorKind::Error,
            "id",
        ),
        (
            "blocked",
            yaml.replace("id: blocked", "id: \"bad\\u0001\""),
            Some(b"value".as_slice()),
            ErrorKind::Error,
            "id",
        ),
        (
            "blocked",
            yaml.replace("type: keyword", "type: long"),
            Some(b"value".as_slice()),
            ErrorKind::Unsupported,
            "long",
        ),
        ("blocked", yaml.to_owned(), None, ErrorKind::Error, "values"),
        (
            "blocked",
            yaml.to_owned(),
            Some(b"\xff".as_slice()),
            ErrorKind::Error,
            "UTF-8",
        ),
        (
            "blocked",
            yaml.to_owned(),
            Some(b"\n".as_slice()),
            ErrorKind::Error,
            "line 1",
        ),
    ] {
        let result = validate_local_pair(stem, yaml.as_bytes(), bytes);
        assert!(result.pair.is_none());
        assert!(
            result
                .findings
                .refusals
                .iter()
                .any(|error| error.kind == kind && error.message.contains(message)),
            "{:?}",
            result.findings
        );
    }
    let result = validate_local_pair("blocked", b"\xff", Some(b"x"));
    assert!(result.findings.refusals[0].message.contains("UTF-8"));
    let id = "x".repeat(512);
    let yaml = yaml.replace("id: blocked", &format!("id: {id}"));
    assert!(
        validate_local_pair(&file_stem(&id), yaml.as_bytes(), Some(b"x"))
            .findings
            .refusals
            .is_empty()
    );
}

#[test]
fn local_reader_accepts_either_half_and_refuses_missing_or_non_regular_files() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("blocked.yaml");
    let txt = dir.path().join("blocked.txt");
    std::fs::write(&yaml, super::codec::YAML).unwrap();
    assert!(read_pair(&yaml).is_err());
    std::fs::write(&txt, " z\r\na\n").unwrap();
    let pair = read_pair(&txt).unwrap();
    assert_eq!(pair, read_pair(&yaml).unwrap());
    assert_eq!(encode_values(&pair.values), "a\nz\n");
    std::fs::remove_file(&txt).unwrap();
    std::fs::create_dir(&txt).unwrap();
    assert!(read_pair(&yaml).is_err());
    assert!(read_pair(&dir.path().join("blocked.json")).is_err());
}

#[test]
fn noncanonical_stored_values_round_trip_but_new_additions_are_refused() {
    for (kind, values) in [
        ("ip", "2001:DB8::1\n2001:db8::1\n"),
        (
            "ip_range",
            "10.0.0.7/24\n10.0.0.1-2001:db8::1\n2001:DB8::1-2001:DB8::1\n",
        ),
    ] {
        let yaml = super::codec::YAML.replace("keyword", kind);
        let result = validate_local_pair("blocked", yaml.as_bytes(), Some(values.as_bytes()));
        assert!(result.findings.refusals.is_empty());
        assert!(!result.findings.warnings.is_empty());
        let pair = result.pair.unwrap();
        let stored = StoredValues::new(pair.values.iter().cloned().collect());
        let additions: ValueSet = pair.values.difference(&stored.set()).cloned().collect();
        assert!(
            validate_additions(&pair.container.list_type, &additions)
                .refusals
                .is_empty()
        );
        let findings = validate_additions(&pair.container.list_type, &pair.values);
        assert!(!findings.refusals.is_empty());
        assert!(
            findings
                .refusals
                .iter()
                .all(|err| err.kind == ErrorKind::Error)
        );
        if kind == "ip" {
            assert!(findings.refusals[0].message.contains("2001:db8::1"));
        } else {
            assert!(
                findings
                    .refusals
                    .iter()
                    .any(|e| e.message.contains("10.0.0.0/24"))
            );
        }
    }
}

#[test]
fn one_value_must_fit_the_import_bound_with_its_lf() {
    for (length, refused) in [(7_999_999, false), (8_000_000, true)] {
        let value = "x".repeat(length);
        let result = validate_local_pair(
            "blocked",
            super::codec::YAML.as_bytes(),
            Some(value.as_bytes()),
        );
        assert_eq!(!result.findings.refusals.is_empty(), refused);
    }
}

#[test]
fn projection_keeps_copies_removes_all_copies_and_adds_once_in_either_order() {
    let current = StoredValues::new(vec!["a".into(), "a".into(), "b".into()]);
    let adds = set(&["c"]);
    let removes = set(&["b"]);
    let add_first = project_states(&current, &adds, &removes, PhaseOrder::AddsFirst);
    assert_eq!(add_first.between.values, ["a", "a", "b", "c"]);
    assert_eq!(add_first.final_values.values, ["a", "a", "c"]);
    let remove_first = project_states(&current, &adds, &removes, PhaseOrder::RemovesFirst);
    assert_eq!(remove_first.between.values, ["a", "a"]);
    assert_eq!(remove_first.final_values.values, ["a", "a", "c"]);
    for (adds, removes, expected) in [
        (ValueSet::new(), set(&["a"]), set(&["b"])),
        (set(&["c"]), ValueSet::new(), set(&["a", "b", "c"])),
        (ValueSet::new(), ValueSet::new(), set(&["a", "b"])),
    ] {
        assert_eq!(
            project_states(&current, &adds, &removes, PhaseOrder::AddsFirst)
                .final_values
                .set(),
            expected
        );
    }
}

#[test]
fn dash_rule_counts_stored_items_at_200_and_201_and_allows_repairs() {
    for (count, refused) in [(200, false), (201, true)] {
        let stored = StoredValues::new(dash_values(count));
        let states = project_states(
            &stored,
            &ValueSet::new(),
            &ValueSet::new(),
            PhaseOrder::AddsFirst,
        );
        let findings =
            validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default());
        assert_eq!(!findings.refusals.is_empty(), refused);
        assert_eq!(
            !stored_warnings(&ValueListType::IpRange, &stored).is_empty(),
            refused
        );
    }
    let mut values = dash_values(199);
    values.push(values[0].clone());
    let stored = StoredValues::new(values);
    let additions: ValueSet = dash_values(201).into_iter().skip(199).collect();
    let removals = set(&["10.0.0.1-10.0.0.1"]);
    for order in [PhaseOrder::AddsFirst, PhaseOrder::RemovesFirst] {
        let states = project_states(&stored, &additions, &removals, order);
        assert_eq!(states.final_values.dash_count(), 201);
        let findings =
            validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default());
        assert!(
            findings
                .refusals
                .iter()
                .any(|e| e.kind == ErrorKind::Unsupported)
        );
    }
    let stored = StoredValues::new(dash_values(201));
    let removals = set(&["10.0.0.0-10.0.0.0"]);
    let repair = project_states(&stored, &ValueSet::new(), &removals, PhaseOrder::AddsFirst);
    assert_eq!(repair.between.dash_count(), 201);
    assert_eq!(repair.final_values.dash_count(), 200);
    assert!(
        validate_projected(&ValueListType::IpRange, &repair, &ReferenceUse::default())
            .refusals
            .is_empty()
    );
    let mut mixed = dash_values(150);
    mixed.extend((0..100).map(|i| format!("10.0.1.{i}/32")));
    assert_eq!(StoredValues::new(mixed).dash_count(), 150);
}

#[test]
fn between_phase_dash_overflow_is_refused_even_with_safe_final_state() {
    let stored = StoredValues::new(dash_values(200));
    let adds = set(&["10.0.1.0-10.0.1.0"]);
    let removes = set(&["10.0.0.0-10.0.0.0"]);
    let states = project_states(&stored, &adds, &removes, PhaseOrder::AddsFirst);
    assert_eq!(states.between.dash_count(), 201);
    assert_eq!(states.final_values.dash_count(), 200);
    let findings = validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default());
    let err = &findings.refusals[0];
    assert_eq!(err.kind, ErrorKind::Unsupported);
    for text in [
        "9.5.1",
        "9.5.6",
        "9.7.0",
        "either operator",
        "/32",
        "/128",
        "CIDR",
    ] {
        assert!(err.message.contains(text), "{err}");
    }
    let states = project_states(&stored, &adds, &removes, PhaseOrder::RemovesFirst);
    assert!(
        validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default())
            .refusals
            .is_empty()
    );
}

#[test]
fn empty_rule_checks_final_between_and_creation_with_named_references() {
    let stored = StoredValues::new(vec!["a".into()]);
    for kind in [
        ValueListType::Keyword,
        ValueListType::Text,
        ValueListType::Ip,
        ValueListType::IpRange,
    ] {
        for references in [
            ReferenceUse {
                installed: vec!["container/item/source.ip".into()],
                ..Default::default()
            },
            ReferenceUse {
                desired: vec!["container/item/source.ip".into()],
                ..Default::default()
            },
        ] {
            let final_empty = project_states(
                &stored,
                &ValueSet::new(),
                &set(&["a"]),
                PhaseOrder::AddsFirst,
            );
            let between_empty = project_states(
                &stored,
                &set(&["b"]),
                &set(&["a"]),
                PhaseOrder::RemovesFirst,
            );
            for states in [final_empty, between_empty] {
                let findings = validate_projected(&kind, &states, &references);
                assert!(
                    findings
                        .refusals
                        .iter()
                        .any(|err| err.kind == ErrorKind::Unsupported
                            && err.message.contains("container/item/source.ip")
                            && err.message.contains("suppresses every event"))
                );
            }
            let safe = project_states(&stored, &set(&["b"]), &set(&["a"]), PhaseOrder::AddsFirst);
            assert!(
                validate_projected(&kind, &safe, &references)
                    .refusals
                    .is_empty()
            );
        }
    }
    let states = project_states(
        &StoredValues::default(),
        &set(&["a"]),
        &ValueSet::new(),
        PhaseOrder::AddsFirst,
    );
    let references = ReferenceUse {
        creating: true,
        installed: vec!["installed".into()],
        desired: vec![],
    };
    assert!(
        !validate_projected(&ValueListType::Keyword, &states, &references)
            .refusals
            .is_empty()
    );
    let references = ReferenceUse {
        creating: true,
        installed: vec![],
        desired: vec!["desired".into()],
    };
    assert!(
        validate_projected(&ValueListType::Keyword, &states, &references)
            .refusals
            .is_empty()
    );
    let empty = project_states(
        &StoredValues::default(),
        &ValueSet::new(),
        &ValueSet::new(),
        PhaseOrder::AddsFirst,
    );
    assert!(
        validate_projected(&ValueListType::Keyword, &empty, &ReferenceUse::default())
            .refusals
            .is_empty()
    );
}

#[test]
fn size_warnings_cover_each_type_at_the_documented_boundary() {
    for kind in [
        ValueListType::Keyword,
        ValueListType::Ip,
        ValueListType::IpRange,
    ] {
        for (count, warns) in [(65_535, false), (65_536, true)] {
            let values: Vec<String> = (0..count)
                .map(|i| match kind {
                    ValueListType::IpRange => {
                        format!("10.{}.{}.{}/32", i / 65536, (i / 256) % 256, i % 256)
                    }
                    _ => format!("10.{}.{}.{ep}", i / 65536, (i / 256) % 256, ep = i % 256),
                })
                .collect();
            assert_eq!(
                size_warning(&kind, values.iter().map(String::as_str)).is_some(),
                warns
            );
        }
    }
    assert!(size_warning(&ValueListType::Text, std::iter::empty()).is_some());
    assert!(size_warning(&ValueListType::Text, ["one"]).is_some());
    assert!(
        size_warning(
            &ValueListType::IpRange,
            std::iter::repeat_n("10.0.0.1-10.0.0.1", 65_536)
        )
        .is_none()
    );
    let warnings = stored_warnings(
        &ValueListType::Keyword,
        &StoredValues::new(vec!["a".into(), "a".into()]),
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.kind == WarningKind::Duplicates)
    );
    let stored = StoredValues::new(vec!["same".into(); 65_536]);
    assert!(
        stored_warnings(&ValueListType::Keyword, &stored)
            .iter()
            .any(|warning| warning.kind == WarningKind::RuleTypeLimit)
    );
}

#[test]
fn additions_refuse_unparsed_empty_control_and_untrimmed_values() {
    for value in ["", " ", "bad\tvalue", "two\nlines", " padded "] {
        assert!(
            !validate_additions(&ValueListType::Keyword, &set(&[value]))
                .refusals
                .is_empty(),
            "{value:?}"
        );
    }
    assert_eq!(
        canonical_value(&ValueListType::Keyword, " padded ").unwrap(),
        Some("padded".into())
    );
}

#[test]
fn local_pair_uses_utf8_bytes_for_ids_and_value_limits() {
    for (id, valid) in [("é".repeat(256), true), ("é".repeat(257), false)] {
        let yaml = super::codec::YAML.replace("id: blocked", &format!("id: {id}"));
        assert_eq!(
            validate_local_pair(&file_stem(&id), yaml.as_bytes(), Some(b"x"))
                .pair
                .is_some(),
            valid
        );
    }
    for (value, valid) in [
        (format!("{}x", "é".repeat(3_999_999)), true),
        ("é".repeat(4_000_000), false),
    ] {
        assert_eq!(
            validate_local_pair(
                "blocked",
                super::codec::YAML.as_bytes(),
                Some(value.as_bytes())
            )
            .pair
            .is_some(),
            valid
        );
    }
}

#[test]
fn duplicate_dash_boundary_and_repairs_still_above_200_refuse() {
    let mut values = dash_values(200);
    values.push(values[0].clone());
    let stored = StoredValues::new(values);
    assert_eq!(stored.set().len(), 200);
    let states = project_states(
        &stored,
        &ValueSet::new(),
        &ValueSet::new(),
        PhaseOrder::AddsFirst,
    );
    assert!(
        !validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default())
            .refusals
            .is_empty()
    );
    let stored = StoredValues::new(dash_values(202));
    let states = project_states(
        &stored,
        &ValueSet::new(),
        &set(&["10.0.0.0-10.0.0.0"]),
        PhaseOrder::RemovesFirst,
    );
    assert_eq!(states.final_values.dash_count(), 201);
    assert!(
        !validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default())
            .refusals
            .is_empty()
    );
    let states = project_states(
        &StoredValues::new(dash_values(201)),
        &set(&["10.0.1.0-10.0.1.0"]),
        &set(&["10.0.0.0-10.0.0.0", "10.0.0.1-10.0.0.1"]),
        PhaseOrder::AddsFirst,
    );
    assert_eq!(states.final_values.dash_count(), 200);
    assert_eq!(states.between.dash_count(), 202);
    assert!(
        !validate_projected(&ValueListType::IpRange, &states, &ReferenceUse::default())
            .refusals
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn reader_refuses_symlinked_files_and_pair_directory() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("blocked.yaml"), super::codec::YAML).unwrap();
    std::fs::write(real.join("blocked.txt"), "value\n").unwrap();
    let linked = dir.path().join("linked");
    symlink(&real, &linked).unwrap();
    assert!(read_pair(&linked.join("blocked.yaml")).is_err());
    symlink(real.join("blocked.txt"), dir.path().join("blocked.txt")).unwrap();
    std::fs::write(dir.path().join("blocked.yaml"), super::codec::YAML).unwrap();
    assert!(read_pair(&dir.path().join("blocked.yaml")).is_err());
}
