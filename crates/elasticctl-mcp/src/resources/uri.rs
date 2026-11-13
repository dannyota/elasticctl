#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResourceRef {
    CoverageTactic,
    CoverageTechnique,
    Doctor,
    Info,
    PrebuiltRulesStatus,
    Alert {
        alert_id: String,
    },
    Case {
        case_id: String,
    },
    ExceptionList {
        namespace_type: String,
        list_id: String,
    },
    Rule {
        rule_id: String,
    },
}

pub(crate) const MAX_URI_BYTES: usize = 4_096;

pub(crate) fn parse(uri: &str) -> Option<ResourceRef> {
    if uri.len() > MAX_URI_BYTES || uri.contains(['?', '#', '@']) {
        return None;
    }
    let path = uri.strip_prefix("elasticctl://stack/")?;
    let segments = path.split('/').map(decode).collect::<Option<Vec<_>>>()?;
    let parts = segments.iter().map(String::as_str).collect::<Vec<_>>();
    Some(match parts.as_slice() {
        ["coverage", "tactic"] => ResourceRef::CoverageTactic,
        ["coverage", "technique"] => ResourceRef::CoverageTechnique,
        ["doctor"] => ResourceRef::Doctor,
        ["info"] => ResourceRef::Info,
        ["prebuilt-rules", "status"] => ResourceRef::PrebuiltRulesStatus,
        ["alerts", id] => ResourceRef::Alert {
            alert_id: (*id).into(),
        },
        ["cases", id] => ResourceRef::Case {
            case_id: (*id).into(),
        },
        ["exception-lists", namespace @ ("single" | "agnostic"), id] => {
            ResourceRef::ExceptionList {
                namespace_type: (*namespace).into(),
                list_id: (*id).into(),
            }
        }
        ["rules", id] => ResourceRef::Rule {
            rule_id: (*id).into(),
        },
        _ => return None,
    })
}

fn decode(segment: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            hex(bytes.next()?)? * 16 + hex(bytes.next()?)?
        } else {
            byte
        });
    }
    let decoded = String::from_utf8(decoded).ok()?;
    if decoded.is_empty()
        || decoded.len() > 1_024
        || decoded.trim().is_empty()
        || decoded.chars().any(|ch| ch <= '\u{1f}' || ch == '\u{7f}')
        || matches!(decoded.as_str(), "." | "..")
    {
        return None;
    }
    Some(decoded)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_nine_shapes() {
        for (path, expected) in [
            ("coverage/tactic", ResourceRef::CoverageTactic),
            ("coverage/technique", ResourceRef::CoverageTechnique),
            ("doctor", ResourceRef::Doctor),
            ("info", ResourceRef::Info),
            ("prebuilt-rules/status", ResourceRef::PrebuiltRulesStatus),
            (
                "alerts/a",
                ResourceRef::Alert {
                    alert_id: "a".into(),
                },
            ),
            (
                "cases/c",
                ResourceRef::Case {
                    case_id: "c".into(),
                },
            ),
            (
                "exception-lists/single/l",
                ResourceRef::ExceptionList {
                    namespace_type: "single".into(),
                    list_id: "l".into(),
                },
            ),
            (
                "rules/r",
                ResourceRef::Rule {
                    rule_id: "r".into(),
                },
            ),
        ] {
            assert_eq!(
                parse(&format!("elasticctl://stack/{path}")),
                Some(expected),
                "{path}"
            );
        }
        assert_eq!(
            parse("elasticctl://stack/exception-lists/agnostic/l"),
            Some(ResourceRef::ExceptionList {
                namespace_type: "agnostic".into(),
                list_id: "l".into()
            })
        );
    }

    #[test]
    fn decodes_once_without_normalizing_identifiers() {
        for (encoded, decoded) in [
            ("a%2Fb", "a/b"),
            ("a%2fb", "a/b"),
            ("a%20b", "a b"),
            ("%E6%97%A5", "日"),
            ("%25", "%"),
            ("%252F", "%2F"),
            ("%20A%20", " A "),
            ("a+b", "a+b"),
            ("%3F%23%40", "?#@"),
            ("%2E%2E%2Fx", "../x"),
        ] {
            let reference = ResourceRef::Rule {
                rule_id: decoded.into(),
            };
            assert_eq!(
                parse(&format!("elasticctl://stack/rules/{encoded}")),
                Some(reference.clone())
            );
            let round_trip = decoded
                .as_bytes()
                .iter()
                .map(|byte| format!("%{byte:02X}"))
                .collect::<String>();
            assert_eq!(
                parse(&format!("elasticctl://stack/rules/{round_trip}")),
                Some(reference)
            );
        }
        assert_eq!(parse("elasticctl://stack/%69nfo"), Some(ResourceRef::Info));
    }

    #[test]
    fn rejects_invalid_uri_grammar() {
        for uri in [
            "https://stack/info",
            "Elasticctl://stack/info",
            "elasticctl://STACK/info",
            "elasticctl://other/info",
            "elasticctl://plans/info",
            "elasticctl://stack:80/info",
            "elasticctl://user@stack/info",
            "elasticctl://stack/",
            "elasticctl://stack//info",
            "elasticctl://stack/info/",
            "elasticctl://stack/info?x",
            "elasticctl://stack/info#x",
            "elasticctl://stack/rules/a@b",
            "elasticctl://stack/rules/%zz",
            "elasticctl://stack/rules/%",
            "elasticctl://stack/rules/%2",
            "elasticctl://stack/rules/%FF",
            "elasticctl://stack/rules/ ",
            "elasticctl://stack/rules/%20",
            "elasticctl://stack/rules/%E3%80%80",
            "elasticctl://stack/rules/%00",
            "elasticctl://stack/rules/%1F",
            "elasticctl://stack/rules/%7F",
            "elasticctl://stack/rules/.",
            "elasticctl://stack/rules/..",
            "elasticctl://stack/rules/%2e%2E",
            "elasticctl://stack/rules/a/b",
            "elasticctl://stack/rules",
            "elasticctl://stack/coverage",
            "elasticctl://stack/exception-lists/shared/l",
            "elasticctl://stack/exception-lists/SINGLE/l",
            "elasticctl://stack/exception-lists/single",
            "elasticctl://stack/Info",
        ] {
            assert_eq!(parse(uri), None, "{uri:?}");
        }
        for control in (0_u8..=31).chain([127]) {
            assert_eq!(
                parse(&format!(
                    "elasticctl://stack/rules/a{}b",
                    char::from(control)
                )),
                None
            );
        }
    }

    #[test]
    fn enforces_decoded_byte_and_uri_limits() {
        for id in ["a".repeat(1024), "é".repeat(512)] {
            assert_eq!(
                parse(&format!("elasticctl://stack/rules/{id}")),
                Some(ResourceRef::Rule { rule_id: id })
            );
        }
        for id in ["a".repeat(1025), "é".repeat(513), "%61".repeat(1025)] {
            assert_eq!(parse(&format!("elasticctl://stack/rules/{id}")), None);
        }
        let prefix = "elasticctl://stack/exception-lists/single/";
        let id = format!(
            "{}{}",
            "%61".repeat(1024),
            "a".repeat(4097 - prefix.len() - 3072)
        );
        let uri = format!("{prefix}{id}");
        assert_eq!(uri.len(), 4097);
        assert_eq!(parse(&uri), None);
    }
}
