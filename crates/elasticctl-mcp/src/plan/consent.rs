use super::{MAX_CONSENT_TEXT_BYTES, PlanError};
use crate::TargetContext;

// Replace C0 except LF, DEL, C1, Unicode line and paragraph separators,
// and bidirectional embedding, override, pop, and isolate controls.
fn replaced(c: char) -> bool {
    matches!(c, '\0'..='\u{9}' | '\u{b}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
pub(crate) fn displays_exactly(text: &str) -> bool {
    !text.chars().any(replaced)
}
fn display(text: &str) -> String {
    text.chars()
        .map(|c| if replaced(c) { '�' } else { c })
        .collect::<String>()
        .replace('\n', "\n  | ")
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn render(
    target: &TargetContext,
    action: &str,
    details: &[String],
    note: Option<&str>,
    plan_id: &str,
    hash: &str,
    minutes: u64,
) -> String {
    let mut text = format!(
        "elasticctl asks to apply: {}\nTarget: profile {} @ {}, space {}\n",
        display(action),
        display(&target.profile),
        display(&target.host),
        display(&target.space)
    );
    for detail in details {
        text.push_str(&format!("  {}\n", display(detail)));
    }
    if let Some(note) = note {
        text.push_str(&format!("Note: {}\n", display(note)));
    }
    let short_hash: String = hash.chars().take(16).collect();
    text.push_str(&format!("Plan: {}\nHash: {}\nExpires in {minutes} min.\n\nSet \"Apply this change\" to true and accept to apply it.\nDecline, or leave it false, and nothing changes.",display(plan_id),display(&short_hash)));
    text
}
pub(crate) fn validate(text: &str) -> Result<(), PlanError> {
    if text.len() > MAX_CONSENT_TEXT_BYTES {
        Err(PlanError::TooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TargetContext;
    fn target() -> TargetContext {
        TargetContext {
            profile: "analyst".into(),
            host: "kibana.example.test".into(),
            space: "default".into(),
        }
    }
    #[test]
    fn exact_text() {
        assert_eq!(
            render(
                &target(),
                "Disable 2 rule(s)",
                &[
                    "r1  One  true -> false".into(),
                    "r2  Two  true -> false".into()
                ],
                Some("key note"),
                "pln_sample",
                "0123456789abcdefabcd",
                15
            ),
            "elasticctl asks to apply: Disable 2 rule(s)\nTarget: profile analyst @ kibana.example.test, space default\n  r1  One  true -> false\n  r2  Two  true -> false\nNote: key note\nPlan: pln_sample\nHash: 0123456789abcdef\nExpires in 15 min.\n\nSet \"Apply this change\" to true and accept to apply it.\nDecline, or leave it false, and nothing changes."
        );
        let text = render(&target(), "x", &[], None, "p", "h", 1);
        assert!(text.contains("Expires in 1 min."));
        assert!(!text.contains("Note:"));
    }
    #[test]
    fn first_three_lines_show_action_target_and_detail() {
        let text = render(
            &target(),
            "Disable 1 rule(s)",
            &["r1  One  true -> false".into()],
            Some("key note"),
            "pln_sample",
            "0123456789abcdef",
            15,
        );
        assert_eq!(
            text.lines().take(3).collect::<Vec<_>>(),
            [
                "elasticctl asks to apply: Disable 1 rule(s)",
                "Target: profile analyst @ kibana.example.test, space default",
                "  r1  One  true -> false",
            ]
        );
    }
    #[test]
    fn action_continuations_precede_target() {
        let text = render(
            &target(),
            "Disable 1 rule(s)\nFORGED\nTarget: forged",
            &[],
            None,
            "p",
            "h",
            15,
        );
        assert_eq!(
            text.lines().take(4).collect::<Vec<_>>(),
            [
                "elasticctl asks to apply: Disable 1 rule(s)",
                "  | FORGED",
                "  | Target: forged",
                "Target: profile analyst @ kibana.example.test, space default",
            ]
        );
    }
    #[test]
    fn replacement_and_continuations() {
        for c in ('\0'..='\u{9}')
            .chain('\u{b}'..='\u{1f}')
            .chain('\u{7f}'..='\u{9f}')
            .chain(['\u{2028}', '\u{2029}'])
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}')
        {
            assert!(!displays_exactly(&c.to_string()));
            assert_eq!(display(&c.to_string()), "�");
        }
        assert!(displays_exactly("a\nb"));
        let mut t = target();
        t.profile = "a\nFORGED".into();
        t.host = "b\nFORGED".into();
        t.space = "c\nFORGED".into();
        let text = render(
            &t,
            "x\nFORGED",
            &["y\nFORGED".into()],
            Some("z\nFORGED"),
            "p\nFORGED",
            "h\nFORGED",
            15,
        );
        assert!(!text.lines().any(|l| l.starts_with("FORGED")));
        assert!(text.contains("  y\n  | FORGED"));
    }
    #[test]
    fn finished_size() {
        let base = render(
            &target(),
            "",
            &["detail".into()],
            Some("note"),
            "p",
            "h",
            15,
        )
        .len();
        for (size, valid) in [(8192, true), (8193, false)] {
            let text = render(
                &target(),
                &"x".repeat(size - base),
                &["detail".into()],
                Some("note"),
                "p",
                "h",
                15,
            );
            assert_eq!(text.len(), size);
            assert_eq!(validate(&text).is_ok(), valid);
        }
    }
}
