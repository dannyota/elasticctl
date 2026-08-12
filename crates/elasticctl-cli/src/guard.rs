//! The dry-run contract. Nothing mutates a remote instance until the operator
//! has seen what would change and passed --yes.

use crate::context::Context;
use elasticctl_core::Resolved;

// Not yet built by any command — wired in as commands adopt the guard in
// later tasks. (Exercised directly by this module's tests in the meantime,
// so `#[allow]` rather than `#[expect]`: the lint only fires in a plain
// build, never in a test build.)
#[allow(dead_code)]
pub struct Preview {
    pub action: String,
    /// One line per affected object. Empty is allowed for actions that have
    /// nothing per-item to say.
    pub details: Vec<String>,
}

/// Parenthesised form of the core banner. The field text lives in
/// `Resolved::banner()` so there is exactly one place that decides how a
/// target is described — a guard preview and any other reporting path must
/// never show the operator two different descriptions of the same target.
#[allow(dead_code)]
pub fn banner(resolved: &Resolved) -> String {
    format!("({})", resolved.banner())
}

#[allow(dead_code)]
pub fn preview_text(preview: &Preview, resolved: &Resolved, applying: bool) -> String {
    let tag = banner(resolved);
    let mut out = if applying {
        format!("Applying: {} {tag}\n", preview.action)
    } else {
        format!("[DRY RUN] {} {tag}\n", preview.action)
    };
    for d in &preview.details {
        out.push_str("  ");
        out.push_str(d);
        out.push('\n');
    }
    if !applying {
        out.push_str("Pass --yes to apply.\n");
    }
    out
}

/// `true` means the caller should proceed with the mutation.
///
/// Writes to stderr, never stdout, so a dry-run preview never contaminates
/// piped JSON output.
#[expect(dead_code)]
pub fn check(ctx: &Context, preview: &Preview) -> bool {
    let applying = ctx.global.yes;
    eprint!("{}", preview_text(preview, &ctx.resolved, applying));
    applying
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_core::{Profile, Resolved, Source};

    fn resolved(name: &str, host: &str, space: &str) -> Resolved {
        Resolved {
            name: name.into(),
            source: Source::Profile,
            profile: Profile {
                kibana_url: format!("https://{host}"),
                es_url: None,
                api_key: Some("essu_secret".into()),
                username: None,
                password: None,
                space: space.into(),
                verify: true,
                timeout_secs: 30,
            },
        }
    }

    #[test]
    fn banner_names_profile_host_and_space() {
        let b = banner(&resolved("prod", "kibana.corp.internal", "soc"));
        assert!(b.contains("prod"), "{b}");
        assert!(b.contains("kibana.corp.internal"), "{b}");
        assert!(b.contains("soc"), "{b}");
    }

    #[test]
    fn banner_never_leaks_the_credential() {
        let b = banner(&resolved("prod", "kibana.corp.internal", "default"));
        assert!(
            !b.contains("essu_secret"),
            "the banner must not print the key: {b}"
        );
    }

    #[test]
    fn preview_text_lists_the_action_and_every_detail() {
        let p = Preview {
            action: "Disable 2 rules".into(),
            details: vec![
                "a  Alpha  enabled -> disabled".into(),
                "b  Beta  enabled -> disabled".into(),
            ],
        };
        let text = preview_text(&p, &resolved("uat", "uat.example.com", "default"), false);
        assert!(text.starts_with("[DRY RUN]"), "{text}");
        assert!(text.contains("Disable 2 rules"));
        assert!(text.contains("Alpha") && text.contains("Beta"));
        assert!(text.contains("Pass --yes to apply."));
    }

    #[test]
    fn apply_text_drops_the_dry_run_marker_and_the_hint() {
        let p = Preview {
            action: "Disable 2 rules".into(),
            details: vec![],
        };
        let text = preview_text(&p, &resolved("uat", "uat.example.com", "default"), true);
        assert!(text.starts_with("Applying:"), "{text}");
        assert!(
            !text.contains("--yes"),
            "the hint is pointless once applying: {text}"
        );
    }

    #[test]
    fn both_modes_carry_the_target_banner() {
        let p = Preview {
            action: "Delete 1 rule".into(),
            details: vec![],
        };
        let r = resolved("prod", "prod.example.com", "default");
        for applying in [false, true] {
            let text = preview_text(&p, &r, applying);
            assert!(
                text.contains("prod"),
                "target must be named in both modes: {text}"
            );
            assert!(text.contains("prod.example.com"), "{text}");
        }
    }
}
