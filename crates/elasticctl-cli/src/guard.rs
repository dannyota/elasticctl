//! Dry-run contract. Remote mutations require a preview and `--yes`.

use crate::context::Context;
use elasticctl_core::Resolved;

/// Mutating commands: remote `rules`, `exceptions`, `state`, `alerts`, and
/// `cases` commands, plus local `config init`. Use full command paths so a
/// non-mutating command with the same leaf name cannot be mislabeled.
///
/// Keep this list with its enforcement. `cmd::meta` reads it for the command
/// tree, avoiding an unchecked duplicate.
///
/// Two contracts verify the list:
///
/// - `check` rejects guarded remote mutations that are not declared here.
/// - `cmd::meta` pins the declared command-tree paths.
///
/// This does not detect mutations that neither call the guard nor appear here.
/// `config init` is declared but unguarded because it writes a local file.
/// The enforced relation is `guard ⊆ MUTATING`.
pub(crate) const MUTATING: [&str; 20] = [
    "rules enable",
    "rules disable",
    "rules delete",
    "rules import",
    "rules prebuilt install",
    "exceptions delete",
    "exceptions import",
    "state push",
    "config init",
    "alerts ack",
    "alerts open",
    "alerts close",
    "alerts tag",
    "alerts assign",
    "cases create",
    "cases close",
    "cases open",
    "cases delete",
    "cases attach",
    "cases comment",
];

pub struct Preview {
    pub action: String,
    /// One line per affected object. Empty when no per-object detail applies.
    pub details: Vec<String>,
}

/// Parenthesized `Resolved::banner()` text. Use one target description in
/// previews and other output.
pub fn banner(resolved: &Resolved) -> String {
    format!("({})", resolved.banner())
}

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

/// Return `true` when the caller should perform the mutation.
///
/// Write to stderr so a dry-run preview does not contaminate piped JSON.
///
/// Every guarded remote mutation reaches the stack here. Reject a path absent
/// from `MUTATING` so the command tree cannot report it as non-mutating.
/// `path` must exactly match a full path in `MUTATING`.
pub fn check(ctx: &Context, path: &'static str, preview: &Preview) -> bool {
    assert!(
        MUTATING.contains(&path),
        "guard::check called from \"{path}\", which is not in MUTATING — \
         a mutating command must be declared there or it ships mutates:false \
         in the command tree"
    );
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

    /// Reject undeclared guarded mutations so the command tree cannot mark
    /// them as non-mutating. Build a real context to exercise `check`.
    #[test]
    #[should_panic(expected = "rules touch")]
    fn check_rejects_an_undeclared_mutating_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "current = \"test\"\n\n\
             [profiles.test]\n\
             kibana_url = \"https://kb.example.com\"\n\
             space = \"default\"\n\
             verify = true\n\
             timeout_secs = 30\n",
        )
        .unwrap();
        let global = crate::cli::GlobalArgs {
            config: Some(config),
            ..Default::default()
        };
        let ctx = crate::context::Context::build(&global).unwrap();
        let preview = Preview {
            action: "Touch 1 rule".into(),
            details: vec![],
        };
        let _ = check(&ctx, "rules touch", &preview);
    }
}
