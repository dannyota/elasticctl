//! The dry-run contract. Nothing mutates a remote instance until the operator
//! has seen what would change and passed --yes.

use crate::context::Context;
use elasticctl_core::Resolved;

/// Commands that mutate: remote for the `rules`/`state` mutations, the local
/// config file for `config init`. Keyed on the full command path
/// (`rules delete`, `state push`, ...), never the bare leaf name, so a future
/// non-mutating `delete` or `import` under another group is not silently
/// mislabeled.
///
/// It lives here, next to the code that enforces it, rather than in the module
/// that renders it. `cmd::meta` reads it to populate `mutates` in the command
/// tree — one definition, because a second copy is one nothing checks.
///
/// Two independent contracts keep this list honest:
/// - `check` asserts its caller is declared here, so a remote mutation that
///   goes through the guard but was never declared fails its own tests rather
///   than shipping `mutates: false`.
/// - the exhaustive tree test in `cmd::meta` pins the declared set, so the
///   list cannot silently grow.
///
/// What is *not* detected: a mutating command that neither calls the guard
/// nor is declared here. `config init` is the one declared mutator that does
/// not call the guard — it writes a local file, not the stack — so
/// `guard ⊆ MUTATING` is the direction enforced: under-declaration, not
/// over-declaration.
pub(crate) const MUTATING: [&str; 6] = [
    "rules enable",
    "rules disable",
    "rules delete",
    "rules import",
    "state push",
    "config init",
];

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

/// `true` means the caller should proceed with the mutation.
///
/// Writes to stderr, never stdout, so a dry-run preview never contaminates
/// piped JSON output.
///
/// Every remote mutation reaches the stack through here, so this is the one
/// place that can enforce `guard ⊆ MUTATING`: a caller whose command path is
/// not declared in `MUTATING` is an undeclared mutation, and fails loudly
/// rather than shipping `mutates: false` in the command tree. `path` is the
/// full command path exactly as `MUTATING` declares it (`"rules delete"`,
/// `"state push"`, ...) — a string that only approximates it would make the
/// assertion a lie.
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

    /// The guard must refuse to run for a command path it has not been told
    /// is mutating: that is exactly the undeclared mutation that would
    /// otherwise ship `mutates: false` in the command tree. A real `Context`
    /// is built from a scratch config so the assertion is exercised through
    /// `check`, not just the constant it reads.
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
