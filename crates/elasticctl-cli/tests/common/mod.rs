//! Helpers shared by the `elasticctl` integration tests.
//!
//! Each test file compiles this module into its own crate and uses a different
//! subset, so the unused `pub` items are expected.
#![allow(dead_code)]

use elasticctl_api_test_support::MockStack;
use std::fs;
use std::path::{Path, PathBuf};

/// Write a profile pointing at `uri` and return the config file's path.
///
/// Written owner-only (0600) so commands do not emit a `config_permissions`
/// warning whose message embeds this directory's path.
pub fn config_for(dir: &Path, uri: &str) -> PathBuf {
    let p = dir.join("config.toml");
    fs::write(
        &p,
        format!(
            "current = \"default\"\n\n[profiles.default]\nkibana_url = \"{uri}\"\napi_key = \"essu_t\"\nspace = \"default\"\nverify = true\ntimeout_secs = 5\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}

/// Write a profile pointing at `stack` and return the args that select it.
pub fn profile_args(dir: &Path, stack: &MockStack) -> Vec<String> {
    let cfg = config_for(dir, &stack.uri());
    vec!["--config".to_string(), cfg.to_string_lossy().into_owned()]
}
