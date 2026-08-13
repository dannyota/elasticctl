//! Output must not depend on whether stdout is a terminal. A pipe must receive
//! the same bytes as a terminal. `assert_cmd` always pipes stdout, so an
//! end-to-end test cannot exercise interactive-only code; a TTY regression
//! could leave the other tests green. Scan the crate source and fail on
//! terminal checks.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_detects_a_terminal() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find source files under {}",
        src.display()
    );

    let banned = ["is_terminal", "atty", "IsTty"];
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        for needle in banned {
            assert!(
                !text.contains(needle),
                "{} must not detect a TTY (found {needle:?}): the same command must \
                 behave identically in a terminal and in a pipe",
                path.display()
            );
        }
    }
}
