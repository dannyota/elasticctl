//! Keep dry-run previews on stderr so piped JSON on stdout remains valid. This
//! source check rejects `print!`/`println!` outside the test module. The
//! end-to-end assertion in `rules_mutate.rs` also runs `rules disable` as a
//! dry run and checks both output streams.

use std::fs;
use std::path::Path;

#[test]
fn guard_module_writes_the_preview_to_stderr_only() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/guard.rs");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("expected to read {}: {e}", path.display()));

    assert!(
        text.contains("eprint!"),
        "{} must write the preview with eprint!: nothing found",
        path.display()
    );

    let production = match text.find("#[cfg(test)]") {
        Some(idx) => &text[..idx],
        None => panic!(
            "{} has no #[cfg(test)] module to exclude from the stdout scan",
            path.display()
        ),
    };
    // Remove stderr macros before scanning: their names contain the stdout
    // macro names as substrings.
    let scrubbed = production.replace("eprintln!(", "").replace("eprint!(", "");
    for needle in ["print!(", "println!("] {
        assert!(
            !scrubbed.contains(needle),
            "{} must not write to stdout (found {needle:?} outside #[cfg(test)]): \
             a dry-run preview on stdout would corrupt piped JSON output",
            path.display()
        );
    }
}
