//! Tripwire for the guard's highest-stakes contract: a dry-run preview must
//! land on stderr, never stdout, or it corrupts piped JSON output on every
//! dry run. `Context::build` needs a config file to exercise `guard::check`
//! end-to-end, which makes a unit test awkward — this reads the module's own
//! source instead and fails if the preview ever reaches for `print!`/
//! `println!` outside its test module.
//!
//! This is an interim guard. A real end-to-end assertion on stdout-versus-
//! stderr becomes possible once the first mutating command wires `check`
//! into a live run (Task 14).

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
    // `eprintln!(`/`eprint!(` textually contain `println!(`/`print!(` as a
    // substring (the leading `e` aside), so the legitimate stderr calls must
    // be scrubbed out before scanning for a stray stdout write.
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
