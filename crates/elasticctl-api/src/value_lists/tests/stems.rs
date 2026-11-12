use super::super::*;

#[test]
fn safe_ids_keep_their_names_and_unsafe_ids_have_stable_hashes() {
    for id in ["blocked", "a.b", "a-1_2", "a", "com0", "com10"] {
        assert_eq!(file_stem(id), id);
    }
    for (id, expected) in [
        ("con", "con-1143da2bc54c"),
        ("NUL.txt", "nul_txt-0241e4ee79f7"),
        ("A", "a-559aead08264"),
        ("ünïcode", "_n_code-b8be8967e4de"),
    ] {
        assert_eq!(file_stem(id), expected);
    }
    assert_eq!(file_stem(&"a".repeat(64)), "a".repeat(64));
    let long = file_stem(&"a".repeat(512));
    assert_eq!(long, format!("{}-471be6558b66", "a".repeat(48)));
    for id in [
        ".hidden",
        "trailing.",
        "prn",
        "aux",
        "nul",
        "com1",
        "com9.x",
        "lpt1",
        "lpt9.x",
        "../escape",
        "a/b",
    ] {
        let stem = file_stem(id);
        assert_ne!(stem, id);
        assert!(stem.len() <= 64 && stem.is_ascii());
        assert!(!stem.contains('/') && !stem.ends_with('.'));
    }
}

#[test]
fn plans_case_variants_distinctly_and_reports_all_case_insensitive_collisions() {
    let planned = plan_stems(["A", "a"]).unwrap();
    assert_eq!(planned["A"], "a-559aead08264");
    assert_eq!(planned["a"], "a");
    // A safe id can equal another id's hashed fallback.
    let error = plan_stems(["A", "a-559aead08264", "B", "b-df7e70e50215"]).unwrap_err();
    for id in ["A", "a-559aead08264", "B", "b-df7e70e50215"] {
        assert!(error.message.contains(id), "{error}");
    }
    assert!(stem_collisions([("first", "SAME"), ("second", "same")]).len() == 1);
}
