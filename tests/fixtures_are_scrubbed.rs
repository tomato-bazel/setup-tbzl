//! ⛔⛔ THE MERGE GATE'S IN-TREE HALF.
//!
//! `tomato-bazel/tbzl-profile` was made public and a LIVE BuildBuddy API key was committed
//! into it **within hours**, extracted from a Bazel BEP fixture. This repository must also be
//! public — a private Action cannot be consumed from another org, which is the same wall that
//! forced that repo public in the first place — so it inherits the same exposure with none of
//! the excuse.
//!
//! ⚠ THE REASON A GREP WAS NOT ENOUGH. The BEP carries
//! `--remote_header=x-buildbuddy-api-key=<key>` nine times across four events, and Bazel's
//! JSON writer escapes `=` as `=`. `grep 'api-key='` over the file finds nothing. So
//! this test normalizes before it matches.
//!
//! ⭐ TWO GATES, NOT ONE, AND THEY CATCH DIFFERENT THINGS. `gitleaks` in
//! `.github/workflows/ci.yml` is the required status check and scans the full PR history for
//! provider-shaped credentials. This test scans the working tree for the ESCAPED shapes a
//! generic scanner's regexes miss, and it runs on a developer's machine before a push exists.
//! Neither subsumes the other.

use std::path::{Path, PathBuf};

/// Walk the repository, not just `tests/fixtures`.
///
/// ⚠ SCANNING ONLY THE FIXTURE DIRECTORY WOULD BE THE BUG. The key in the incident above was
/// not in a fixture directory — it was inline in `src/`, pasted into a doc comment that was
/// quoting a real BEP. A scanner aimed at where secrets are *supposed* to live finds none.
fn repo_root() -> PathBuf {
    // Under Bazel the test runs in runfiles; `RUNFILES_DIR`/`TEST_SRCDIR` point at the tree.
    // Under cargo, `CARGO_MANIFEST_DIR` does. Prefer the source tree either way.
    if let Ok(d) = std::env::var("TBZL_SETUP_SRCDIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        // ⚠ Skip build outputs and VCS internals. `bazel-*` are symlinks into the output
        // base; following them walks the entire external repository tree and the test times
        // out rather than failing — which reads as flakiness.
        if name.starts_with('.') && name != ".github" && name != ".gitleaks.toml" {
            continue;
        }
        if matches!(name.as_ref(), "target" | "bazel-out" | "bazel-bin" | "bazel-testlogs")
            || name.starts_with("bazel-")
        {
            continue;
        }
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn no_fixture_or_source_file_carries_a_credential() {
    let root = repo_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 5,
        "the scanner found {} files under {} — it is not looking at the repository, and a \
         scanner that inspects nothing passes",
        files.len(),
        root.display()
    );

    let mut failures = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue; // binary
        };
        for hit in tbzl_setup::redact::scan(&text) {
            failures.push(format!(
                "{}: `{}` with a value that is not a placeholder (offset {} in normalized text)",
                f.strip_prefix(&root).unwrap_or(f).display(),
                hit.pattern,
                hit.at
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "⛔ credential-shaped content found. Scrub it, rotate the secret, and remember that \
         `grep` will not find the JSON-escaped form:\n  {}",
        failures.join("\n  ")
    );
}

/// ⚠ A scanner nobody has ever seen fail is a scanner nobody knows works. This proves the
/// walk + scan pipeline catches a planted secret in a file on disk — the same code path the
/// test above runs, not a unit test of `scan` alone.
#[test]
fn the_scanner_catches_a_planted_secret_in_a_real_file() {
    let dir = std::env::var("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join(format!("scrub-selftest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("planted.json");

    // ⭐⭐ THE PLANTED VALUE IS ASSEMBLED AT RUNTIME, AND THIS FILE THEREFORE CONTAINS NO
    // CONTIGUOUS SECRET-SHAPED TOKEN. Writing it as a literal would make THIS file fail
    // `no_fixture_or_source_file_carries_a_credential` above — the scanner cannot tell a
    // deliberately planted secret from an accidental one, and it must not try. The
    // alternative, adding an exemption for this path, is how a scanner acquires the
    // allowlist entry that later hides a real key.
    //
    // ⚠ It must also not contain any of `redact`'s placeholder markers, or the scanner would
    // correctly ignore it and this test would pass while proving nothing.
    let key = format!("{}{}{}", "Zk3Qv91", "LmTr8", "Wb2Nc4Jh");
    let esc = concat!("\\", "u003d");
    // The escaped form, exactly as Bazel writes it.
    std::fs::write(
        &f,
        format!(r#"{{"cmdLine":["--remote_header{esc}x-buildbuddy-api-key{esc}{key}"]}}"#),
    )
    .unwrap();

    let mut files = Vec::new();
    walk(&dir, &mut files);
    assert_eq!(files.len(), 1);
    let text = std::fs::read_to_string(&files[0]).unwrap();
    assert!(
        !text.contains("api-key="),
        "precondition: the raw bytes must not contain the unescaped form"
    );
    assert!(
        !tbzl_setup::redact::scan(&text).is_empty(),
        "the planted secret must be found"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
