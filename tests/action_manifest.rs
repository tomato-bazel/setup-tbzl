//! The Action's own manifest must load on a GitHub runner.
//!
//! ⛔⛔ NOTHING ELSE IN THIS REPOSITORY CAN CATCH THIS, AND THAT IS THE WHOLE REASON THE TEST
//! EXISTS. `action.yml` is only parsed as an *Action manifest* when a workflow **uses** the
//! Action. `bazel test`, `actionlint` and this repo's own CI all read it as ordinary YAML,
//! where every string is just a string. So a manifest that GitHub refuses to load is green
//! here, green in review, and fails on first contact with the first consumer.
//!
//! Which is exactly what happened. v1.0.0 shipped with a usage example inside an output's
//! `description`, and every consumer got:
//!
//! ```text
//! action.yml (Line: 145, Col: 18): Unrecognized named-value: 'steps'.
//! Located at position 1 within expression: steps.x.outputs.bazelrc
//! ##[error]Failed to load tomato-bazel/setup-tbzl/v1/action.yml
//! ```
//!
//! ⚠ THE TRAP IS THAT `steps` IS LEGAL ON THE NEXT LINE. In a composite action,
//! `value: ${{ steps.configure.outputs.bazelrc }}` is correct and required. In a
//! `description:` the same syntax is still *evaluated* and `steps` is not in scope. Two
//! adjacent lines, one legal, and they look alike — which is why reading did not find it.

use std::path::PathBuf;

fn manifest() -> String {
    // ⚠ FAIL, DO NOT SKIP, IF THE MANIFEST IS MISSING. A test that skips when its input is
    // absent reports the same green as one that ran, which is the failure mode this suite
    // exists to prevent.
    let dir = std::env::var("TBZL_SETUP_SRCDIR").unwrap_or_else(|_| ".".to_string());
    let p = PathBuf::from(dir).join("action.yml");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}. This test cannot run, which is not a pass.", p.display()))
}

/// ⭐ THE ONE THAT WOULD HAVE CAUGHT v1.0.0.
///
/// GitHub evaluates `${{ … }}` in `description:` as well as in `value:`. Only a small set of
/// contexts is available there — `inputs`, `github`, `env` — and `steps` is not among them.
#[test]
fn descriptions_contain_no_expressions() {
    let src = manifest();
    let mut offenders = Vec::new();
    let mut in_description = false;

    for (n, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        // A description opens either inline (`description: "…"`) or as a block scalar
        // (`description: >-`), and a block continues while lines stay more indented.
        if trimmed.starts_with("description:") {
            in_description = true;
            if trimmed.contains("${{") {
                offenders.push((n + 1, line.to_string()));
            }
            continue;
        }
        if in_description {
            // A new key at any level ends the block scalar.
            let is_key = trimmed.contains(':') && !trimmed.starts_with('#') && !line.starts_with("      ");
            if trimmed.is_empty() || is_key {
                in_description = false;
            } else if line.contains("${{") {
                offenders.push((n + 1, line.to_string()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "`${{{{ … }}}}` inside a description makes the manifest UNLOADABLE on a runner — GitHub \
         evaluates these strings. Put the example in README.md instead.\n{}",
        offenders
            .iter()
            .map(|(n, l)| format!("  line {n}: {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// ⚠ Guards the other half: the outputs genuinely need `steps`, so a well-meaning fix that
/// stripped every expression from the file would break the Action just as thoroughly, and
/// would pass the test above.
#[test]
fn output_values_still_reference_their_step() {
    let src = manifest();
    assert!(
        src.contains("value: ${{ steps.configure.outputs.bazelrc }}"),
        "the bazelrc output must still read from the configure step — `steps` is legal, and \
         required, in `value:`"
    );
}

/// The composite `runs:` block is what makes `steps` legal in `value:` at all.
#[test]
fn the_action_is_composite() {
    let src = manifest();
    assert!(
        src.contains("using: composite"),
        "outputs reference `steps.*`, which is only valid in a composite action"
    );
}
