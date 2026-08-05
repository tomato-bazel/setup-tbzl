//! Ask the real credential helper the question Bazel will ask, before Bazel asks it.
//!
//! ⭐⭐ THIS MODULE IS THE ONE THAT PAYS FOR THE REPOSITORY.
//!
//! `cred-helper` fails OPEN at four independent layers, every one of them defaulting to
//! silence:
//!
//!   1. the documented top-level contract — *"Any miss ... yields `{"headers":{}}` and exit
//!      0, so a fetch degrades to anonymous rather than failing the build"*
//!   2. the unconfigured-host return, a wildcard `_` arm that swallows `Ok(None)` and
//!      `Err(_)` identically
//!   3. the secret store — *"a backend error is treated as a miss and the next ref is tried"*
//!   4. the config arms — *"a missing or malformed config file is a miss, never an error"*
//!
//! There is no strict mode. I grepped the whole repository at its released HEAD for
//! `strict|FAIL|process::exit|eprintln` and the helper binary has no error path to stdout and
//! no non-zero exit anywhere. That is a deliberate design decision on their side, and it has
//! now cost this estate two fleet-wide outages that were misdiagnosed as unrelated systems:
//! a dead-code-eliminated config feature that made every private-ECR pull 401 (read as "the
//! C++ toolchain is broken"), and a helper timeout under ECR minting (read as "RBE is
//! starved").
//!
//! ⭐ THE FIX DOES NOT REQUIRE CHANGING THE HELPER. An unconfigured host and a correctly
//! configured anonymous host are byte-identical on the wire — but a host we KNOW must
//! authenticate is not allowed to be anonymous. So: run the helper exactly as Bazel will,
//! with exactly the environment the build will have, and treat `{"headers":{}}` as a HARD
//! ERROR. Every one of the four layers above becomes loud, in the step where it can be read,
//! with the derived variable name and the token path in the message.
//!
//! ⚠ This probe is why the Action's guarantee is empirical rather than merely careful. Every
//! other check in `verify` reasons about strings; this one gets an answer from the binary
//! that will actually be invoked.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// What the helper said when asked about one host.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    /// A credential was returned. The header NAME only — the value is never carried out of
    /// this module.
    Authenticated { header: String },
    /// ⛔ `{"headers":{}}` — the fail-open answer. Indistinguishable from "this host is
    /// meant to be anonymous", which is why only the caller's knowledge that the host MUST
    /// authenticate turns it into an error.
    Anonymous,
    /// The helper could not be run at all.
    HelperUnusable(String),
    /// The helper produced something that is not the protocol.
    Unparseable(String),
}

/// Run `<helper> get` with `{"uri":"https://<host>/"}` on stdin, exactly as Bazel does.
///
/// ⚠ `env` REPLACES the child's environment for the variables it names; everything else is
/// inherited. The point is to probe under the same variables the build will see, including
/// the `FASTVERK_TOKEN_FILE_*` this Action is about to export — not under the ambient shell.
pub fn probe(helper: &Path, host: &str, env: &[(String, String)]) -> Probe {
    // ⚠ `https://` regardless of the endpoint's gRPC scheme. cred-helper parses the request
    // URI for its HOST and ignores the scheme, and Bazel itself hands the helper an
    // https-shaped URI for a `grpcs://` remote. Sending `grpcs://` here would probe a code
    // path Bazel never exercises.
    let request = format!("{{\"uri\":\"https://{host}/\"}}");

    let mut cmd = Command::new(helper);
    cmd.arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Probe::HelperUnusable(format!(
                "cannot execute credential helper at {}: {e}",
                helper.display()
            ))
        }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        // ⚠ Ignore a write error: the helper drains stdin fully precisely so Bazel's writer
        // never sees EPIPE, but a helper that exited early would produce one here and the
        // real diagnosis is in its output, not in this write.
        let _ = stdin.write_all(request.as_bytes());
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return Probe::HelperUnusable(format!("credential helper did not complete: {e}")),
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_response(&stdout)
}

/// Parse the helper's `get` response.
///
/// ⚠ `expires` is tolerated and ignored. It is emitted only for refreshable sources and its
/// presence is not evidence of anything this check cares about — a token file that exists but
/// holds a dead token still produces `expires`.
pub fn parse_response(stdout: &str) -> Probe {
    let v: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(e) => {
            // ⛔⛔ THE HELPER'S STDOUT GOES INTO AN ERROR MESSAGE, AND ITS STDOUT CARRIES
            // BEARER TOKENS. A malformed-but-nearly-right response — a stray log line before
            // the JSON, a truncated write — is exactly the case that reaches here, and it is
            // exactly the case most likely to contain a real credential. This message lands in
            // a GitHub Actions annotation on a PUBLIC repository's build log. Redact first.
            //
            // ⚠ This is the leak path the `mask` function exists for; before it was wired in,
            // `mask` was an exported, tested function with no caller — which is its own warning
            // sign. A redactor nothing calls redacts nothing.
            return Probe::Unparseable(format!(
                "credential helper emitted non-JSON ({e}): {:?}",
                crate::redact::mask(truncate(stdout.trim(), 200))
            ));
        }
    };
    let Some(headers) = v.get("headers").and_then(|h| h.as_object()) else {
        return Probe::Unparseable(
            "credential helper response has no `headers` object — this is not the Bazel \
             credential-helper protocol"
                .to_string(),
        );
    };
    // ⛔ THE FAIL-OPEN SHAPE. An empty map is a well-formed, exit-0, entirely successful
    // response that means "send nothing".
    let Some((name, values)) = headers.iter().next() else {
        return Probe::Anonymous;
    };
    // ⚠ A header present with an empty or absent value list is also anonymous in effect.
    // Bazel would send an empty header, which the RBE rejects the same way as none.
    let non_empty = values
        .as_array()
        .map(|a| a.iter().any(|s| s.as_str().is_some_and(|s| !s.is_empty())))
        .unwrap_or(false);
    if !non_empty {
        return Probe::Anonymous;
    }
    Probe::Authenticated {
        header: name.clone(),
    }
}

/// Pull the bearer value out of a helper response, for token inspection.
///
/// ⭐ SEPARATE FROM `probe` ON PURPOSE. `probe` returns no secret material, so the common
/// path cannot leak one into a log through a `Debug` impl. Only `verify::token_claims`, which
/// needs the JWT body, calls this — and it discards the value before returning.
pub fn bearer_value(stdout: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let headers = v.get("headers")?.as_object()?;
    let (_, values) = headers.iter().next()?;
    let raw = values.as_array()?.first()?.as_str()?;
    Some(raw.strip_prefix("Bearer ").unwrap_or(raw).to_string())
}

fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔⛔ A MALFORMED RESPONSE IS THE ONE MOST LIKELY TO CARRY A REAL TOKEN, and its text goes
    /// into an annotation on a PUBLIC build log.
    #[test]
    fn a_malformed_response_does_not_leak_the_credential_into_the_error() {
        let secret = format!("{}{}{}", "Zk3Qv91", "LmTr8", "Wb2Nc4Jh");
        // A stray log line before the JSON — a real and common way to get here.
        let out = format!("warning: keychain locked\n{{\"headers\":{{\"authorization\":[\"Bearer {secret}\"]}}}}");
        let Probe::Unparseable(msg) = parse_response(&out) else {
            panic!("expected Unparseable for {out:?}");
        };
        assert!(
            !msg.contains(&secret),
            "the credential must not reach the error message: {msg}"
        );
    }

    #[test]
    fn a_credential_is_recognized() {
        assert_eq!(
            parse_response(r#"{"headers":{"Authorization":["Bearer abc"]}}"#),
            Probe::Authenticated {
                header: "Authorization".into()
            }
        );
    }

    /// ⛔ THE EXACT BYTES THE HELPER EMITS FOR AN UNCONFIGURED HOST. Everything in this
    /// repository exists to stop this string from being mistaken for success.
    #[test]
    fn the_fail_open_response_is_recognized_as_anonymous() {
        assert_eq!(parse_response(r#"{"headers":{}}"#), Probe::Anonymous);
        assert_eq!(parse_response("{\"headers\":{}}\n"), Probe::Anonymous);
    }

    /// ⚠ A header whose value list is empty sends an empty header, which the RBE rejects
    /// identically to no header. Anonymous in effect.
    #[test]
    fn an_empty_value_list_is_anonymous_in_effect() {
        assert_eq!(
            parse_response(r#"{"headers":{"Authorization":[]}}"#),
            Probe::Anonymous
        );
        assert_eq!(
            parse_response(r#"{"headers":{"Authorization":[""]}}"#),
            Probe::Anonymous
        );
    }

    #[test]
    fn garbage_is_not_silently_treated_as_either() {
        assert!(matches!(parse_response("not json"), Probe::Unparseable(_)));
        assert!(matches!(parse_response("{}"), Probe::Unparseable(_)));
    }

    #[test]
    fn a_bearer_is_extractable_for_claim_inspection() {
        assert_eq!(
            bearer_value(r#"{"headers":{"Authorization":["Bearer t.o.k"]}}"#).as_deref(),
            Some("t.o.k")
        );
    }

    #[test]
    fn a_missing_helper_binary_is_an_error_not_a_miss() {
        let p = probe(Path::new("/nonexistent/cred-helper"), "rbe.tbzl.dev", &[]);
        assert!(matches!(p, Probe::HelperUnusable(_)), "got {p:?}");
    }
}
