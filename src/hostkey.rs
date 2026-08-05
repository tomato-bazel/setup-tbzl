//! Derivation of the credential helper's per-host environment variable.
//!
//! ⛔⛔ THIS IS THE MOST EXPENSIVE FUNCTION IN THE REPOSITORY TO GET WRONG, AND IT WILL NOT
//! TELL YOU.
//!
//! `cred-helper` self-routes off the request URI: it uppercases the host, replaces every
//! non-alphanumeric byte with `_`, and looks up `FASTVERK_TOKEN_FILE_<that>`. A well-formed
//! request for a host it has no variable for returns `{"headers":{}}` and exit 0 — so Bazel
//! sends NO Authorization header at all and the RBE answers `UNAUTHENTICATED`, which reads as
//! a broken endpoint or a bad token. Measured on the first cutover attempt: 97 of 97 targets
//! failed that way with a VALID token sitting in the token file the whole time.
//!
//! ⭐ The reason this module exists rather than the workflow spelling the variable out: the
//! variable is now DERIVED from the endpoint, in the same process that emits the endpoint. A
//! stale key is no longer a thing a consumer can have, because there is nothing to keep in
//! sync — and `verify::credential_round_trip` then proves the derivation was right by asking
//! the real helper, rather than trusting this code.
//!
//! ⚠ THIS MUST TRACK `cred-helper`'s `canonical_env_var` EXACTLY (credresolve/src/
//! connections.rs). Two independent implementations of one derivation is how they drift; the
//! helper itself already carries two copies (`credresolve` and `oidc`) with no shared test.
//! `same_shape_as_cred_helper` below pins the cases that matter.

/// `rbe.tbzl.dev` -> `FASTVERK_TOKEN_FILE_RBE_TBZL_DEV`.
///
/// ⚠ EVERY non-`[A-Za-z0-9]` byte becomes `_`, not just dots and dashes. `[::1]` therefore
/// becomes `___1_` — brackets and colons all collapse. That is the helper's behavior, and
/// matching it matters more than being tidy.
pub fn token_file_var(host: &str) -> String {
    format!("FASTVERK_TOKEN_FILE_{}", sanitize(host))
}

/// `rbe.tbzl.dev` -> `FASTVERK_TOKEN_RBE_TBZL_DEV` — the value-carrying variant.
///
/// ⚠ Not what CI should use: a static value freezes the token at build start, and a build
/// that outlives the ~1h TTL dies `UNAUTHENTICATED` partway through. That took one repo's
/// main branch to 1 green in 25. Present because `verify` warns when it is set alongside the
/// file form, where it would shadow it.
pub fn token_value_var(host: &str) -> String {
    format!("FASTVERK_TOKEN_{}", sanitize(host))
}

fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact strings the live workflow hardcoded, which this now derives.
    #[test]
    fn same_shape_as_cred_helper() {
        assert_eq!(
            token_file_var("rbe.tbzl.dev"),
            "FASTVERK_TOKEN_FILE_RBE_TBZL_DEV"
        );
        assert_eq!(
            token_file_var("rbe.fastverk.com"),
            "FASTVERK_TOKEN_FILE_RBE_FASTVERK_COM"
        );
        assert_eq!(
            token_value_var("gitlab.savvifi.com"),
            "FASTVERK_TOKEN_GITLAB_SAVVIFI_COM"
        );
    }

    /// ⚠ Not just dots. A dash, a colon and a bracket all collapse to `_` too — but DIGITS
    /// survive, which is what makes an IPv6 literal produce `___1_` rather than five
    /// underscores. Worth pinning: an "obviously all underscores" reading of the rule derives
    /// a variable name the helper never looks up, and the helper answers anonymously.
    #[test]
    fn every_non_alphanumeric_collapses_but_digits_survive() {
        assert_eq!(sanitize("a-b.c"), "A_B_C");
        assert_eq!(sanitize("[::1]"), "___1_");
        assert_eq!(sanitize("rbe2.tbzl.dev"), "RBE2_TBZL_DEV");
    }

    /// ⛔ THE TWO ENDPOINTS THAT COEXISTED IN ONE LIVE WORKFLOW derive DIFFERENT variables.
    /// That is the whole bug: the job-level env named `rbe.fastverk.com` while the step-level
    /// override named `rbe.tbzl.dev`, and the helper key was written for exactly one of them.
    #[test]
    fn the_two_live_endpoints_do_not_share_a_key() {
        assert_ne!(
            token_file_var("rbe.tbzl.dev"),
            token_file_var("rbe.fastverk.com")
        );
    }
}
