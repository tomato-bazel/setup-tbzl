//! Where this executor keeps bazel's state — resolved from the RUNNER, never from the plane.
//!
//! ⭐⭐ THE CONVENTION, AND WHY IT IS A CONVENTION RATHER THAN A PROFILE FIELD.
//!
//! The plane knows which cache TIERS are worth enabling. It cannot know where a given executor
//! has disk: `/bazel-cache` is a property of one ARC pod's PVC, not of tbzl-boston. Put that
//! path in the served profile and the profile stops describing a plane and starts describing a
//! runner — so a Buildkite agent, a laptop, a dev container or a second pod shape cannot use it,
//! and the estate is welded to one hosted GHA fleet.
//!
//! So the split is the same one this crate already makes for credentials: the platform decides
//! the NAME and the POLICY, the host decides the PATH.
//!
//! | who | decides |
//! |---|---|
//! | the plane (profile) | *which* cache tiers to enable |
//! | the runner (env)    | *where* those tiers live |
//! | this module         | that the two are consistent, or a loud failure |
//!
//! ## The two variables
//!
//! ⛔ TWO, NOT ONE, AND COLLAPSING THEM IS THE BUG THIS FILE EXISTS TO PREVENT. A single
//! `TBZL_HOME` reads as tidier and is wrong, because the two directories have OPPOSITE sharing
//! semantics:
//!
//! - `TBZL_CACHE_ROOT` — **shared**. Content-addressed, built for many concurrent readers and
//!   writers. On tbzl-boston this is one PVC mounted into every runner pod, which is what lets a
//!   pod that has never run find LLVM, the Go SDK and protobuf already fetched.
//! - `TBZL_OUTPUT_ROOT` — **private to this executor**. Bazel takes an EXCLUSIVE lock on the
//!   output base. Two runners sharing one do not share work: they serialise, or fail outright.
//!
//! Someone who sets `TBZL_HOME=/bazel-cache` and lets both live under it gets a fleet where
//! every concurrent build blocks on one lock, and the symptom is "the plane got slower", which
//! names nothing. `resolve` refuses that arrangement instead.
//!
//! ## Fallbacks, and why the last one is a finding rather than a default
//!
//! An unset `TBZL_OUTPUT_ROOT` falls back to bazel's own default, `$HOME/.cache/bazel`. On a
//! container that IS the writable layer, which is what a pod's `ephemeral-storage` limit
//! governs — and on 2026-08-19 that evicted every runner on this plane mid-build, presenting as
//! "the build is not advancing" because ARC silently replaces evicted pods while the run stays
//! `in_progress`. So the fallback is permitted (a laptop is fine) and REPORTED, and `verify`
//! turns it fatal where it is known to be wrong.

use std::path::{Path, PathBuf};

/// The env var naming a directory shared by every executor on this host. Many readers.
pub const CACHE_ROOT_VAR: &str = "TBZL_CACHE_ROOT";
/// The env var naming a directory private to THIS executor. Exclusively locked by bazel.
pub const OUTPUT_ROOT_VAR: &str = "TBZL_OUTPUT_ROOT";

/// Subdirectory names under `TBZL_CACHE_ROOT`. ⚠ Fixed by convention, deliberately: if the
/// profile named them, two planes could disagree and a runner's disk would silently hold two
/// copies of the same content-addressed data under different names.
pub const REPO_DIR: &str = "repo";
pub const CONTENTS_DIR: &str = "contents";
pub const DISK_DIR: &str = "disk";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    /// Shared cache root, if this host offers one.
    pub cache_root: Option<PathBuf>,
    /// Private output base root, if this host names one.
    pub output_root: Option<PathBuf>,
    /// Human-readable note about how each was resolved, for the step log.
    pub provenance: Vec<String>,
}

impl Layout {
    pub fn repository_cache(&self) -> Option<PathBuf> {
        self.cache_root.as_ref().map(|r| r.join(REPO_DIR))
    }
    pub fn repo_contents_cache(&self) -> Option<PathBuf> {
        self.cache_root.as_ref().map(|r| r.join(CONTENTS_DIR))
    }
    pub fn disk_cache(&self) -> Option<PathBuf> {
        self.cache_root.as_ref().map(|r| r.join(DISK_DIR))
    }
}

/// Resolve the layout from an environment.
///
/// ⚠ Takes the environment as a parameter rather than reading it, so the invariants below are
/// testable without a process that has the wrong variables set.
pub fn resolve(env: &[(String, String)]) -> Result<Layout, String> {
    let get = |k: &str| -> Option<String> {
        env.iter()
            .find(|(n, _)| n == k)
            // ⚠ An empty value is UNSET, not "the current directory". A workflow that writes
            // `TBZL_CACHE_ROOT: ${{ env.SOMETHING_UNDEFINED }}` produces the empty string, and
            // treating that as a path roots the cache at the repo checkout.
            .and_then(|(_, v)| (!v.trim().is_empty()).then(|| v.trim().to_string()))
    };

    let mut provenance = Vec::new();
    let cache_root = get(CACHE_ROOT_VAR).map(PathBuf::from);
    let output_root = get(OUTPUT_ROOT_VAR).map(PathBuf::from);

    match &cache_root {
        Some(p) => provenance.push(format!("{CACHE_ROOT_VAR}={} (from the runner)", p.display())),
        None => provenance.push(format!(
            "{CACHE_ROOT_VAR} unset — no shared cache is configured on this executor, so each \
             build starts cold. That is correct on a laptop and wrong on a fleet"
        )),
    }
    match &output_root {
        Some(p) => provenance.push(format!("{OUTPUT_ROOT_VAR}={} (from the runner)", p.display())),
        None => provenance.push(format!(
            "{OUTPUT_ROOT_VAR} unset — bazel will use its default output base under \
             $HOME/.cache/bazel. ⚠ In a container that is the WRITABLE LAYER, which is what a \
             pod's ephemeral-storage limit governs"
        )),
    }

    // ⛔ INVARIANT 1 — THE OUTPUT BASE MUST NOT LIVE INSIDE THE SHARED CACHE. This is the
    // arrangement a single `TBZL_HOME` produces, and it is not a performance nit: bazel locks
    // the output base exclusively, so every concurrent executor on this host would serialise on
    // one lock. Nothing errors; the fleet just stops overlapping, and the symptom is "builds got
    // slower" with no failure to point at.
    if let (Some(c), Some(o)) = (&cache_root, &output_root) {
        if o == c || o.starts_with(c) {
            return Err(format!(
                "{OUTPUT_ROOT_VAR} ({}) is inside {CACHE_ROOT_VAR} ({}). Bazel takes an \
                 EXCLUSIVE lock on the output base, so every concurrent build on this host \
                 would serialise on it — and that failure is silent, because a serialised \
                 fleet reports slowness rather than an error. The two directories have \
                 opposite sharing semantics and must not nest: the cache is shared by design, \
                 the output base cannot be",
                o.display(),
                c.display()
            ));
        }
        // ⚠ The reverse nesting is equally wrong and much easier to type by accident.
        if c.starts_with(o) {
            return Err(format!(
                "{CACHE_ROOT_VAR} ({}) is inside {OUTPUT_ROOT_VAR} ({}). The shared cache would \
                 then sit under a directory bazel treats as its own private state and is free \
                 to clean, so `bazel clean --expunge` on one executor would delete the fleet's \
                 shared cache",
                c.display(),
                o.display()
            ));
        }
    }

    Ok(Layout { cache_root, output_root, provenance })
}

/// Does this path sit where a container's writable layer usually is?
///
/// ⚠ A HEURISTIC, AND LABELLED AS ONE. There is no portable way to ask "is this an overlayfs
/// upper dir that counts against ephemeral-storage" without reading mountinfo, which is not
/// available identically across the runtimes this has to work on. `$HOME/.cache` is where bazel
/// puts the output base by default and is the case that actually bit this estate.
pub fn looks_like_writable_layer(p: &Path, home: Option<&str>) -> bool {
    let Some(home) = home else { return false };
    let home = Path::new(home);
    p.starts_with(home.join(".cache"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// ⛔ THE `TBZL_HOME` MISTAKE, REFUSED. Both roots under one parent is the arrangement a
    /// single variable invites, and it silently serialises every concurrent build.
    #[test]
    fn the_output_base_may_not_live_inside_the_shared_cache() {
        let e = env(&[(CACHE_ROOT_VAR, "/bazel-cache"), (OUTPUT_ROOT_VAR, "/bazel-cache/out")]);
        let err = resolve(&e).expect_err("nesting must be refused");
        assert!(err.contains("EXCLUSIVE lock"), "the error must name the cause, got: {err}");
    }

    /// ⛔ AND THE REVERSE, which is easier to type by accident and destroys more.
    #[test]
    fn the_shared_cache_may_not_live_inside_the_output_base() {
        let e = env(&[(CACHE_ROOT_VAR, "/out/cache"), (OUTPUT_ROOT_VAR, "/out")]);
        let err = resolve(&e).expect_err("reverse nesting must be refused");
        assert!(err.contains("expunge"), "the error must name the consequence, got: {err}");
    }

    #[test]
    fn identical_roots_are_refused() {
        let e = env(&[(CACHE_ROOT_VAR, "/same"), (OUTPUT_ROOT_VAR, "/same")]);
        assert!(resolve(&e).is_err(), "identical roots are the degenerate nesting case");
    }

    /// ⚠ EMPTY IS UNSET. An undefined GitHub expression renders as the empty string, and
    /// treating that as a path roots the cache at the checkout directory.
    #[test]
    fn an_empty_value_is_unset_not_a_relative_path() {
        let e = env(&[(CACHE_ROOT_VAR, "   "), (OUTPUT_ROOT_VAR, "")]);
        let l = resolve(&e).expect("empty values are unset, not an error");
        assert_eq!(l.cache_root, None);
        assert_eq!(l.output_root, None);
    }

    #[test]
    fn disjoint_roots_resolve_and_derive_the_conventional_subdirs() {
        let e = env(&[(CACHE_ROOT_VAR, "/bazel-cache"), (OUTPUT_ROOT_VAR, "/w/.bazelroot")]);
        let l = resolve(&e).expect("disjoint roots are the correct arrangement");
        assert_eq!(l.repository_cache().unwrap(), Path::new("/bazel-cache/repo"));
        assert_eq!(l.repo_contents_cache().unwrap(), Path::new("/bazel-cache/contents"));
        assert_eq!(l.disk_cache().unwrap(), Path::new("/bazel-cache/disk"));
    }

    #[test]
    fn the_default_output_base_is_recognised_as_the_writable_layer() {
        assert!(looks_like_writable_layer(
            Path::new("/home/runner/.cache/bazel"),
            Some("/home/runner")
        ));
        assert!(!looks_like_writable_layer(
            Path::new("/home/runner/_work/.bazelroot"),
            Some("/home/runner")
        ));
    }
}
