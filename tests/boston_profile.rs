//! ⛔⛔ ONE TEST PER SILENT FAILURE THE tbzl-boston CUTOVER ACTUALLY HIT.
//!
//! Read `loud_failures.rs` first — the same rule applies here: a test that only proves the
//! document parses is worth very little, because a WRONG profile parses perfectly. Every
//! assertion below corresponds to a failure observed on the live plane during the migration on
//! 2026-08-19, and every one of them is a value that is accepted, stored, echoed back, and then
//! produces a build that hangs or lies rather than an error.
//!
//! ⚠ THE FIXTURE IS REQUIRED, NOT OPTIONAL. If it cannot be read this test FAILS — it does not
//! skip. A suite that quietly passes when its input is missing is the exact shape this
//! repository exists to prevent, and `BUILD.bazel` puts the tree in runfiles for that reason.

use std::path::PathBuf;

fn boston() -> tbzl_setup::protocol::Profile {
    // Bazel runs this from runfiles; cargo from the manifest dir. Prefer the source tree either
    // way, and PANIC rather than skip if neither resolves.
    let root = std::env::var("TBZL_SETUP_SRCDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let path = root.join("tests/fixtures/tbzl-boston.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("tbzl-boston fixture unreadable at {}: {e}", path.display()));
    tbzl_setup::protocol::Profile::parse(&bytes)
        .unwrap_or_else(|e| panic!("tbzl-boston profile does not parse: {e}"))
}

/// ⛔ THE ACCOUNT IN `container-image` CHANGED WITH THIS CUTOVER, UNLIKE THE PREVIOUS ONE.
///
/// The exec property is an opaque routing token the scheduler string-compares and never
/// fetches. The AWS plane's workers advertise `042825952740`; tbzl-boston's advertise
/// `394050190195`. A profile carrying the old account names a platform NO WORKER SERVES, and
/// the scheduler answers
///
///   FAILED_PRECONDITION: No workers exist for instance name prefix "" platform {…}
///
/// which reads as a dead endpoint rather than as a one-token mismatch. `savvifi/aion` carried a
/// comment asserting the string would NOT change, written from the previous cutover, and that
/// comment was wrong this time.
#[test]
fn container_image_names_the_account_whose_workers_actually_serve() {
    let p = boston();
    let ex = p.facts.execution.expect("boston profile must offer execution");
    let img = ex
        .exec_properties
        .get("container-image")
        .expect("container-image is not optional: without it the scheduler sees platform {}");
    assert!(
        img.contains("394050190195"),
        "container-image must name the tbzl account whose workers serve this plane, got {img}"
    );
    assert!(
        !img.contains("042825952740"),
        "container-image still names the AWS plane's account; every action will fail to schedule"
    );
}

/// ⛔ THE TWO PLATFORM STATEMENTS MUST AGREE, AND DISAGREEMENT DOES NOT ERROR.
///
/// `exec_properties` is what the client sends; `advertised_platform` is what the fleet claims to
/// serve. A client cannot observe the latter, so the only thing that can catch the platform
/// having drifted is the platform contradicting ITSELF in its own published document. If they
/// differ, actions queue forever against a fleet that will never claim them — which reads as a
/// slow build.
#[test]
fn the_platform_does_not_contradict_itself() {
    let p = boston();
    let ex = p.facts.execution.expect("execution");
    assert_eq!(
        ex.exec_properties, ex.advertised_platform,
        "the profile's two platform statements disagree; actions would queue forever"
    );
}

/// ⛔ `remote_local_fallback` MUST BE FALSE, OR A BROKEN PLANE GOES GREEN.
///
/// With fallback on, an action the RBE rejects silently runs on the client and the build
/// succeeds having proven nothing about the plane. Measured during this cutover: aion's own
/// `.bazelrc` sets `--remote_local_fallback`, and only the workflow's explicit
/// `--noremote_local_fallback` made two separate failures visible instead of slow.
#[test]
fn local_fallback_is_off_so_a_broken_plane_cannot_pass() {
    assert!(
        !boston().recommendations.remote_local_fallback,
        "remote_local_fallback must be false: with it on, a rejected action runs locally and \
         the build goes green having exercised nothing"
    );
}

/// ⚠ THE RUNNER LABEL MUST NAME A SCALE SET THAT EXISTS, AND A WRONG ONE QUEUES FOREVER.
///
/// GitHub holds a job whose `runs-on` matches no runner indefinitely rather than failing it, so
/// a stale label reads as a slow build. tbzl-boston's set is `boston-linux-x64`; the AWS plane's
/// is `tbzl-linux-x64`. This asserts the profile does not hand consumers the old one — which is
/// precisely how `savvifi/aion` was stranded three times.
#[test]
fn runner_label_is_this_planes_set_not_the_aws_one() {
    let p = boston();
    assert_eq!(p.facts.runner_label, "boston-linux-x64");
    assert_ne!(
        p.facts.runner_label, "tbzl-linux-x64",
        "handing out the AWS label makes every job queue forever with no error"
    );
}

/// ⚠ EXECUTION AND CACHE MUST NAME THE SAME HOST HERE, AND SPLITTING THEM IS A REAL FAILURE.
///
/// A `--remote_cache` pointing somewhere other than `--remote_executor` makes bazel upload the
/// Action to one store and ask a scheduler that reads another to run it. The error blames the
/// SERVER's blobstore — `Failed to obtain action: Shard 0: Object not found` — and cost an
/// afternoon when a global `~/.bazelrc` did exactly this.
#[test]
fn cache_and_execution_are_not_split_across_hosts() {
    let p = boston();
    let ex = p.facts.execution.expect("execution").endpoint;
    let ca = p.facts.cache.expect("cache").endpoint;
    assert_eq!(
        ex, ca,
        "execution and cache name different hosts; actions upload to one store and execute \
         against another, and the error names the server rather than the client"
    );
    assert!(ex.contains("boston.rbe.tbzl.dev"), "endpoint must be this plane, got {ex}");
}

/// ⚠ `jobs` MUST NOT BE COPIED FROM THE AWS PROFILE.
///
/// That plane recommends 200 from a measured study on a fleet autoscaling to 150 workers.
/// tbzl-boston is ONE node with worker concurrency 32, so 200 oversubscribes a fixed pool. This
/// is a guard against the most tempting edit — copying the neighbouring fixture — rather than a
/// claim that 64 is optimal.
#[test]
fn jobs_is_sized_for_a_single_node_not_an_autoscaling_fleet() {
    let j = boston().recommendations.jobs.expect("jobs should be recommended");
    assert!(
        j <= 128,
        "jobs={j} looks copied from the autoscaling plane; this box has one worker at \
         concurrency 32"
    );
}

/// ⛔⛔ THE CROSS-ORG ERROR, WHICH NO SINGLE-PROFILE TEST COULD HAVE CAUGHT.
///
/// ARC scale sets are ORG-SCOPED. One physical plane is served by three of them, verified against
/// the live cluster:
///
///   boston-linux-x64        -> github.com/savvifi
///   boston-linux-x64-fv     -> github.com/fastverk
///   boston-linux-x64-tbzl   -> github.com/tomato-bazel
///
/// A repo whose `runs-on` names another org's set matches NO runner, and GitHub QUEUES THAT JOB
/// FOREVER rather than failing it — so the mistake reads as a slow build and only surfaces when
/// the old scale set is deleted. An inventory of nine repos pending migration prescribed
/// `boston-linux-x64` for SEVEN of them, four of which are not savvifi repos.
///
/// ⭐ THE TEST WALKS EVERY BOSTON PROFILE rather than checking one. The failure is a DISAGREEMENT
/// between documents, so a per-document assertion cannot see it — which is exactly why it
/// survived nine independent reviews.
#[test]
fn runner_label_matches_the_orgs_scale_set() {
    let root = std::env::var("TBZL_SETUP_SRCDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let dir = root.join("tests/fixtures");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("fixtures unreadable at {}: {e}", dir.display()));

    let expected = |tenant: &str| -> Option<&'static str> {
        match tenant {
            "savvifi" => Some("boston-linux-x64"),
            "fastverk" => Some("boston-linux-x64-fv"),
            "tomato-bazel" => Some("boston-linux-x64-tbzl"),
            _ => None,
        }
    };

    let mut checked = 0usize;
    for e in entries {
        let path = e.expect("dir entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("tbzl-boston") || !name.ends_with(".json") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name} unreadable: {e}"));
        let p = tbzl_setup::protocol::Profile::parse(&bytes)
            .unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
        assert_eq!(p.plane, "tbzl-boston", "{name} is in the boston set but names another plane");
        let want = expected(&p.tenant)
            .unwrap_or_else(|| panic!("{name} names tenant {:?}, which has no known boston scale set. Add it to this mapping AND create the scale set, or the profile hands out a label that matches no runner", p.tenant));
        assert_eq!(
            p.facts.runner_label, want,
            "{name}: tenant {:?} must use scale set {want:?}, not {:?}. ARC scale sets are \
             org-scoped, and a job naming another org's set QUEUES FOREVER rather than failing",
            p.tenant, p.facts.runner_label
        );
        checked += 1;
    }
    // ⚠ An empty fixtures glob would pass every assertion above by never running one.
    assert!(checked >= 3, "expected at least three boston profiles (one per org), walked {checked}");
}
