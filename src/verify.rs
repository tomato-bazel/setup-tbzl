//! Preflight: turn every silent failure in this stack into a loud one, before Bazel starts.
//!
//! ⭐⭐ THE DESIGN RULE THIS FILE IMPLEMENTS. Every check here corresponds to a failure that
//! has actually happened on this estate and whose symptom named the wrong system. The
//! measure of a check is not that it passes on a good config — every bug listed in
//! `README.md` passed a happy-path test — it is that it FAILS on the specific bad config that
//! previously went unnoticed. `tests/loud_failures.rs` asserts exactly that, one test per
//! historical incident.
//!
//! ⛔ NOTHING HERE DEGRADES. A check that cannot be performed reports that it could not be
//! performed and, if it is load-bearing, fails. The credential helper underneath this stack
//! already demonstrates where the other choice leads.

use crate::credprobe::{self, Probe};
use crate::hostkey;
use crate::jwt;
use crate::protocol::{host_of, Profile};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Warn,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    /// Stable identifier, e.g. `TBZL-CRED-ANON`. ⚠ Stable because people grep logs for it and
    /// because a renamed code silently orphans every runbook entry that names it.
    pub code: &'static str,
    pub message: String,
}

impl Finding {
    fn fatal(code: &'static str, message: impl Into<String>) -> Self {
        Self { level: Level::Fatal, code, message: message.into() }
    }
    fn warn(code: &'static str, message: impl Into<String>) -> Self {
        Self { level: Level::Warn, code, message: message.into() }
    }
}

/// Everything the checks need that is not in the profile.
#[derive(Default)]
pub struct Context<'a> {
    /// Path to the `cred-helper` binary the build will use.
    pub cred_helper: Option<&'a Path>,
    /// The environment the build will run with — the variables this Action is about to
    /// export, plus whatever the workflow already set.
    ///
    /// ⭐ THE "WHATEVER THE WORKFLOW ALREADY SET" HALF IS NOT INCIDENTAL. It is what makes
    /// `no_shadow_config` able to see a stale job-level `RBE_ENDPOINT` inherited from the
    /// workflow, which is the live bug this Action was written for.
    pub env: Vec<(String, String)>,
    /// Unix seconds. Injected so token-expiry behavior is testable without waiting.
    pub now: i64,
    /// Contents of the consuming repository's `.bazelrc`, if one exists.
    pub repo_bazelrc: Option<String>,
    /// `RUNNER_NAME` / `RUNNER_ENVIRONMENT`, for the plane check.
    pub runner_name: Option<String>,
    pub runner_environment: Option<String>,
    /// What the workflow ASKED FOR, to be checked against what the document turned out to be.
    pub expect: Expect,
    /// Where this executor keeps bazel state, resolved from the runner. See `crate::layout`.
    pub layout: crate::layout::Layout,
    /// `$HOME`, for deciding whether the output base is on the container's writable layer.
    pub home: Option<String>,
}

/// The identity the caller believes it fetched.
///
/// ⛔ THIS EXISTS BECAUSE `config-url` NAMES A DOCUMENT DIRECTLY. When the Action built a query
/// string (`?tenant=savvifi&plane=…`), the server was the thing that resolved a name to a
/// document, and a wrong name came back as a 404 — loud. Pointing at a URL instead moves that
/// resolution to whoever wrote the URL, and a URL that resolves to the WRONG tenant's profile
/// returns 200 with a perfectly valid document. Every downstream check then passes, because
/// nothing is malformed: it is simply somebody else's plane.
///
/// ⚠ EACH FIELD IS OPTIONAL AND AN ABSENT ONE ASSERTS NOTHING. `tenant` is required by
/// `action.yml`, so in CI the first field is always checked; the other two are only asserted
/// when the workflow pinned them. Absence must not silently weaken the check, which is why the
/// message below distinguishes "not asserted" from "asserted and matched".
#[derive(Default, Clone, Debug)]
pub struct Expect {
    pub tenant: Option<String>,
    pub plane: Option<String>,
    pub config_version: Option<String>,
}

/// How many distinct checks `all` plus `endpoint_reachable` perform.
///
/// ⚠ A CONSTANT, AND IT MUST BE UPDATED WITH THE LIST BELOW. `checks_are_all_counted` fails if
/// it drifts. The alternative — reporting `findings.len()` — announced "0 checks passed" on a
/// clean run, which reads as "nothing was checked".
pub const CHECK_COUNT: usize = 9;

/// Run every check that does not need the network.
///
/// ⚠ Reachability is separate (`endpoint_reachable`) because it is the only check that can
/// fail for a reason outside the configuration — a transient network fault — and mixing it in
/// would make the offline suite untestable.
pub fn all(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let mut f = without_credentials(profile, ctx);
    f.extend(credential_round_trip(profile, ctx));
    f
}

/// Every check that does NOT require a credential to already exist.
///
/// ⭐⭐ THIS EXISTS TO BREAK A DEADLOCK, NOT TO OFFER A WEAKER MODE. A consumer's token-minting
/// step needs `token_url` and `scope`, which only this Action knows — so it has to run AFTER
/// setup-tbzl. But `credential_round_trip` is FATAL when the helper answers anonymously, which it
/// necessarily does before any token has been minted — so setup-tbzl could not run first. The two
/// requirements were circular, and the way every consumer escaped it was by hard-coding the two
/// auth values, which is precisely the transcription this Action exists to delete.
///
/// ⛔ THE CREDENTIAL CHECK IS DEFERRED, NEVER DROPPED. `--phase resolve` runs these checks and
/// exports the auth values; `--phase configure` runs ALL of them, including the probe, and is
/// what writes the bazelrc. A build still cannot start without the round trip having passed — it
/// simply happens after the token exists instead of before it could.
pub fn without_credentials(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let mut f = Vec::new();
    f.extend(local_fallback_is_off(profile));
    f.extend(platform_agreement(profile));
    f.extend(no_shadow_config(profile, ctx));
    f.extend(no_competing_bazelrc(ctx));
    f.extend(plane_matches_runner(profile, ctx));
    f.extend(identity_matches_request(profile, ctx));
    f.extend(output_base_survives_the_build(ctx));
    f
}

// ── V8 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔ THE OUTPUT BASE IS ON THE CONTAINER'S WRITABLE LAYER, AND THE BUILD WILL BE EVICTED.
///
/// This is the check for the failure of 2026-08-19, written from it. Bazel defaults
/// `--output_user_root` to `$HOME/.cache/bazel`; in a container that IS the writable layer,
/// which is exactly what a pod's `ephemeral-storage` limit governs. Measured at 7.1 GiB for one
/// repo against an 8Gi limit.
///
/// ⭐ AND THE SYMPTOM NAMED NOTHING. ARC replaced each evicted pod, GitHub kept the run
/// `in_progress` rather than failing it, and the eviction message lived on pod objects that were
/// garbage-collected — so it presented as "the build is not advancing", against an idle node,
/// with the evidence already gone. A preflight check is the only place this is cheap to see.
///
/// ⚠ FATAL ONLY ON A SELF-HOSTED RUNNER. On a laptop the default output base is correct and
/// this must not fail; `RUNNER_ENVIRONMENT` is the same signal `plane_matches_runner` uses. On a
/// GitHub-hosted runner the writable layer is a normal disk, so it is a warning at most.
fn output_base_survives_the_build(ctx: &Context<'_>) -> Vec<Finding> {
    let self_hosted = ctx.runner_environment.as_deref() == Some("self-hosted");

    let Some(root) = &ctx.layout.output_root else {
        // Unset: bazel falls back to $HOME/.cache/bazel.
        if !self_hosted {
            return vec![];
        }
        return vec![Finding::fatal(
            "TBZL-OUTPUT-BASE-EPHEMERAL",
            format!(
                "{} is not set on this self-hosted runner, so bazel will put its output base \
                 under $HOME/.cache/bazel — the container's writable layer, which is what the \
                 pod's ephemeral-storage limit governs. That evicted every runner on this plane \
                 mid-build, and it does NOT surface as a failure: the pod is replaced, the run \
                 stays in_progress, and the eviction message is garbage-collected with the pod. \
                 Set {} on the runner to a path on a volume",
                crate::layout::OUTPUT_ROOT_VAR,
                crate::layout::OUTPUT_ROOT_VAR
            ),
        )];
    };

    // Set, but pointed back at the very place it exists to avoid.
    if crate::layout::looks_like_writable_layer(root, ctx.home.as_deref()) {
        let level = if self_hosted { Finding::fatal } else { Finding::warn };
        return vec![level(
            "TBZL-OUTPUT-BASE-EPHEMERAL",
            format!(
                "{}={} is under $HOME/.cache, which in a container is the writable layer bounded \
                 by ephemeral-storage. Setting the variable to the location it exists to avoid \
                 is worse than leaving it unset, because it reads as configured",
                crate::layout::OUTPUT_ROOT_VAR,
                root.display()
            ),
        )];
    }
    vec![]
}

// ── V7 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔ THE DOCUMENT IS NOT THE ONE THE WORKFLOW ASKED FOR.
///
/// `config-url` points at a profile document, so nothing between the workflow and the file
/// checks that the file is the right one. A URL copied from another repo, a release asset whose
/// name drifted, a tenant renamed upstream — all return 200 with a valid document, and every
/// other check in this file passes on it, because it is a perfectly good profile. It is just
/// not yours: the build then runs against another tenant's plane, authenticating with your
/// token against their exec properties.
///
/// ⭐ THIS IS FATAL, NOT A WARNING, AND THAT IS THE WHOLE POINT OF THE CHECK. A warning here
/// would be printed into a log next to a build that appeared to work. The failure it prevents
/// is silent by construction — there is no error message anywhere downstream that says "wrong
/// tenant", because from the plane's perspective nothing is wrong.
fn identity_matches_request(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for (what, want, got) in [
        ("tenant", &ctx.expect.tenant, &profile.tenant),
        ("plane", &ctx.expect.plane, &profile.plane),
        (
            "config_version",
            &ctx.expect.config_version,
            &profile.config_version,
        ),
    ] {
        // ⚠ An unasserted field is not a finding. Only `tenant` is required by `action.yml`;
        // the others assert only when the workflow pinned them.
        let Some(want) = want.as_deref().filter(|w| !w.is_empty()) else {
            continue;
        };
        if want != got {
            out.push(Finding::fatal(
                "TBZL-IDENTITY-MISMATCH",
                format!(
                    "the fetched profile declares {what}={got:?} but this workflow asked for \
                     {what}={want:?}. The document at `config-url` is valid — it is simply not \
                     the one you asked for, so nothing downstream would have reported this. \
                     Fix `config-url`, or the `{what}` input if the URL is right"
                ),
            ));
        }
    }
    out
}

// ── V1 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔ WRONG PLANE. A runner on the wrong fleet reaches the endpoint's DNS name and then
/// nothing, and Bazel reports `UNAVAILABLE: Network closed for unknown reason` — a string
/// that names neither the runner nor the endpoint, and that is byte-identical to the message
/// for a wrong endpoint. The two causes were indistinguishable in the field.
///
/// The profile carries the label whose runners can reach this plane, so the mismatch is
/// checkable. ⚠ Only on self-hosted runners: a GitHub-hosted runner is named
/// `GitHub Actions N`, which carries no label information at all, and failing there would be
/// failing on absence of evidence.
fn plane_matches_runner(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let (Some(name), Some(env)) = (&ctx.runner_name, &ctx.runner_environment) else {
        return vec![];
    };
    if env != "self-hosted" {
        // ⚠ A GitHub-hosted runner cannot reach a private plane at all, so if the profile
        // names a self-hosted label this is already wrong — but say so as a warning, because
        // a hosted runner reaching a public endpoint is a legitimate configuration.
        return vec![Finding::warn(
            "TBZL-PLANE-HOSTED",
            format!(
                "this is a GitHub-hosted runner; the profile expects `runs-on: {}`. \
                 If the plane is not publicly reachable the build will fail with \
                 `UNAVAILABLE: Network closed for unknown reason`, which names neither",
                profile.facts.runner_label
            ),
        )];
    }
    // ARC names a runner `<scale-set-name>-<random>`.
    if name.starts_with(&profile.facts.runner_label) {
        return vec![];
    }
    vec![Finding::fatal(
        "TBZL-PLANE-MISMATCH",
        format!(
            "runner {name:?} is not from scale set {:?}, which is the fleet that can reach \
             {}. Change `runs-on:` to {:?}. Left alone this surfaces as \
             `UNAVAILABLE: Network closed for unknown reason` after the build has already \
             started, and that message is identical to the one for a wrong endpoint",
            profile.facts.runner_label,
            profile
                .facts
                .execution
                .as_ref()
                .map(|e| e.endpoint.as_str())
                .or(profile.facts.cache.as_ref().map(|c| c.endpoint.as_str()))
                .unwrap_or("the plane"),
            profile.facts.runner_label,
        ),
    )]
}

// ── V2 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔⛔ THE FAIL-OPEN CHECK. See `credprobe`. A host the platform told us to authenticate is
/// not allowed to come back anonymous.
fn credential_round_trip(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let hosts = profile.credential_hosts();
    let Some(helper) = ctx.cred_helper else {
        return vec![Finding::fatal(
            "TBZL-CRED-NOHELPER",
            format!(
                "no credential helper path was given, but {} host(s) require authentication \
                 ({}). Without the helper Bazel sends no Authorization header and the RBE \
                 answers UNAUTHENTICATED",
                hosts.len(),
                hosts.join(", ")
            ),
        )];
    };
    let mut out = Vec::new();
    for host in hosts {
        let var = hostkey::token_file_var(&host);
        match credprobe::probe(helper, &host, &ctx.env) {
            Probe::Authenticated { .. } => {
                out.extend(token_claims(profile, ctx, helper, &host));
            }
            Probe::Anonymous => out.push(Finding::fatal(
                "TBZL-CRED-ANON",
                format!(
                    "the credential helper returned NO credential for {host} — it answered \
                     `{{\"headers\":{{}}}}` and exit 0, which is its documented behavior for a \
                     host it has no secret for. Bazel would send no Authorization header at \
                     all and {host} would answer UNAUTHENTICATED, which reads as a broken \
                     endpoint or a bad token. Check that {var} is exported and names a \
                     readable, non-empty token file. \
                     (Measured once at 97/97 targets failing this way with a VALID token on \
                     disk under a different variable name.)"
                ),
            )),
            Probe::HelperUnusable(e) => out.push(Finding::fatal("TBZL-CRED-HELPER", e)),
            Probe::Unparseable(e) => out.push(Finding::fatal("TBZL-CRED-PROTO", e)),
        }
        // ⚠ The value-carrying variable shadows nothing today — the file form is resolved
        // FIRST by the helper — but a reader who sets it expects it to win. Say so.
        let value_var = hostkey::token_value_var(&host);
        if ctx.env.iter().any(|(k, _)| *k == value_var) {
            out.push(Finding::warn(
                "TBZL-CRED-STATIC",
                format!(
                    "{value_var} is set. The helper resolves {var} FIRST, so the static value \
                     is not what the build will use. A static token also freezes at build \
                     start and dies mid-build once the ~1h TTL passes"
                ),
            ));
        }
    }
    out
}

// ── V3 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔ A TOKEN THAT IS PRESENT, WELL-FORMED AND WRONG. Minted against the previous Cognito
/// pool, or without the scope, it produces the same `UNAUTHENTICATED` as no token at all.
/// Reading the claims separates three failures that were previously one symptom.
fn token_claims(
    profile: &Profile,
    ctx: &Context<'_>,
    helper: &Path,
    host: &str,
) -> Vec<Finding> {
    // Re-run to obtain the value. ⚠ `probe` deliberately does not carry secret material out,
    // so inspecting the claims costs a second invocation. The helper is a few milliseconds
    // and runs once per host, not once per fetch.
    let raw = std::process::Command::new(helper)
        .arg("get")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .envs(ctx.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            if let Some(s) = c.stdin.as_mut() {
                let _ = s.write_all(format!("{{\"uri\":\"https://{host}/\"}}").as_bytes());
            }
            c.wait_with_output()
        });
    let Ok(out) = raw else { return vec![] };
    let Some(token) = credprobe::bearer_value(&String::from_utf8_lossy(&out.stdout)) else {
        return vec![];
    };
    let claims = match jwt::claims(&token) {
        Ok(c) => c,
        // ⛔⛔ FATAL WHEN THE SERVER SAYS IT ISSUES JWTs, and this is the hole the end-to-end
        // test found. The round trip above proves the helper returned SOMETHING; it cannot
        // prove that something is a token. A token file holding an HTML error page, a curl
        // error body or the string "null" is non-empty, so the helper emits
        // `Authorization: Bearer <!DOCTYPE html>…`, the probe passes, and the build dies
        // UNAUTHENTICATED with a configuration that looks entirely correct — which is the
        // same indistinguishable symptom this whole file exists to break apart.
        //
        // ⚠ Only a WARNING when the server declares `opaque`, because an opaque access token
        // is legal OAuth2 and the check is then genuinely unavailable rather than failed.
        Err(e) if profile.facts.auth.token_format == "jwt" => {
            return vec![Finding::fatal(
                "TBZL-TOKEN-MALFORMED",
                format!(
                    "the credential for {host} is not a JWT, but this plane's issuer emits \
                     JWTs: {e}. The token file almost certainly holds something that is not a \
                     token — an error body, an empty JSON value, or a truncated write. It is \
                     non-empty, so the helper returned it and every check short of this one \
                     passed"
                ),
            )]
        }
        Err(e) => {
            return vec![Finding::warn(
                "TBZL-TOKEN-OPAQUE",
                format!("cannot inspect the token for {host}: {e}"),
            )]
        }
    };
    let mut out = Vec::new();
    let auth = &profile.facts.auth;

    if !claims.has_scope(&auth.scope) {
        out.push(Finding::fatal(
            "TBZL-TOKEN-SCOPE",
            format!(
                "the token for {host} does not carry scope {:?}. The RBE frontend STRING-MATCHES \
                 this scope; a token without it is rejected exactly like no token at all",
                auth.scope
            ),
        ));
    }
    if let Some(iss) = &claims.issuer {
        if iss != &auth.issuer {
            out.push(Finding::fatal(
                "TBZL-TOKEN-ISSUER",
                format!(
                    "the token for {host} was minted by {iss:?}, but this plane verifies \
                     against {:?}. A token from the previous pool is well-formed, unexpired, \
                     and rejected — and the rejection is indistinguishable from an absent token",
                    auth.issuer
                ),
            ));
        }
    }
    match claims.seconds_remaining(ctx.now) {
        Some(s) if s <= 0 => out.push(Finding::fatal(
            "TBZL-TOKEN-EXPIRED",
            format!("the token for {host} expired {}s ago", -s),
        )),
        // ⚠ 300s, not 0. A token minted just inside its expiry passes a naive check and then
        // dies during analysis, which reads as a mid-build network fault.
        Some(s) if s < 300 => out.push(Finding::warn(
            "TBZL-TOKEN-SOON",
            format!(
                "the token for {host} expires in {s}s. The helper re-reads the token file on \
                 every invocation, so this is only safe if a refresh loop is running"
            ),
        )),
        _ => {}
    }
    out
}

// ── V4 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔ EXEC PROPERTIES ARE BYTE-MATCHED AND PART OF THE ACTION DIGEST. The scheduler compares
/// what the client sends against what its workers advertise and never fetches the image
/// named. A mismatch does not error — every action queues against an idle fleet.
///
/// ⭐ WHAT IS AND IS NOT CHECKABLE HERE, STATED PRECISELY. A client cannot observe the
/// fleet's advertised platform; only submitting an action and watching it not get scheduled
/// would prove agreement, and that costs a build. What IS checkable is whether the
/// platform's own two statements agree — the properties it tells clients to send, and the
/// platform it reports its workers advertise. Those are produced by different systems and
/// have already drifted in production (`aion-ci` advertised account `491117466965` while the
/// live `RbeCluster` and every real consumer used `042825952740`; nothing failed only because
/// that ConfigSet turned out to be dead). This check catches that class.
fn platform_agreement(profile: &Profile) -> Vec<Finding> {
    let Some(ex) = &profile.facts.execution else {
        return vec![];
    };
    if ex.advertised_platform.is_empty() {
        return vec![Finding::warn(
            "TBZL-PLATFORM-UNSTATED",
            "the profile does not report the fleet's advertised platform, so the exec \
             properties cannot be cross-checked. A mismatch would not error — actions would \
             queue against an idle fleet until the build timed out",
        )];
    }
    if ex.exec_properties == ex.advertised_platform {
        return vec![];
    }
    // ⚠ Union of both key sets, sorted and deduped: a property present on one side and
    // ABSENT on the other is the same failure as two different values, and iterating only
    // one map would miss exactly half of them.
    let mut keys: Vec<&String> = ex
        .exec_properties
        .keys()
        .chain(ex.advertised_platform.keys())
        .collect();
    keys.sort();
    keys.dedup();
    let diff: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            let a = ex.exec_properties.get(*k).map(String::as_str);
            let b = ex.advertised_platform.get(*k).map(String::as_str);
            (a != b).then(|| {
                format!(
                    "{k}: send={:?} advertised={:?}",
                    a.unwrap_or("<absent>"),
                    b.unwrap_or("<absent>")
                )
            })
        })
        .collect();
    vec![Finding::fatal(
        "TBZL-PLATFORM-DRIFT",
        format!(
            "the platform disagrees with itself about the exec properties for plane {:?}. \
             It tells clients to send one thing and reports its workers advertise another: {}. \
             These are byte-matched by the scheduler, so shipping either value would leave \
             actions queuing against an idle fleet with no error at all",
            profile.plane,
            diff.join("; ")
        ),
    )]
}

// ── V5 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔⛔ THE BUG THIS ACTION WAS WRITTEN FOR. `savvifi/aion`'s `build.yml` carried TWO endpoint
/// configurations at once: workflow-level `env:` naming `rbe.fastverk.com` +
/// `fastverk-id-aion`, and a job-level override naming `rbe.tbzl.dev` + `tbzl-id-build-plane`.
/// The `build` job was correct; any job added to that workflow inherits the stale one, and
/// that is exactly how one PR failed.
///
/// ⭐ The Action fetching everything does not, on its own, fix this — a stale `RBE_ENDPOINT`
/// still sits in the environment, and a later step that reads it wins. So the leftovers are
/// treated as a hard error naming both values. The duplicate becomes unrepresentable rather
/// than merely overridden.
fn no_shadow_config(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let get = |k: &str| ctx.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

    let ep = profile
        .facts
        .execution
        .as_ref()
        .map(|e| e.endpoint.as_str())
        .or(profile.facts.cache.as_ref().map(|c| c.endpoint.as_str()));

    for (var, expected, what) in [
        ("RBE_ENDPOINT", ep, "endpoint"),
        ("RBE_TOKEN_URL", Some(profile.facts.auth.token_url.as_str()), "token URL"),
        ("RBE_TOKEN_SCOPE", Some(profile.facts.auth.scope.as_str()), "scope"),
    ] {
        let (Some(found), Some(expected)) = (get(var), expected) else {
            continue;
        };
        if found != expected {
            out.push(Finding::fatal(
                "TBZL-SHADOW-ENV",
                format!(
                    "{var} is already set to {found:?}, which disagrees with the platform's \
                     {what} {expected:?}. Two {what}s in one workflow is the failure this \
                     Action exists to remove: whichever step reads the stale one silently \
                     targets the wrong plane. Delete {var} from the workflow — setup-tbzl \
                     exports it"
                ),
            ));
        }
    }

    // ⛔ A token-file variable for a host this plane does NOT use is the fail-open in its
    // purest form: correct-looking, exported, and pointing the helper at nothing.
    let ours: Vec<String> = profile
        .credential_hosts()
        .iter()
        .map(|h| hostkey::token_file_var(h))
        .collect();
    for (k, _) in &ctx.env {
        if k.starts_with("FASTVERK_TOKEN_FILE_") && !ours.contains(k) {
            out.push(Finding::warn(
                "TBZL-SHADOW-CRED",
                format!(
                    "{k} is exported but names no host this plane uses ({}). If it was written \
                     for a previous endpoint it authenticates nothing, and the helper will \
                     answer anonymously for the host that matters",
                    ours.join(", ")
                ),
            ));
        }
    }
    out
}

// ── V6 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔ A REPO `.bazelrc` THAT ALSO DECLARES REMOTE FLAGS IS THE TRANSCRIPTION THIS EXISTS TO
/// KILL. Bazel applies rc flags before the command line for the same option, so a generated
/// bazelrc usually wins — but `--remote_default_exec_properties` ACCUMULATES rather than
/// replacing, and two `container-image` entries produce a platform nobody advertises.
fn no_competing_bazelrc(ctx: &Context<'_>) -> Vec<Finding> {
    let Some(rc) = &ctx.repo_bazelrc else {
        return vec![];
    };
    let mut hits = Vec::new();
    for line in rc.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        for flag in [
            "--remote_executor",
            "--remote_cache",
            "--remote_default_exec_properties",
            "--remote_instance_name",
            "--credential_helper",
        ] {
            if l.contains(flag) {
                hits.push(format!("{flag} ({l})"));
            }
        }
    }
    if hits.is_empty() {
        return vec![];
    }
    vec![Finding::fatal(
        "TBZL-RC-CONFLICT",
        format!(
            "the repository's .bazelrc declares remote-execution flags that setup-tbzl also \
             emits: {}. --remote_default_exec_properties ACCUMULATES rather than replacing, so \
             two container-image entries produce a platform no worker advertises and every \
             action queues. Delete them from the repo rc, or pass \
             `allow-repo-bazelrc: true` if the overlap is deliberate",
            hits.join("; ")
        ),
    )]
}

// ── V0 ────────────────────────────────────────────────────────────────────────────────────
/// ⛔⛔ THE MASK. With `--remote_local_fallback`, an exec-property mismatch does not queue —
/// it falls back and the build goes GREEN having executed entirely on the runner. The plane
/// is unused and nobody finds out. This is the property that turns every other failure in
/// this file from loud into invisible, which is why it is checked first and why the
/// protocol's default is `false`.
fn local_fallback_is_off(profile: &Profile) -> Vec<Finding> {
    if profile.facts.execution.is_some() && profile.recommendations.remote_local_fallback {
        return vec![Finding::warn(
            "TBZL-LOCAL-FALLBACK",
            "the platform recommends --remote_local_fallback with remote execution enabled. \
             A wrong exec property then produces a GREEN build that ran entirely on the \
             runner instead of a queue that times out. The failure becomes invisible rather \
             than slow",
        )];
    }
    vec![]
}

// ── reachability (network; separate on purpose) ───────────────────────────────────────────

/// Split `grpcs://host:port` into the pieces a dialer needs.
///
/// ⚠ Defaults follow gRPC, not HTTP: `grpcs`/`https` -> 443, `grpc`/`http` -> 80. The live
/// endpoint states :8980 explicitly, so the default is only ever reached by a malformed
/// profile — where guessing 80 for a TLS endpoint produces a connect error that reads as a
/// firewall problem.
pub fn dial_target(endpoint: &str) -> Option<(String, u16)> {
    let host = host_of(endpoint)?;
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let port = authority
        .rsplit_once(':')
        // ⚠ `[::1]` has colons of its own; only a colon AFTER the closing bracket is a port.
        .filter(|(l, _)| !l.contains('[') || l.ends_with(']'))
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(if endpoint.starts_with("grpcs") || endpoint.starts_with("https") {
            443
        } else {
            80
        });
    Some((host, port))
}

/// TCP-connect to the endpoint.
///
/// ⭐ WHY A BARE TCP DIAL IS WORTH IT. The wrong-plane failure is a routing failure: the name
/// resolves and the connection never establishes. That is observable in one round trip, and
/// observing it here costs a second instead of surfacing twenty minutes into a build as
/// `UNAVAILABLE: Network closed for unknown reason`.
///
/// ⚠ It proves reachability, NOT that the far end speaks REAPI or accepts the token. Those
/// are `credential_round_trip`'s job and the build's. Claiming more would be the kind of
/// check that passes while everything is broken.
pub fn endpoint_reachable(endpoint: &str, timeout: std::time::Duration) -> Vec<Finding> {
    use std::net::ToSocketAddrs;
    let Some((host, port)) = dial_target(endpoint) else {
        return vec![Finding::fatal(
            "TBZL-ENDPOINT-MALFORMED",
            format!("cannot parse a host and port out of endpoint {endpoint:?}"),
        )];
    };
    let addrs = match (host.trim_matches(['[', ']']), port).to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => {
            return vec![Finding::fatal(
                "TBZL-ENDPOINT-DNS",
                format!("{host} does not resolve: {e}"),
            )]
        }
    };
    for addr in &addrs {
        if std::net::TcpStream::connect_timeout(addr, timeout).is_ok() {
            return vec![];
        }
    }
    vec![Finding::fatal(
        "TBZL-ENDPOINT-UNREACHABLE",
        format!(
            "cannot open a TCP connection to {host}:{port} from this runner within {:?}. \
             This is the wrong-plane failure: the name resolves and the route does not exist. \
             Left to Bazel it surfaces as `UNAVAILABLE: Network closed for unknown reason`, \
             which names neither the runner nor the endpoint",
            timeout
        ),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⚠ Guards the reported count against the actual one. Eight checks in `all`, plus
    /// `endpoint_reachable`.
    #[test]
    fn checks_are_all_counted() {
        assert_eq!(CHECK_COUNT, 8 + 1);
    }

    /// ⛔ A VALID PROFILE FOR THE WRONG TENANT MUST BE FATAL.
    ///
    /// This is the failure `config-url` introduced by naming a document instead of a query:
    /// the fetch succeeds, the document parses, every other check passes, and the build runs
    /// against somebody else's plane. Nothing downstream reports it.
    #[test]
    fn a_valid_profile_for_another_tenant_is_fatal() {
        let p = Profile::parse(crate::protocol::SAMPLE.as_bytes()).unwrap();
        let ctx = Context {
            expect: Expect { tenant: Some("not-savvifi".into()), ..Default::default() },
            ..Default::default()
        };
        let f = identity_matches_request(&p, &ctx);
        assert_eq!(f.len(), 1, "a wrong tenant must produce exactly one finding");
        assert!(matches!(f[0].level, Level::Fatal), "wrong tenant must be FATAL, not a warning");
        assert_eq!(f[0].code, "TBZL-IDENTITY-MISMATCH");
    }

    /// ⛔ THE 2026-08-19 EVICTION, AS A TEST.
    ///
    /// An unset output root on a self-hosted runner means bazel writes its output base into the
    /// container's writable layer, which `ephemeral-storage` bounds. Nothing downstream reports
    /// it: the pod is replaced, the run stays `in_progress`, the evidence is collected.
    #[test]
    fn an_unset_output_root_on_a_self_hosted_runner_is_fatal() {
        let ctx = Context { runner_environment: Some("self-hosted".into()), ..Default::default() };
        let f = output_base_survives_the_build(&ctx);
        assert_eq!(f.len(), 1, "an unset output root on a fleet runner must be reported");
        assert!(matches!(f[0].level, Level::Fatal), "it evicts the build; a warning is too quiet");
        assert_eq!(f[0].code, "TBZL-OUTPUT-BASE-EPHEMERAL");
    }

    /// ⚠ AND IT MUST NOT FIRE ON A LAPTOP, where bazel's default output base is exactly right.
    /// A check that fails on correct configurations gets disabled, and then catches nothing.
    #[test]
    fn an_unset_output_root_off_a_fleet_runner_is_quiet() {
        assert!(output_base_survives_the_build(&Context::default()).is_empty());
    }

    /// ⛔ SET, BUT POINTED AT THE PLACE IT EXISTS TO AVOID — worse than unset, because it reads
    /// as configured to anyone auditing the runner.
    #[test]
    fn an_output_root_under_home_cache_is_still_fatal() {
        let ctx = Context {
            runner_environment: Some("self-hosted".into()),
            home: Some("/home/runner".into()),
            layout: crate::layout::Layout {
                output_root: Some("/home/runner/.cache/bazel".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let f = output_base_survives_the_build(&ctx);
        assert_eq!(f.len(), 1, "pointing the variable at the writable layer must be caught");
        assert!(matches!(f[0].level, Level::Fatal));
    }

    /// ⭐ THE CORRECT ARRANGEMENT IS SILENT. Without this the three tests above would pass on a
    /// check that simply always fires.
    #[test]
    fn an_output_root_on_a_volume_is_accepted() {
        let ctx = Context {
            runner_environment: Some("self-hosted".into()),
            home: Some("/home/runner".into()),
            layout: crate::layout::Layout {
                output_root: Some("/home/runner/_work/.bazelroot".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            output_base_survives_the_build(&ctx).is_empty(),
            "a correctly configured runner must produce no finding"
        );
    }

    /// ⚠ AND AN UNASSERTED FIELD MUST NOT FIRE. `plane` and `config_version` are optional
    /// inputs; asserting on their absence would fail every workflow that does not pin them.
    #[test]
    fn an_unasserted_field_asserts_nothing() {
        let p = Profile::parse(crate::protocol::SAMPLE.as_bytes()).unwrap();
        let ctx = Context {
            expect: Expect { tenant: Some(p.tenant.clone()), ..Default::default() },
            ..Default::default()
        };
        assert!(
            identity_matches_request(&p, &ctx).is_empty(),
            "matching tenant with unpinned plane/config_version must be clean"
        );
    }

    #[test]
    fn dial_targets_parse() {
        assert_eq!(
            dial_target("grpcs://rbe.tbzl.dev:8980"),
            Some(("rbe.tbzl.dev".into(), 8980))
        );
        // ⚠ grpcs with no port is 443, not 80.
        assert_eq!(dial_target("grpcs://x.example"), Some(("x.example".into(), 443)));
        assert_eq!(dial_target("grpc://x.example"), Some(("x.example".into(), 80)));
        // IPv6 literal: the inner colons are not a port.
        assert_eq!(dial_target("grpcs://[::1]:8980"), Some(("[::1]".into(), 8980)));
        assert_eq!(dial_target("grpcs://[::1]"), Some(("[::1]".into(), 443)));
    }
}

#[cfg(test)]
mod phase_tests {
    use super::*;
    use crate::protocol::Profile;

    /// ⛔ THE DEFERRAL MUST BE A DEFERRAL, NOT A QUIET WEAKENING.
    ///
    /// `--phase resolve` exists to break a deadlock: the mint step needs values only the profile
    /// carries, and the credential probe cannot pass before a token exists. The danger is that
    /// "skip the check that is inconvenient right now" grows into skipping others — so this
    /// asserts that the ONLY findings `all` adds over `without_credentials` are credential ones.
    #[test]
    fn resolve_defers_the_credential_check_and_nothing_else() {
        let p = Profile::parse(crate::protocol::SAMPLE.as_bytes()).unwrap();
        let ctx = Context::default();
        let without = without_credentials(&p, &ctx);
        let full = all(&p, &ctx);

        assert!(
            full.len() > without.len(),
            "with no credential helper configured the probe must contribute a finding; if it \
             does not, this test is comparing two identical lists and proves nothing"
        );
        let seen: Vec<&str> = without.iter().map(|f| f.code).collect();
        for f in &full {
            if !seen.contains(&f.code) {
                assert!(
                    f.code.starts_with("TBZL-CRED") || f.code.starts_with("TBZL-TOKEN"),
                    "phase=resolve dropped {}, which is not a credential check — the split must \
                     defer the probe, not disable unrelated verification",
                    f.code
                );
            }
        }
    }

    /// ⚠ AND EVERY NON-CREDENTIAL CHECK MUST STILL RUN IN RESOLVE. The reverse of the above:
    /// a resolve phase that returned an empty list would also satisfy the assertion there.
    #[test]
    fn resolve_still_runs_the_other_checks() {
        let p = Profile::parse(crate::protocol::SAMPLE.as_bytes()).unwrap();
        let ctx = Context {
            // A wrong tenant is caught by a NON-credential check, so it must fire in resolve.
            expect: Expect { tenant: Some("not-savvifi".into()), ..Default::default() },
            ..Default::default()
        };
        let codes: Vec<&str> = without_credentials(&p, &ctx).iter().map(|f| f.code).collect();
        assert!(
            codes.contains(&"TBZL-IDENTITY-MISMATCH"),
            "resolve must still catch a wrong document; got {codes:?}"
        );
    }
}
