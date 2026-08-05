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
}

/// Run every check that does not need the network.
///
/// ⚠ Reachability is separate (`endpoint_reachable`) because it is the only check that can
/// fail for a reason outside the configuration — a transient network fault — and mixing it in
/// would make the offline suite untestable.
pub fn all(profile: &Profile, ctx: &Context<'_>) -> Vec<Finding> {
    let mut f = Vec::new();
    f.extend(local_fallback_is_off(profile));
    f.extend(platform_agreement(profile));
    f.extend(no_shadow_config(profile, ctx));
    f.extend(no_competing_bazelrc(ctx));
    f.extend(plane_matches_runner(profile, ctx));
    f.extend(credential_round_trip(profile, ctx));
    f
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
        // ⚠ An opaque access token is legal OAuth2, so this is a warning: the check is
        // unavailable, not failed. Cognito issues JWTs, so in practice it means the token
        // file holds something else entirely — an error message, say.
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
