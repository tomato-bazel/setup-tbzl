//! ⭐⭐ THE POINT OF THIS REPOSITORY, AS TESTS.
//!
//! Every bug `setup-tbzl` exists to prevent passed a happy-path test. `--credential_helper`
//! keyed to the wrong host, a token file exported under a stale variable name, an
//! exec-property token that no worker advertises, two endpoint configurations in one
//! workflow — each of those shipped, ran, and produced a build. Some produced a GREEN build.
//!
//! So the measure of this suite is NOT that a good configuration is accepted. It is that each
//! specific bad configuration, taken from an incident that actually happened on this estate,
//! now FAILS — and fails with a message that names the cause rather than the symptom.
//!
//! ⚠ `happy_path_is_accepted` is at the bottom, deliberately last and deliberately labelled:
//! on its own it proves almost nothing, and treating it as the important test is the mistake
//! that produced every entry above it.
//!
//! ⭐ THE FAKE HELPER IS A FAITHFUL MODEL, NOT A STUB. It reproduces `cred-helper`'s actual
//! contract, fail-open included: resolve `FASTVERK_TOKEN_FILE_<HOST>`, read the file fresh,
//! and answer `{"headers":{}}` with exit 0 for anything it cannot resolve. A stub that
//! returned an error for an unconfigured host would test a helper that does not exist and
//! would make every test below pass for the wrong reason.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tbzl_setup::protocol::Profile;
use tbzl_setup::verify::{self, Context, Finding, Level};

// ── harness ───────────────────────────────────────────────────────────────────────────────

fn tmpdir(name: &str) -> PathBuf {
    // ⚠ TEST_TMPDIR under Bazel, temp_dir otherwise. Hardcoding /tmp would break the sandbox
    // and hardcoding temp_dir would leak between concurrent test targets.
    let base = std::env::var("TEST_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let d = base.join(format!("setup-tbzl-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write a shell script that behaves like the real `cred-helper`, fail-open and all.
fn fake_cred_helper(dir: &Path) -> PathBuf {
    let p = dir.join("cred-helper");
    // The derivation is the helper's: uppercase, every non-alphanumeric to `_`.
    std::fs::write(
        &p,
        r#"#!/bin/sh
# A faithful model of tomato-bazel/cred-helper, INCLUDING its fail-open.
[ "$1" = "get" ] || { printf '{"headers":{}}\n'; exit 0; }
body=$(cat)
host=$(printf '%s' "$body" | sed -n 's|.*"uri":"[a-z]*://\([^/"]*\).*|\1|p' | sed 's/:[0-9]*$//')
key="FASTVERK_TOKEN_FILE_$(printf '%s' "$host" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')"
path=$(eval printf '%s' "\"\${$key:-}\"")
# ⛔ THE FAIL-OPEN, REPRODUCED EXACTLY. No variable, no file, or an empty file, and the
# helper answers anonymously with exit 0 — no error, no stderr, nothing to notice.
[ -n "$path" ] && [ -s "$path" ] || { printf '{"headers":{}}\n'; exit 0; }
printf '{"headers":{"Authorization":["Bearer %s"]},"expires":"2099-01-01T00:00:00Z"}\n' "$(cat "$path")"
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

/// A JWT with the given issuer, scope and expiry. Signature is a placeholder — nothing under
/// test verifies signatures, and pretending otherwise would be the wrong kind of realism.
fn token(issuer: &str, scope: &str, exp: i64) -> String {
    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for c in data.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for i in 0..c.len() + 1 {
                out.push(A[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
        out
    }
    let payload = format!(r#"{{"iss":"{issuer}","scope":"{scope}","exp":{exp}}}"#);
    format!("aGRy.{}.c2ln", b64(payload.as_bytes()))
}

/// The live plane's real values, so the fixtures are not a parallel universe.
const ENDPOINT: &str = "grpcs://rbe.tbzl.dev:8980";
const OLD_ENDPOINT: &str = "grpcs://rbe.fastverk.com:8980";
const SCOPE: &str = "fastverk-api/rbe:build";
const ISSUER: &str = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_RQcKMlCbB";
const IMAGE: &str =
    "docker://042825952740.dkr.ecr.us-east-1.amazonaws.com/tbzl-rbe-worker:act-22.04-libtinfo5-py3";

struct Doc {
    endpoint: String,
    send_image: String,
    advertised_image: String,
    local_fallback: bool,
}

impl Default for Doc {
    fn default() -> Self {
        Self {
            endpoint: ENDPOINT.into(),
            send_image: IMAGE.into(),
            advertised_image: IMAGE.into(),
            local_fallback: false,
        }
    }
}

impl Doc {
    fn build(&self) -> Profile {
        let json = format!(
            r#"{{
              "protocol": "tbzl.buildconfig/v1",
              "config_version": "2026-08-05.1",
              "tenant": "savvifi", "plane": "tbzl-build-plane",
              "facts": {{
                "runner_label": "tbzl-linux-x64",
                "execution": {{
                  "endpoint": "{}",
                  "exec_properties": {{"OSFamily": "linux", "container-image": "{}"}},
                  "advertised_platform": {{"OSFamily": "linux", "container-image": "{}"}}
                }},
                "auth": {{"token_url": "https://tbzl-id-build-plane.auth.us-east-1.amazoncognito.com/oauth2/token",
                          "scope": "{SCOPE}", "issuer": "{ISSUER}"}}
              }},
              "recommendations": {{"jobs": 200, "remote_max_connections": 200,
                                   "remote_local_fallback": {}}}
            }}"#,
            self.endpoint, self.send_image, self.advertised_image, self.local_fallback
        );
        Profile::parse(json.as_bytes()).expect("fixture must parse")
    }
}

fn ctx<'a>(helper: &'a Path, env: Vec<(&str, String)>) -> Context<'a> {
    Context {
        cred_helper: Some(helper),
        env: env.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        now: 1_800_000_000,
        repo_bazelrc: None,
        runner_name: None,
        runner_environment: None,
    }
}

fn codes(f: &[Finding]) -> Vec<&str> {
    f.iter().map(|x| x.code).collect()
}
fn fatal(f: &[Finding]) -> Vec<&str> {
    f.iter()
        .filter(|x| x.level == Level::Fatal)
        .map(|x| x.code)
        .collect()
}

// ── 1. the credential-helper fail-open, in its three shapes ───────────────────────────────

/// ⭐⭐ THE 97/97 FAILURE, AND WHY IT IS NOW UNREPRESENTABLE RATHER THAN MERELY CAUGHT.
///
/// The original bug: a valid token on disk the whole time, exported under the variable derived
/// from the PREVIOUS endpoint's host. The helper answered anonymously for the host that
/// mattered, Bazel sent no Authorization header, and the RBE said UNAUTHENTICATED — which
/// reads as a broken endpoint or a bad token.
///
/// ⛔ AN EARLIER VERSION OF THIS TEST ASSERTED THE FAILURE WAS *DETECTED*, AND IT WAS WRONG
/// ABOUT THE PRODUCT. `main.rs` derives the variable from the endpoint and injects it into the
/// environment it probes with, so by the time any check runs the correct name is always
/// present. The test passed only because it called `verify::all` directly, bypassing that
/// injection — a test proving something the binary does not do. The repository's own
/// end-to-end CI step caught the discrepancy.
///
/// ⭐ So the real claim is stronger and this is what it asserts: a stale variable CANNOT
/// displace the derived one. The wrong name may be present, and the right name still wins.
#[test]
fn a_stale_helper_variable_cannot_displace_the_derived_one() {
    let d = tmpdir("stale-key");
    let helper = fake_cred_helper(&d);
    let tok = d.join("rbe-token");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();

    let p = Doc::default().build();
    // What the binary derives and exports, before any check runs.
    let rendered = tbzl_setup::render::render(&p, &tok.display().to_string(), "/unused");
    assert!(rendered
        .env
        .iter()
        .any(|(k, _)| k == "FASTVERK_TOKEN_FILE_RBE_TBZL_DEV"));

    // The stale name from the previous endpoint is ALSO present, pointing somewhere useless.
    let mut env: Vec<(&str, String)> = vec![(
        "FASTVERK_TOKEN_FILE_RBE_FASTVERK_COM",
        d.join("nowhere").display().to_string(),
    )];
    let owned: Vec<(String, String)> = rendered.env.clone();
    for (k, v) in &owned {
        env.push((k.as_str(), v.clone()));
    }

    let f = verify::all(&p, &ctx(&helper, env));
    assert!(
        fatal(&f).is_empty(),
        "the derived variable must win over a stale one: {f:?}"
    );
    // ⚠ And the leftover is still reported, because it authenticates nothing and its presence
    // means someone believes it matters.
    assert!(codes(&f).contains(&"TBZL-SHADOW-CRED"), "got {:?}", codes(&f));
}

/// ⛔ THE PROBE ITSELF, IN ISOLATION. This is the mechanism the guarantee rests on: a host the
/// platform said to authenticate answering `{"headers":{}}` is a FATAL finding, not a
/// successful anonymous fetch. Every remaining way to reach that state — a failed mint, a
/// truncated write, a helper that lost its config feature to dead-code elimination — lands
/// here.
#[test]
fn an_anonymous_answer_for_a_host_that_must_authenticate_is_loud() {
    let d = tmpdir("anon");
    let helper = fake_cred_helper(&d);
    // No token variable at all.
    let f = verify::all(&Doc::default().build(), &ctx(&helper, vec![]));
    assert!(fatal(&f).contains(&"TBZL-CRED-ANON"), "got {:?}", codes(&f));
    let msg = &f.iter().find(|x| x.code == "TBZL-CRED-ANON").unwrap().message;
    assert!(
        msg.contains("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV"),
        "the message must name the variable the helper actually wants: {msg}"
    );
}

/// ⛔ THE MINT STEP FAILED AND DID NOT CHECK. The variable is derived correctly and the path
/// it names does not exist. Identical wire behavior to every other miss, identical silence.
/// ⚠ This one is reachable in production, which the stale-name case no longer is: the token
/// path comes from the consumer, the variable name does not.
#[test]
fn a_missing_token_file_is_loud() {
    let d = tmpdir("missing-token");
    let helper = fake_cred_helper(&d);
    let env = vec![(
        "FASTVERK_TOKEN_FILE_RBE_TBZL_DEV",
        d.join("never-written").display().to_string(),
    )];
    assert!(
        fatal(&verify::all(&Doc::default().build(), &ctx(&helper, env)))
            .contains(&"TBZL-CRED-ANON")
    );
}

/// ⛔ The file exists and is zero bytes — a token-minting step that failed and did not check.
/// `[ -s "$path" ]` in the real helper treats it as a miss.
#[test]
fn an_empty_token_file_is_loud() {
    let d = tmpdir("empty-token");
    let helper = fake_cred_helper(&d);
    let tok = d.join("empty");
    std::fs::write(&tok, "").unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    assert!(
        fatal(&verify::all(&Doc::default().build(), &ctx(&helper, env)))
            .contains(&"TBZL-CRED-ANON")
    );
}

/// ⛔⛔ THE HOLE THE END-TO-END TEST FOUND, AND THE REASON A HAPPY-PATH SUITE IS NOT ENOUGH.
///
/// The round trip proves the helper returned SOMETHING. It cannot prove that something is a
/// token. A token file holding an HTML error page, a curl error body, or the literal `null` is
/// NON-EMPTY — so the helper emits `Authorization: Bearer <!DOCTYPE html>…`, the probe passes,
/// and the build dies UNAUTHENTICATED against a configuration that looks entirely correct.
///
/// ⚠ Before `facts.auth.token_format`, this was a WARNING and the step went green.
#[test]
fn a_token_file_holding_something_that_is_not_a_token_is_loud() {
    let d = tmpdir("not-a-token");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    // Exactly what a failed mint leaves behind when nobody checks the HTTP status.
    std::fs::write(&tok, "<!DOCTYPE html><html><body>502 Bad Gateway</body></html>").unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    let f = verify::all(&Doc::default().build(), &ctx(&helper, env));
    assert!(fatal(&f).contains(&"TBZL-TOKEN-MALFORMED"), "got {:?}", codes(&f));
}

/// ⚠ And a plane that genuinely issues opaque tokens must NOT be broken by that check — the
/// claim is unavailable, not failed. Otherwise the fix above would make an entire legitimate
/// issuer unusable.
#[test]
fn an_opaque_token_is_a_warning_when_the_server_says_so() {
    let d = tmpdir("opaque-ok");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, "an-opaque-oauth2-access-token").unwrap();
    let mut p = Doc::default().build();
    p.facts.auth.token_format = "opaque".to_string();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    let f = verify::all(&p, &ctx(&helper, env));
    assert!(fatal(&f).is_empty(), "got {:?}", f);
    assert!(codes(&f).contains(&"TBZL-TOKEN-OPAQUE"));
}

/// ⛔ The helper binary is absent, or is not executable, or was published for the wrong
/// architecture. `cred-helper` publishes no linux-arm64 artifact at all, so this is reachable
/// by simply running on the wrong worker shape.
#[test]
fn an_unusable_helper_binary_is_loud() {
    let d = tmpdir("no-helper");
    let missing = d.join("not-installed");
    let f = verify::all(&Doc::default().build(), &ctx(&missing, vec![]));
    assert!(fatal(&f).contains(&"TBZL-CRED-HELPER"), "got {:?}", codes(&f));
}

// ── 2. the token that is present, well-formed, and wrong ──────────────────────────────────

/// ⛔ THE SCOPE IS STRING-MATCHED. A token minted for a neighboring scope authenticates
/// nothing and is rejected exactly like an absent token.
#[test]
fn a_token_without_the_exact_scope_is_loud() {
    let d = tmpdir("wrong-scope");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, "fastverk-api/rbe:read", 1_900_000_000)).unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    let f = verify::all(&Doc::default().build(), &ctx(&helper, env));
    assert!(fatal(&f).contains(&"TBZL-TOKEN-SCOPE"), "got {:?}", codes(&f));
}

/// ⛔ THE POOL MOVED AND THE VOCABULARY DID NOT. A token from the previous Cognito pool
/// carries the right scope, is unexpired, and is refused — and the refusal is byte-identical
/// to having sent nothing.
#[test]
fn a_token_from_the_previous_pool_is_loud() {
    let d = tmpdir("wrong-issuer");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(
        &tok,
        token(
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OLDPOOL",
            SCOPE,
            1_900_000_000,
        ),
    )
    .unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    let f = verify::all(&Doc::default().build(), &ctx(&helper, env));
    assert!(fatal(&f).contains(&"TBZL-TOKEN-ISSUER"), "got {:?}", codes(&f));
}

/// ⛔ An expired token mid-build took one repo's main branch to 1 green in 25. Catching it
/// before the build starts is the cheap half.
#[test]
fn an_expired_token_is_loud() {
    let d = tmpdir("expired");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_700_000_000)).unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    let f = verify::all(&Doc::default().build(), &ctx(&helper, env));
    assert!(fatal(&f).contains(&"TBZL-TOKEN-EXPIRED"), "got {:?}", codes(&f));
}

// ── 3. the exec property that queues forever ──────────────────────────────────────────────

/// ⛔ THE DRIFT THAT ALREADY HAPPENED. The `aion-ci` ConfigSet advertised account
/// `491117466965` while the live `RbeCluster` and every real consumer used `042825952740`.
/// Nothing failed — only because that ConfigSet turned out to be dead. On a live path the
/// same drift strands every action against an idle fleet with no error at all.
#[test]
fn a_platform_that_disagrees_with_itself_is_loud() {
    let doc = Doc {
        send_image: "docker://491117466965.dkr.ecr.us-east-1.amazonaws.com/tbzl-rbe-worker:act-22.04-libtinfo5-py3".into(),
        advertised_image: IMAGE.into(),
        ..Default::default()
    };
    let d = tmpdir("platform-drift");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];

    let f = verify::all(&doc.build(), &ctx(&helper, env));
    assert!(fatal(&f).contains(&"TBZL-PLATFORM-DRIFT"), "got {:?}", codes(&f));
    let msg = &f
        .iter()
        .find(|x| x.code == "TBZL-PLATFORM-DRIFT")
        .unwrap()
        .message;
    // ⭐ Both account ids must appear. A message that says "mismatch" without the two values
    // sends the reader back to the same two files this check exists to compare for them.
    assert!(msg.contains("491117466965") && msg.contains("042825952740"), "{msg}");
}

/// ⚠ A property present on one side and absent on the other is the same failure. Iterating
/// only the sent map would miss exactly half the drift.
#[test]
fn a_property_missing_from_one_side_is_loud() {
    let mut p = Doc::default().build();
    let ex = p.facts.execution.as_mut().unwrap();
    ex.advertised_platform = BTreeMap::from([("OSFamily".into(), "linux".into())]);
    let d = tmpdir("half-drift");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let f = verify::all(
        &p,
        &ctx(
            &helper,
            vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())],
        ),
    );
    assert!(fatal(&f).contains(&"TBZL-PLATFORM-DRIFT"), "got {:?}", codes(&f));
}

/// ⛔⛔ THE MASK. Local fallback turns the check above from "slow" into "invisible": a wrong
/// exec property no longer queues, the build goes green having run on the runner, and the
/// plane is simply unused.
#[test]
fn recommending_local_fallback_is_reported() {
    let doc = Doc { local_fallback: true, ..Default::default() };
    let d = tmpdir("fallback");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let f = verify::all(
        &doc.build(),
        &ctx(
            &helper,
            vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())],
        ),
    );
    assert!(codes(&f).contains(&"TBZL-LOCAL-FALLBACK"), "got {:?}", codes(&f));
}

// ── 4. two configurations in one workflow ─────────────────────────────────────────────────

/// ⛔⛔ THE LIVE BUG, VERBATIM. `savvifi/aion`'s `.github/workflows/build.yml` carries
/// workflow-level `env:` naming `rbe.fastverk.com` + `fastverk-id-aion` AND a job-level
/// override naming `rbe.tbzl.dev` + `tbzl-id-build-plane`. The `build` job is correct; any
/// job added to that workflow inherits the stale one. That is exactly how one PR failed.
///
/// ⭐ Fetching everything from the platform does not by itself remove this — the stale
/// variable is still in the environment for any step that reads it. So it is a hard error
/// naming both values.
#[test]
fn a_second_endpoint_left_in_the_environment_is_loud() {
    let d = tmpdir("two-endpoints");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();

    let env = vec![
        ("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string()),
        // The workflow-level value that any newly added job would inherit.
        ("RBE_ENDPOINT", OLD_ENDPOINT.to_string()),
        (
            "RBE_TOKEN_URL",
            "https://fastverk-id-aion.auth.us-east-1.amazoncognito.com/oauth2/token".to_string(),
        ),
    ];
    let f = verify::all(&Doc::default().build(), &ctx(&helper, env));
    let shadows: Vec<_> = f.iter().filter(|x| x.code == "TBZL-SHADOW-ENV").collect();
    assert_eq!(
        shadows.len(),
        2,
        "both the stale endpoint and the stale token URL must be reported, got {:?}",
        codes(&f)
    );
    assert!(shadows.iter().all(|x| x.level == Level::Fatal));
    // ⭐ Both values in the message: the reader should not have to open the workflow to see
    // which two things disagree.
    let joined = shadows.iter().map(|x| x.message.clone()).collect::<String>();
    assert!(joined.contains("rbe.fastverk.com") && joined.contains("rbe.tbzl.dev"), "{joined}");
    assert!(joined.contains("fastverk-id-aion") && joined.contains("tbzl-id-build-plane"));
}

/// ⚠ A token-file variable for a host this plane does not use authenticates nothing. It is
/// the residue of a cutover and it looks entirely correct.
#[test]
fn a_leftover_token_variable_for_another_host_is_reported() {
    let d = tmpdir("leftover-cred");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let f = verify::all(
        &Doc::default().build(),
        &ctx(
            &helper,
            vec![
                ("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string()),
                ("FASTVERK_TOKEN_FILE_RBE_FASTVERK_COM", tok.display().to_string()),
            ],
        ),
    );
    assert!(codes(&f).contains(&"TBZL-SHADOW-CRED"), "got {:?}", codes(&f));
}

// ── 5. the repo that also configures itself ───────────────────────────────────────────────

/// ⛔ `--remote_default_exec_properties` ACCUMULATES rather than replacing. A repo `.bazelrc`
/// with its own `build:rbe` block plus a generated rc produces two `container-image` entries
/// and therefore a platform no worker advertises — the queue-forever failure, arrived at from
/// a direction nobody looks.
#[test]
fn a_repo_bazelrc_that_also_declares_remote_flags_is_loud() {
    let d = tmpdir("rc-conflict");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let mut c = ctx(
        &helper,
        vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())],
    );
    // Taken from a real consumer repo's .bazelrc in this estate.
    c.repo_bazelrc = Some(
        "build:rbe --remote_executor=grpcs://rbe.fastverk.com:8980\n\
         build:rbe --remote_default_exec_properties=container-image=docker://old\n\
         # build:rbe --remote_cache=commented-out-does-not-count\n"
            .to_string(),
    );
    let f = verify::all(&Doc::default().build(), &c);
    assert!(fatal(&f).contains(&"TBZL-RC-CONFLICT"), "got {:?}", codes(&f));
    let msg = &f.iter().find(|x| x.code == "TBZL-RC-CONFLICT").unwrap().message;
    assert!(
        !msg.contains("commented-out"),
        "a commented line is not configuration: {msg}"
    );
}

// ── 6. the wrong fleet ────────────────────────────────────────────────────────────────────

/// ⛔ WRONG PLANE. Symptom: `UNAVAILABLE: Network closed for unknown reason` — a string that
/// names neither the runner nor the endpoint, and that is identical to the message for a
/// wrong endpoint. The two causes were indistinguishable in the field.
#[test]
fn a_runner_from_the_wrong_scale_set_is_loud() {
    let d = tmpdir("wrong-plane");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let mut c = ctx(
        &helper,
        vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())],
    );
    c.runner_name = Some("fastverk-linux-x64-abc12".into());
    c.runner_environment = Some("self-hosted".into());
    let f = verify::all(&Doc::default().build(), &c);
    assert!(fatal(&f).contains(&"TBZL-PLANE-MISMATCH"), "got {:?}", codes(&f));
}

/// ⚠ The right scale set must NOT trip it — ARC appends a random suffix to every runner name,
/// so an equality check here would fail every real build.
#[test]
fn the_right_scale_set_passes_despite_the_arc_suffix() {
    let d = tmpdir("right-plane");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let mut c = ctx(
        &helper,
        vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())],
    );
    c.runner_name = Some("tbzl-linux-x64-7fk2q".into());
    c.runner_environment = Some("self-hosted".into());
    let f = verify::all(&Doc::default().build(), &c);
    assert!(!codes(&f).contains(&"TBZL-PLANE-MISMATCH"), "got {:?}", codes(&f));
}

// ── 7. the platform that cannot be reached ────────────────────────────────────────────────

/// ⛔ CONSTRAINT 1, AS A TEST. An unreachable platform must stop the build, not produce a
/// default configuration. A silent fallback would reproduce every failure above at every
/// consumer simultaneously.
#[test]
fn an_unreachable_platform_does_not_produce_a_default_config() {
    // Nothing served: the document is absent.
    assert!(Profile::parse(b"").is_err());
    // Served but empty — an HTTP 200 with a zero-length body, which a naive fetch treats as
    // success.
    assert!(Profile::parse(b"   \n\t ").is_err());
    // Served but truncated mid-document.
    assert!(Profile::parse(br#"{"protocol":"tbzl.buildconfig/v1","con"#).is_err());
    // Served, valid JSON, and an error page rather than a profile.
    assert!(Profile::parse(br#"{"error":"tenant not found"}"#).is_err());
}

/// ⛔ A TCP dial to a port nothing listens on must be fatal, with the endpoint named.
#[test]
fn an_endpoint_that_does_not_accept_connections_is_loud() {
    // Port 1 on loopback: reserved, never bound, and resolves instantly — so this tests the
    // connect failure rather than DNS.
    let f = verify::endpoint_reachable(
        "grpcs://127.0.0.1:1",
        std::time::Duration::from_millis(400),
    );
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].code, "TBZL-ENDPOINT-UNREACHABLE");
    assert!(f[0].message.contains("127.0.0.1:1"), "{}", f[0].message);
}

// ── 8. the control ────────────────────────────────────────────────────────────────────────

/// ⚠ THIS TEST PROVES ALMOST NOTHING ON ITS OWN, and it is last for that reason. Every
/// configuration bug this repository exists to prevent passed a test exactly like it. It is
/// here to catch the opposite failure — a check so eager that no real build could start —
/// which is the only way the suite above becomes worthless.
#[test]
fn happy_path_is_accepted() {
    let d = tmpdir("happy");
    let helper = fake_cred_helper(&d);
    let tok = d.join("t");
    std::fs::write(&tok, token(ISSUER, SCOPE, 1_900_000_000)).unwrap();
    let env = vec![("FASTVERK_TOKEN_FILE_RBE_TBZL_DEV", tok.display().to_string())];
    let f = verify::all(&Doc::default().build(), &ctx(&helper, env));
    assert!(fatal(&f).is_empty(), "a correct config must start: {:?}", f);
}

/// ⭐ And the rendered output of that same configuration is what a build would actually read.
#[test]
fn the_happy_path_renders_a_config_whose_pieces_agree() {
    let p = Doc::default().build();
    let r = tbzl_setup::render::render(&p, "/tmp/rbe-token", "/tmp/cred-helper");

    // The three values that must agree, all derived from one endpoint.
    assert!(r.bazelrc.contains("build --remote_executor=grpcs://rbe.tbzl.dev:8980"));
    assert!(r
        .bazelrc
        .contains("common --credential_helper=rbe.tbzl.dev=/tmp/cred-helper"));
    assert!(r.env.iter().any(|(k, v)| k == "FASTVERK_TOKEN_FILE_RBE_TBZL_DEV"
        && v == "/tmp/rbe-token"));

    // ⭐ And the old endpoint appears NOWHERE — there is no second place for it to live.
    assert!(!r.bazelrc.contains("fastverk.com"));
    assert!(!r.env.iter().any(|(k, _)| k.contains("FASTVERK_COM")));
}
