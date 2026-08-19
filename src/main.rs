//! `tbzl-setup` — the binary `action.yml` execs.
//!
//! Reads a served build profile, verifies it against the runner it is on, and writes one
//! bazelrc plus the environment the build needs. ⛔ Exits non-zero on any fatal finding and
//! writes NOTHING in that case: a half-written config is worse than none, because it looks
//! like it worked.
//!
//! ```text
//! tbzl-setup configure --profile <file> --out <dir>
//!            [--cred-helper <path>] [--token-file <path>]
//!            [--repo-bazelrc <path>] [--allow-repo-bazelrc]
//!            [--expect-tenant <slug>] [--expect-plane <name>]
//!            [--expect-config-version <ver>]
//!            [--skip-reachability] [--strict]
//! ```
//!
//! ⛔ `--expect-tenant` IS NOT COSMETIC. `--profile` names a file that something else fetched,
//! so this binary is the first place that can notice the file belongs to a different tenant.
//! Such a document is valid, parses, and passes every other check — see `verify::Expect`.
//!
//! ⚠ GITHUB_ENV / GITHUB_OUTPUT are read from the environment, not passed as flags, so the
//! binary behaves identically under `act`, under a local shell, and in CI. When they are
//! absent it prints what it would have written — which is what makes the whole thing
//! debuggable on a laptop.

use std::io::Write;
use std::path::PathBuf;
use tbzl_setup::{layout, protocol::Profile, render, verify};

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // ⚠ `::error::` is the GitHub Actions annotation form: it puts the message on the
            // job summary and on the failing step, rather than only in a log nobody opens.
            eprintln!("::error title=setup-tbzl::{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

struct Args {
    profile: PathBuf,
    out: PathBuf,
    cred_helper: Option<PathBuf>,
    token_file: String,
    repo_bazelrc: Option<PathBuf>,
    allow_repo_bazelrc: bool,
    skip_reachability: bool,
    strict: bool,
    /// What the caller believes it fetched. See `verify::Expect`.
    expect: verify::Expect,
    /// Override `TBZL_CACHE_ROOT` / `TBZL_OUTPUT_ROOT` from the command line.
    cache_root: Option<String>,
    output_root: Option<String>,
    /// Where to write the executor's layout rc. Defaults to `$HOME/.bazelrc`.
    home_bazelrc: Option<PathBuf>,
    /// Skip writing it entirely.
    no_home_bazelrc: bool,
    /// Which half of the job this invocation is. See `Phase`.
    phase: Phase,
}

/// ⭐⭐ THE TWO HALVES, AND WHY THERE ARE TWO.
///
/// A consumer mints its own RBE token, and to do that it needs `token_url` and `scope` — which
/// only the served profile knows. So the mint has to run AFTER this binary. But
/// `credential_round_trip` is fatal when the helper answers anonymously, which it necessarily
/// does before any token has been minted — so this binary could not run before the mint either.
///
/// ⛔ THAT DEADLOCK IS WHY EVERY CONSUMER HARD-CODED THE TWO AUTH VALUES, and they are the worst
/// two to transcribe: the scope is string-matched, so a stale one mints a token that is
/// well-formed, unexpired and REFUSED, and the build dies as UNAUTHENTICATED with a valid token
/// on disk.
///
/// `resolve` fetches the document, runs every check that does not need a credential, and exports
/// the auth values. `configure` runs everything including the probe and writes the bazelrc. The
/// credential check is deferred, never skipped: no build starts without it having passed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Resolve,
    Configure,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        profile: PathBuf::new(),
        out: PathBuf::from("."),
        cred_helper: None,
        token_file: String::new(),
        repo_bazelrc: None,
        allow_repo_bazelrc: false,
        skip_reachability: false,
        strict: false,
        expect: verify::Expect::default(),
        cache_root: None,
        output_root: None,
        home_bazelrc: None,
        no_home_bazelrc: false,
        // ⚠ Configure is the default so an existing single-call consumer is unchanged.
        phase: Phase::Configure,
    };
    let mut it = std::env::args().skip(1);
    // ⚠ The subcommand is required and lenient parsing is deliberately NOT offered. The
    // credential helper accepts any argv and answers `{"headers":{}}`; that leniency is
    // precisely what let a wrong invocation look like a successful one.
    match it.next().as_deref() {
        Some("configure") => {}
        other => return Err(format!("expected subcommand `configure`, got {other:?}")),
    }
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--profile" => a.profile = PathBuf::from(val()?),
            "--out" => a.out = PathBuf::from(val()?),
            "--cred-helper" => a.cred_helper = Some(PathBuf::from(val()?)),
            "--token-file" => a.token_file = val()?,
            "--repo-bazelrc" => a.repo_bazelrc = Some(PathBuf::from(val()?)),
            // ⛔ THE IDENTITY ASSERTIONS. `--profile` names a FILE, so nothing upstream of here
            // has checked that the file is the one the workflow asked for. See
            // `verify::Expect` — a valid profile for another tenant fails no other check.
            "--expect-tenant" => a.expect.tenant = Some(val()?),
            "--expect-plane" => a.expect.plane = Some(val()?),
            "--expect-config-version" => a.expect.config_version = Some(val()?),
            // ⚠ OVERRIDES FOR THE LAYOUT CONVENTION, and they are FLAGS rather than step env
            // for a specific reason: a GitHub Action input that is not supplied renders as the
            // EMPTY STRING, and putting that in the step's `env:` would mask a value the runner
            // itself had set. A flag that is simply absent cannot do that.
            "--cache-root" => a.cache_root = Some(val()?),
            "--output-root" => a.output_root = Some(val()?),
            "--home-bazelrc" => a.home_bazelrc = Some(PathBuf::from(val()?)),
            "--phase" => {
                a.phase = match val()?.as_str() {
                    "resolve" => Phase::Resolve,
                    "configure" => Phase::Configure,
                    // ⚠ No lenient default. A typo'd phase silently becoming `configure` would
                    // run the credential probe before the token exists and fail as an auth
                    // problem, which is the wrong diagnosis for a wrong flag value.
                    other => return Err(format!("--phase must be `resolve` or `configure`, got {other:?}")),
                }
            }
            "--no-home-bazelrc" => a.no_home_bazelrc = true,
            "--allow-repo-bazelrc" => a.allow_repo_bazelrc = true,
            "--skip-reachability" => a.skip_reachability = true,
            "--strict" => a.strict = true,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if a.profile.as_os_str().is_empty() {
        return Err("--profile is required".into());
    }
    Ok(a)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    // ── 1. the document ──────────────────────────────────────────────────────────────────
    // ⛔ A missing profile file is a HARD ERROR, not an empty config. This is the branch that
    // an autoconfigure gets wrong: "the platform was unreachable, so use sensible defaults"
    // reproduces every failure in the README at every consumer simultaneously, and does it
    // silently.
    let bytes = std::fs::read(&args.profile).map_err(|e| {
        format!(
            "cannot read the build profile at {}: {e}. setup-tbzl does NOT fall back to \
             defaults — if the platform cannot be reached, the build must not start",
            args.profile.display()
        )
    })?;
    let profile = Profile::parse(&bytes).map_err(|e| e.to_string())?;

    println!(
        "::notice title=setup-tbzl::tenant={} plane={} config_version={} protocol={}",
        profile.tenant, profile.plane, profile.config_version, profile.protocol
    );

    // ── 2. verification ──────────────────────────────────────────────────────────────────
    let env: Vec<(String, String)> = std::env::vars().collect();

    // ── the executor's storage layout ────────────────────────────────────────────────────
    // ⭐ RESOLVED FROM THE RUNNER, NOT FROM THE PROFILE. The plane says which cache tiers are
    // worth enabling; where this executor has disk is its own property. See `layout`.
    //
    // ⛔ A failure here is fatal and not a fall-back to bazel's defaults: the arrangements
    // `resolve` rejects (a shared output base, a cache under the output base) fail SILENTLY at
    // build time — as slowness, or as `bazel clean` deleting the fleet's cache — so the only
    // place they can be caught is before the build starts.
    // ⚠ A flag beats the runner's environment, and does so by REPLACING the entry rather than
    // being appended — `resolve` reads the first match, so appending would silently lose.
    let mut layout_env = env.clone();
    for (var, over) in [
        (layout::CACHE_ROOT_VAR, &args.cache_root),
        (layout::OUTPUT_ROOT_VAR, &args.output_root),
    ] {
        if let Some(v) = over {
            layout_env.retain(|(n, _)| n != var);
            layout_env.push((var.to_string(), v.clone()));
        }
    }
    let layout = layout::resolve(&layout_env)?;
    for note in &layout.provenance {
        println!("::notice title=setup-tbzl::{note}");
    }
    let cred_helper = args.cred_helper.clone();
    let repo_rc = args
        .repo_bazelrc
        .as_ref()
        .filter(|_| !args.allow_repo_bazelrc)
        .and_then(|p| std::fs::read_to_string(p).ok());

    // ⭐ The env handed to the checks is the env the BUILD will have: the process env, plus
    // the variables about to be exported. Probing under anything else would prove something
    // about this process rather than about the build.
    let rendered = render::render(&profile, &args.token_file, &cred_helper_str(&cred_helper));
    let mut probe_env = env.clone();
    for (k, v) in &rendered.env {
        probe_env.retain(|(n, _)| n != k);
        probe_env.push((k.clone(), v.clone()));
    }

    let ctx = verify::Context {
        cred_helper: cred_helper.as_deref(),
        env: probe_env,
        now: unix_now(),
        repo_bazelrc: repo_rc,
        runner_name: std::env::var("RUNNER_NAME").ok(),
        runner_environment: std::env::var("RUNNER_ENVIRONMENT").ok(),
        expect: args.expect.clone(),
        layout: layout.clone(),
        home: std::env::var("HOME").ok(),
    };

    // ⛔ THE ONLY DIFFERENCE BETWEEN THE PHASES IS *WHEN* THE CREDENTIAL PROBE RUNS, NOT WHETHER.
    // In `resolve` no token exists yet by construction, so probing would fail on the absence of
    // something the next step is about to create — and reporting that as an auth failure would be
    // the wrong diagnosis. Every other check runs in both phases.
    let mut findings = match args.phase {
        Phase::Resolve => verify::without_credentials(&profile, &ctx),
        Phase::Configure => verify::all(&profile, &ctx),
    };

    if !args.skip_reachability {
        // ⚠ 5 seconds. Long enough that a healthy plane never trips it, short enough that a
        // wrong-plane job fails in seconds instead of at the build's timeout.
        let t = std::time::Duration::from_secs(5);
        for ep in [
            profile.facts.execution.as_ref().map(|e| e.endpoint.as_str()),
            profile.facts.cache.as_ref().map(|c| c.endpoint.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            findings.extend(verify::endpoint_reachable(ep, t));
        }
    }

    let mut fatal = 0usize;
    for f in &findings {
        let level = match f.level {
            verify::Level::Fatal => "error",
            // ⚠ `--strict` promotes warnings. Off by default because a warning that cannot be
            // silenced gets ignored, and on in CI for repos that want the tighter contract.
            verify::Level::Warn if args.strict => "error",
            verify::Level::Warn => "warning",
        };
        if level == "error" {
            fatal += 1;
        }
        println!("::{level} title=setup-tbzl {}::{}", f.code, f.message);
    }
    if fatal > 0 {
        // ⛔ NOTHING IS WRITTEN. A bazelrc on disk beside a failed step is the worst outcome:
        // a later step picks it up and the build runs on a configuration that was rejected.
        return Err(format!(
            "{fatal} fatal finding(s) — no configuration was written. \
             Each one above is a failure that would otherwise have been silent"
        ));
    }

    // ── 3. emit ──────────────────────────────────────────────────────────────────────────
    //
    // ⭐ RESOLVE STOPS HERE, AND WRITES NO bazelrc DELIBERATELY. Its whole job is to hand the
    // minting step the two values it cannot otherwise know. Writing a configuration now would
    // mean writing one whose credential round trip has not been checked — a file on disk that
    // looks configured and was never verified, which is the exact failure `configure` refuses to
    // produce on a fatal finding.
    if args.phase == Phase::Resolve {
        append_kv("GITHUB_ENV", &rendered.env)?;
        // ⚠ THE PROFILE PATH IS EXPORTED SO THE SECOND PHASE READS THE SAME BYTES. Re-fetching
        // could return a different document — the platform is free to publish a new
        // config_version mid-job — and a build configured from two different documents is
        // exactly the drift this Action exists to make unrepresentable.
        append_kv(
            "GITHUB_ENV",
            &[("TBZL_PROFILE".to_string(), args.profile.display().to_string())],
        )?;
        append_kv("GITHUB_OUTPUT", &rendered.outputs)?;
        println!(
            "::notice title=setup-tbzl::resolve complete — {} checks run, {} warning(s). \
             RBE_TOKEN_URL and RBE_TOKEN_SCOPE are exported for your minting step; run this \
             Action again with phase=configure once the token file exists",
            verify::CHECK_COUNT - 1,
            findings.len()
        );
        return Ok(());
    }

    std::fs::create_dir_all(&args.out).map_err(|e| format!("cannot create --out: {e}"))?;
    let rc_path = args.out.join("tbzl.bazelrc");
    std::fs::write(&rc_path, &rendered.bazelrc)
        .map_err(|e| format!("cannot write {}: {e}", rc_path.display()))?;

    // ── the executor's layout rc ─────────────────────────────────────────────────────────
    // ⭐ THIS IS WHAT LETS CONSUMERS STOP TRANSCRIBING. bazel reads the home rc on EVERY
    // invocation, so `bazel query` in some later step gets the same output base and caches as
    // the build without the workflow threading anything through.
    if !args.no_home_bazelrc {
        let path = args
            .home_bazelrc
            .clone()
            .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".bazelrc")));
        match path {
            None => println!(
                "::warning title=setup-tbzl::$HOME is unset, so no layout bazelrc was written. \
                 Every bazel invocation will use its own defaults"
            ),
            Some(p) => {
                let body = render::render_home(&layout, &profile.recommendations.caches);
                // ⛔ SPLICE, DO NOT CLOBBER. A GitHub-hosted runner already ships a ~/.bazelrc,
                // and a developer's own is where a --remote_cache line once split an RBE
                // build's two legs. Only the fenced block is ours; everything else survives
                // byte-for-byte, and re-running replaces the block rather than appending.
                let prev = std::fs::read_to_string(&p).unwrap_or_default();
                let next = render::splice_block(&prev, &body)?;
                std::fs::write(&p, &next)
                    .map_err(|e| format!("cannot write {}: {e}", p.display()))?;
                println!(
                    "::notice title=setup-tbzl::updated the setup-tbzl block in {} — every bazel \
                     invocation in this job now shares one output base and the host's caches, \
                     with no per-step flags. {} bytes of pre-existing configuration were left \
                     untouched",
                    p.display(),
                    prev.len()
                );
            }
        }
    }

    append_kv("GITHUB_ENV", &rendered.env)?;
    append_kv(
        "GITHUB_OUTPUT",
        &[
            &rendered.outputs[..],
            &[("bazelrc".to_string(), rc_path.display().to_string())],
        ]
        .concat(),
    )?;
    // ⚠ Exported for the build step. `--bazelrc` is a STARTUP flag: it must come before the
    // command (`bazel --bazelrc=$TBZL_BAZELRC build //...`).
    append_kv(
        "GITHUB_ENV",
        &[("TBZL_BAZELRC".to_string(), rc_path.display().to_string())],
    )?;

    // ⚠ REPORT THE NUMBER OF CHECKS RUN, NOT THE NUMBER OF FINDINGS. An earlier version
    // printed `findings.len()`, so a completely clean configuration announced
    // "(0 checks passed)" — which reads as "nothing was checked", i.e. as exactly the
    // fail-open this binary exists to prevent. A reassuring message that says the opposite of
    // what it means is worse than no message.
    println!(
        "::notice title=setup-tbzl::wrote {} — {} checks run, {} warning(s), no fatal findings",
        rc_path.display(),
        verify::CHECK_COUNT,
        findings.len()
    );
    Ok(())
}

fn cred_helper_str(p: &Option<PathBuf>) -> String {
    p.as_ref()
        .map(|p| p.display().to_string())
        // ⚠ The in-cluster build-runner image bakes the helper here, so it is the right
        // default for a pod. On a GitHub runner `action.yml` always passes --cred-helper
        // explicitly, and `verify` fails loudly if the path does not execute.
        .unwrap_or_else(|| "/usr/local/bin/cred-helper".to_string())
}

/// Append `k=v` pairs to a GitHub Actions file variable, or print them when absent.
///
/// ⚠ Uses the heredoc form for every value, not `k=v`. A bare `k=v` line breaks the moment a
/// value contains a newline, and it does so by silently truncating rather than erroring —
/// which is how a multi-line value becomes a half-value nobody notices.
fn append_kv(var: &str, pairs: &[(String, String)]) -> Result<(), String> {
    let Ok(path) = std::env::var(var) else {
        for (k, v) in pairs {
            println!("[{var}] {k}={v}");
        }
        return Ok(());
    };
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open ${var} ({path}): {e}"))?;
    for (k, v) in pairs {
        let delim = format!("__tbzl_{}__", k.to_ascii_lowercase());
        writeln!(f, "{k}<<{delim}\n{v}\n{delim}")
            .map_err(|e| format!("cannot write ${var}: {e}"))?;
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
