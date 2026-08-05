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
//!            [--skip-reachability] [--strict]
//! ```
//!
//! ⚠ GITHUB_ENV / GITHUB_OUTPUT are read from the environment, not passed as flags, so the
//! binary behaves identically under `act`, under a local shell, and in CI. When they are
//! absent it prints what it would have written — which is what makes the whole thing
//! debuggable on a laptop.

use std::io::Write;
use std::path::PathBuf;
use tbzl_setup::{protocol::Profile, render, verify};

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
    };

    let mut findings = verify::all(&profile, &ctx);

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
    std::fs::create_dir_all(&args.out).map_err(|e| format!("cannot create --out: {e}"))?;
    let rc_path = args.out.join("tbzl.bazelrc");
    std::fs::write(&rc_path, &rendered.bazelrc)
        .map_err(|e| format!("cannot write {}: {e}", rc_path.display()))?;

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

    println!(
        "::notice title=setup-tbzl::wrote {} ({} checks passed)",
        rc_path.display(),
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
