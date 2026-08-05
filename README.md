# setup-tbzl

Name your tenant. The platform decides everything else.

```yaml
jobs:
  build:
    runs-on: tbzl-linux-x64
    steps:
      - uses: actions/checkout@v4
      - uses: tomato-bazel/setup-tbzl@v1
        id: tbzl
        with:
          tenant: savvifi
      - run: bazel --bazelrc=${{ steps.tbzl.outputs.bazelrc }} build //...
```

That is the whole configuration. No endpoint, no token URL, no scope, no
`--credential_helper` host, no exec properties, no `--jobs`.

---

## ⭐ The problem, and why it is not a documentation problem

A consumer of this plane currently has to get **eight** values right, and most of
them are silent when wrong:

| value | what a mistake looks like |
|---|---|
| `runs-on` | ⛔ `UNAVAILABLE: Network closed for unknown reason` |
| `RBE_ENDPOINT` | ⛔ the same string, from a different cause |
| `RBE_TOKEN_URL` / `RBE_TOKEN_SCOPE` | ⛔ `UNAUTHENTICATED`; the scope is **string-matched** |
| `--credential_helper=<HOST>=…` | ⛔ **host-keyed** — the wrong host and the helper is never invoked |
| `FASTVERK_TOKEN_FILE_<HOST>` | ⛔⛔ **fails open** — a stale key means Bazel sends *no header at all* |
| `--remote_default_exec_properties=container-image=…` | ⛔ **byte-matched**, part of the action digest; a mismatch **queues forever**, or goes **green having run locally** |
| `--jobs` | ⚠ measured wrong in **both directions** in one day |

⭐ Four of those produce the same two error strings, and one produces no error at
all. Documentation cannot fix a value whose wrongness is unobservable.

**The live proof.** `savvifi/aion`'s `.github/workflows/build.yml` carries **two
endpoint configurations at once** — workflow-level `env:` naming
`rbe.fastverk.com` + `fastverk-id-aion`, and a job-level override naming
`rbe.tbzl.dev` + `tbzl-id-build-plane`. The `build` job is correct. **Any job
someone adds inherits the stale one.**

---

## ⭐⭐ The design property

**Every value is fetched from the platform at runtime and never transcribed into
the workflow.** One source of truth, so the endpoint, the scope, the
credential-helper host key and the exec-property token *cannot* drift apart —
they are derived from each other in one process.

The duplicate-endpoint bug above becomes **unrepresentable** rather than fixed:
there is nowhere for a second copy to live. And a leftover one in the
environment is a hard error naming both values.

---

## ⛔ Three constraints

### 1. Fail loud

If the platform cannot be reached, **the step fails**. There is no default
profile, no salvage parse, no partial configuration.

This is not caution for its own sake. The credential helper this stack depends
on fails **open at four layers**, every one defaulting to silence, and that
property has already cost two fleet-wide outages that were misdiagnosed as
unrelated systems. An autoconfigure that quietly substituted defaults would
reproduce every failure in the table above, at every consumer, at once.

### 2. Versioned, not per-build adaptive

The platform publishes a `config_version`. Every build resolving that version
gets **identical bytes**. Builds record it.

⛔ An autotuner that varied settings per run would destroy the only thing that
makes tuning possible — comparability between two builds of one commit — and
would make a regression un-bisectable, because the knobs would have moved
underneath the bisect. Changes to the recommendation are deliberate,
attributable and pinnable (`with: config-version:`).

### 3. Public repo, real secret gate

This repository is public because `savvifi/aion` is a **different org** and a
private repo's Action cannot be consumed cross-org.

⛔⛔ And a live BuildBuddy API key was committed into `tomato-bazel/tbzl-profile`
**within hours** of it being made public, extracted from a BEP fixture. The BEP
carries `--remote_header=x-buildbuddy-api-key=…` **nine times across four
events**, and Bazel's JSON writer escapes `=` as `=` — so grepping for
`api-key=` finds nothing.

Two gates, deliberately:

* **`gitleaks`**, a **required status check** (`.gitleaks.toml` adds the
  Bazel-specific and JSON-escaped shapes the default rules do not model), over
  the **full PR history** — a shallow scan misses a secret added and then removed
  on the branch, which stays permanently retrievable.
* **`fixtures_are_scrubbed_test`**, an ordinary `bazel test` that walks the
  working tree for the escaped forms. It caught a real leaked key in this
  repository's own `mask()` test before there was a first commit.

⚠ GitHub's own secret scanning is **not** the gate. The `tomato-bazel` org is on
the Free plan with org-level secret scanning and push protection both
`false`, and its existing public repos report `secret_scanning: disabled`. Push
protection also blocks a *push*, not a *merge*. Enable it as defense in depth;
do not rely on it as the control.

---

## The protocol, not the backend

⭐ The Action speaks `tbzl.buildconfig/v1` — a document, not a Kubernetes object.
Today it is produced from the `ConfigSet` / `CredentialSet` / `RbeCluster` CRDs
the operator already ships. Tomorrow **roma** serves it from its own knowledge of
its own capabilities.

That swap must not touch consumers, so:

* `facts.execution` and `facts.cache` are **independently optional**. roma is a
  cache today and an execution engine later; a protocol assuming one endpoint
  answers everything breaks exactly halfway through the migration.
* `protocol` (the contract) and `config_version` (the recommendation) are
  **separate versions**. Conflating them makes a tuning change look breaking and
  a breaking change look routine.
* Unknown fields are ignored; a server marks a field load-bearing with
  `min_client`, and an older binary then fails **loudly** rather than silently
  dropping it.

The full design, the field-by-field map from the existing CRDs, and the list of
what roma has to implement to take this over: **`tomato-bazel/infra`,
`docs/autoconfigure.md`**.

---

## What is checked, and what each check catches

Every check corresponds to a failure that actually happened on this estate.

| code | catches |
|---|---|
| `TBZL-CRED-ANON` | ⛔⛔ the helper answered `{"headers":{}}` — a failed mint, an empty or absent token file, a helper that lost its config feature. **97/97 targets once failed this way with a valid token on disk.** |
| `TBZL-TOKEN-MALFORMED` | ⛔⛔ a token file holding an HTML error body — **non-empty, so every other check passes** |
| `TBZL-CRED-HELPER` | the helper binary is absent or not executable for this arch |
| `TBZL-TOKEN-SCOPE` | a token without the exact string-matched scope |
| `TBZL-TOKEN-ISSUER` | a token from the previous Cognito pool — well-formed, unexpired, refused |
| `TBZL-TOKEN-EXPIRED` | an already-dead token |
| `TBZL-PLATFORM-DRIFT` | the platform's two statements about exec properties disagree |
| `TBZL-SHADOW-ENV` | ⛔⛔ a second endpoint / token URL / scope left in the environment |
| `TBZL-SHADOW-CRED` | a `FASTVERK_TOKEN_FILE_*` for a host this plane does not use |
| `TBZL-RC-CONFLICT` | the repo's own `.bazelrc` also declares remote flags (they **accumulate**) |
| `TBZL-PLANE-MISMATCH` | the runner is from the wrong scale set |
| `TBZL-ENDPOINT-UNREACHABLE` | the wrong-plane routing failure, in one round trip |
| `TBZL-LOCAL-FALLBACK` | ⛔⛔ the mask that turns every failure above into a green build |

⭐ `tests/loud_failures.rs` is one test per row. **A test that only proves the
happy path is worth very little here** — every bug in the table at the top of
this file passed one.

### ⛔⛔ And a unit test is not enough either — two corrections the CI step forced

**1. A test was wrong about the product, and passed.** It asserted that a token
exported under the *previous* endpoint's variable name is **detected**. It is
not, and should not be: `main.rs` *derives* that name from the endpoint and
injects it before probing, so the correct name is always present. **The stale
name is unrepresentable, not caught.** The test passed only by calling
`verify::all` directly and skipping the injection — a green test describing a
property the code does not have, inside the repository built to prevent exactly
that. Only driving the real binary told the difference.

**2. Correcting it exposed a real hole.** The round trip proves the helper
returned *something*; it cannot prove that something is a **token**. A file
holding an HTML error page is **non-empty**, so the helper emits
`Authorization: Bearer <!DOCTYPE html>…`, the probe passes, and the build dies
`UNAUTHENTICATED` against a configuration that looks entirely correct. It was a
warning and the step went green. `facts.auth.token_format` makes it fatal — the
client cannot demand a JWT (opaque tokens are legal OAuth2), but the **server
knows which it issues**, so it says.

---

## ⛔ What this does **not** solve

Stated plainly, because a half-known gap is worse than a known one.

0. ⏰ **No `tbzl-setup` release is published yet**, so `action.yml` cannot download
   its binary and says so explicitly instead of 404ing. `release.yml` publishes
   immutable `setuptbzl-<sha>` tags on merge to main; pin one there afterwards.
   Until then, build it and set `TBZL_SETUP_BIN`.
1. **`config.tbzl.dev` does not exist.** Nothing is deployed. The Action fetches
   from `inputs.config-url`, which today must point at a file or a release asset.
   The service, and the publisher that renders a `ConfigSet` into this document,
   are designed in `docs/autoconfigure.md` and not built.
2. **No consumer is wired up.** `savvifi/aion` still carries its two endpoint
   configurations. Cutting it over is a separate change.
3. **Exec-property agreement is only checked between the platform's own two
   statements.** A client cannot observe what a fleet advertises; only submitting
   an action and watching it fail to schedule would prove it, and that costs a
   build. What *is* made loud is server-side self-disagreement, and the local
   fallback that would otherwise hide the result.
4. **The credential helper still fails open.** This Action makes the *consequence*
   loud by probing it; it does not fix the helper. A `FASTVERK_CRED_STRICT=1` in
   `tomato-bazel/cred-helper` remains the higher-value fix and is not done here.
5. **`--jobs` and `--remote_max_connections` are analytic, not learned.** They are
   derived from fleet capacity and one measured build. The feedback loop over
   `tbzl-build-records` and `tbzl-fleet-samples` is designed, not built.
6. **`token-file` is still the consumer's job.** Minting the bearer stays in the
   workflow, because the client-credentials secret is the tenant's. The Action
   derives the variable *name* and verifies the result; it does not mint.
7. **No `linux-arm64` credential helper exists upstream**, so an arm64 runner
   fails at the helper install step. `tbzl-setup` itself is built for it.

---

## Development

```console
$ bazel test //... --config=ci --keep_going
```

⛔ **Bazel, never cargo, for anything shipped.** `cargo` resolves the lockfile and
nothing else — a cargo-built binary has a different linkage and glibc floor than
the one consumers download, and the difference surfaces at exec with a message
naming the loader rather than the toolchain.
