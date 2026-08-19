//! `tbzl-setup` — autoconfigure a Bazel build for the tbzl remote-execution plane.
//!
//! ⭐⭐ THE ONE DESIGN PROPERTY. Every value a consumer needs is FETCHED FROM THE PLATFORM AT
//! RUNTIME and never transcribed into a workflow. One source of truth, so the endpoint, the
//! token issuer, the scope, the credential-helper host key and the exec-property routing
//! token cannot drift apart — they have a single origin and are derived from each other. The
//! duplicate-endpoint bug that this was written for becomes UNREPRESENTABLE rather than
//! merely fixed.
//!
//! ⛔ THREE NON-NEGOTIABLE CONSTRAINTS, implemented rather than documented:
//!
//!   1. **FAIL LOUD.** Nothing here falls back to a default. The credential helper this stack
//!      depends on fails OPEN at four layers and that property has already cost two
//!      fleet-wide outages misdiagnosed as unrelated systems. An autoconfigure that quietly
//!      substituted defaults would reproduce every failure it exists to prevent, at every
//!      consumer at once. See `protocol::Profile::parse` and every branch in `verify`.
//!   2. **VERSIONED, NOT PER-BUILD ADAPTIVE.** The platform publishes a `config_version`;
//!      every build resolving that version gets identical bytes. An autotuner that varied
//!      settings per run would destroy the comparability that makes tuning possible and make
//!      regressions un-bisectable. See `protocol::Recommendations`.
//!   3. **PUBLIC REPO, REAL SECRET GATE.** `savvifi/aion` is a different org from
//!      `tomato-bazel`, and a private repo's Action cannot be consumed cross-org. Public
//!      means fixtures are published, and a live API key reached a public repo in this estate
//!      within hours of the last time that happened. See `redact` and
//!      `.github/workflows/ci.yml`.
//!
//! ⭐ WHY RUST, AND WHERE THE SPEED ACTUALLY IS. This runs at the head of every job on the
//! plane, so its own cost is pure overhead. A JavaScript action pays a Node boot; a Docker
//! action pays an image pull; a bash action pays `jq`, a subshell per value, and gives up
//! typed errors. A single static musl binary starts in single-digit milliseconds, parses and
//! verifies in well under one, and adds no dependency to the runner image. ⚠ The one network
//! fetch stays in `curl` in `action.yml` — see the note there; that is a deliberate trade,
//! not an oversight.

pub mod credprobe;
pub mod hostkey;
pub mod jwt;
pub mod layout;
pub mod protocol;
pub mod redact;
pub mod render;
pub mod verify;
