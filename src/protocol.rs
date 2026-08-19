//! `tbzl.buildconfig/v1` — the wire protocol between a consumer's CI and the build platform.
//!
//! ⭐⭐ THIS FILE IS THE CONTRACT, AND IT IS DELIBERATELY NOT SHAPED LIKE THE THING THAT
//! SERVES IT TODAY. Today a `ConfigSet` custom resource is reconciled by
//! `tbzl-build-operator` against a Buildbarn plane. Tomorrow `roma` serves the same answer
//! from its own knowledge of its own capabilities. If this struct mirrored the CRD, that
//! migration would be a rewrite here *and* a version bump at every consumer. It mirrors
//! neither backend: it is the set of questions a Bazel client has to have answered, and any
//! server that can answer them can serve it.
//!
//! ⭐ TWO VERSIONS MOVE INDEPENDENTLY AND CONFLATING THEM IS THE MISTAKE.
//!
//!   `protocol`        the CONTRACT — the shape of this document. Changes rarely. A major
//!                     this binary does not implement is a HARD FAIL, because guessing at a
//!                     document you do not understand is how you end up sending a config
//!                     nobody asked for.
//!   `config_version`  the RECOMMENDATION — what the platform currently advises. Changes
//!                     often, as tuning learns. It is recorded in the build record and never
//!                     affects compatibility.
//!
//! ⛔ Without that split, raising `--jobs` from 64 to 200 looks like a breaking change, and a
//! genuinely breaking change looks like routine tuning. Both readings are expensive.
//!
//! ⚠ FORWARD COMPATIBILITY IS EXPLICIT, NOT IMPLICIT. Unknown fields are IGNORED (so the
//! server can add an advisory field without stranding every pinned consumer), but the server
//! declares `min_client` when a field is load-bearing. An older binary then fails loudly
//! instead of silently dropping the thing that mattered. `serde(deny_unknown_fields)` would
//! get the second case right and the first case catastrophically wrong.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The protocol family this binary implements. The document's `protocol` must be
/// `tbzl.buildconfig/v1`.
pub const PROTOCOL: &str = "tbzl.buildconfig/v1";

/// This binary's own version, used against the document's `min_client`.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which cache tiers the plane recommends. See `layout` for where they land.
///
/// ⚠ EVERY TIER DEFAULTS TO ON, and that is the safe direction here. A tier enabled with no
/// `TBZL_CACHE_ROOT` configured emits nothing at all — `layout` has no path to give it — so the
/// cost of a wrong `true` is a cold build, while the cost of a wrong `false` is a cold build
/// that looks configured. Neither corrupts anything; the louder failure is the one that still
/// works.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caches {
    /// `--repository_cache`: downloaded archives, content-addressed, many readers.
    #[serde(default = "yes")]
    pub repository: bool,
    /// `--repo_contents_cache` (bazel 9): EXTRACTED repository contents, shareable across
    /// workspaces. ⭐ The tier that took a fresh-pod build from 72s to 19s on this estate.
    #[serde(default = "yes")]
    pub repo_contents: bool,
    /// `--disk_cache`: action outputs.
    ///
    /// ⚠ EARNS LITTLE ALONGSIDE `--remote_executor`, because the RBE's own cache already serves
    /// this role. Kept on by default so a run with remote execution disabled is not
    /// pathologically slow, which is the case it exists for.
    #[serde(default = "yes")]
    pub disk: bool,
}

fn yes() -> bool {
    true
}

impl Default for Caches {
    fn default() -> Self {
        Self { repository: true, repo_contents: true, disk: true }
    }
}

/// One tenant's build configuration, as served by the platform.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// `tbzl.buildconfig/v1`. See the module note on the two versions.
    pub protocol: String,

    /// The platform's versioned recommendation id, e.g. `2026-08-05.1`.
    ///
    /// ⭐ OPAQUE ON PURPOSE. A consumer records it and can bisect against it; it must never be
    /// parsed for meaning, or the format becomes part of the contract by accident.
    pub config_version: String,

    /// Minimum `tbzl-setup` version that understands this document. Optional; semver-ish
    /// `major.minor.patch`, compared numerically.
    #[serde(default)]
    pub min_client: Option<String>,

    pub tenant: String,
    pub plane: String,

    /// ⭐ PLATFORM FACTS — things the server KNOWS. Not tunable, not negotiable, not derivable
    /// by the client. Getting one wrong is an outage, not a slowdown.
    pub facts: Facts,

    /// ⭐ DERIVED RECOMMENDATIONS — things the server COMPUTES from fleet capacity and
    /// measurement. Getting one wrong is a slow build, not a broken one.
    #[serde(default)]
    pub recommendations: Recommendations,
}

/// The half a client cannot work out for itself.
#[derive(Debug, Clone, Deserialize)]
pub struct Facts {
    /// The `runs-on` label whose runners can reach this plane.
    ///
    /// ⛔ WRONG PLANE IS THE FAILURE THIS EXISTS FOR, and its symptom is
    /// `UNAVAILABLE: Network closed for unknown reason` — a string that names neither the
    /// runner nor the endpoint. The Action prints this label so a human comparing it against
    /// their `runs-on:` needs no other evidence.
    pub runner_label: String,

    /// ⭐ OPTIONAL, AND THE OPTIONALITY IS LOAD-BEARING. `roma` is a cache today and an
    /// execution engine later; a protocol that assumes one endpoint answers everything
    /// breaks exactly halfway through that migration. Absent here means "this plane offers
    /// you no remote execution" — which the Action reports LOUDLY rather than treating as a
    /// reason to build locally in silence.
    #[serde(default)]
    pub execution: Option<Execution>,

    /// ⭐ OPTIONAL AND INDEPENDENT of `execution`. Cache-only is a legitimate, complete
    /// answer; so is execution-only.
    #[serde(default)]
    pub cache: Option<Cache>,

    pub auth: Auth,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Execution {
    /// `grpcs://host:port`.
    pub endpoint: String,

    /// What the client must send as `--remote_default_exec_properties`.
    ///
    /// ⛔ BYTE-MATCHED AND PART OF THE ACTION DIGEST. The scheduler string-compares this
    /// against what its workers advertise and NEVER fetches the image it names. A mismatch
    /// is not an error: the scheduler finds no worker whose platform matches and every
    /// action queues against an idle fleet. Measured once on this estate at 426 slots with
    /// ZERO demand, 522 tasks waiting, ~4s actions waiting ~40 minutes.
    ///
    /// ⚠ `BTreeMap` so emission order is deterministic. The properties are sorted into the
    /// action digest anyway, but a stable rendering is what lets two bazelrc files be
    /// diffed.
    pub exec_properties: BTreeMap<String, String>,

    /// ⭐⭐ WHAT THE FLEET ACTUALLY ADVERTISES, read from the live plane by the server.
    ///
    /// This is not redundant with `exec_properties`, and the difference is the entire point.
    /// `exec_properties` is what the platform TELLS clients to send; this is what the
    /// platform's workers SAY they serve. They are produced by different systems and have
    /// already drifted in production: the `aion-ci` ConfigSet advertised account
    /// `491117466965` while the live `RbeCluster` and every real consumer used
    /// `042825952740`. Nothing failed, because the ConfigSet was dead — but the same drift
    /// on a live path strands every action.
    ///
    /// The Action compares them and refuses to run if they disagree. That converts a
    /// server-side inconsistency from a 40-minute queue into a one-second step failure.
    #[serde(default)]
    pub advertised_platform: BTreeMap<String, String>,

    /// REAPI instance name; empty for the default instance.
    ///
    /// ⚠ NOT AN ISOLATION BOUNDARY. Buildbarn routes by PLATFORM, so two tenants with
    /// different instance names share a CAS and share cache entries. Recorded here because
    /// the client has to send it, not because it means anything about tenancy.
    #[serde(default)]
    pub instance_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Cache {
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Auth {
    /// OAuth2 client-credentials token endpoint.
    pub token_url: String,

    /// ⛔ STRING-MATCHED BY THE RBE FRONTEND. Not parsed, not normalized, not treated as a
    /// URI. `fastverk-api/rbe:build` is the live value and it deliberately survived a move
    /// to a different Cognito pool: the pool moved, the vocabulary did not.
    pub scope: String,

    /// Expected `iss` claim. Used to catch a token minted against the WRONG pool — which
    /// today produces an `UNAUTHENTICATED` indistinguishable from no token at all.
    pub issuer: String,

    /// `jwt` (default) or `opaque`.
    ///
    /// ⛔⛔ THIS CLOSES A REAL HOLE, FOUND BY THIS REPOSITORY'S OWN END-TO-END TEST. The
    /// credential round trip proves the helper returned SOMETHING; it cannot prove that
    /// something is a token. A token file holding an HTML error page, a curl error body, or
    /// the string "null" is non-empty, so the helper happily emits
    /// `Authorization: Bearer <!DOCTYPE html>…` and the probe passes. The build then dies
    /// UNAUTHENTICATED with a valid-looking configuration.
    ///
    /// ⚠ An opaque access token is legal OAuth2, so the client cannot simply demand a JWT.
    /// The SERVER knows which it issues, so it says — and when it says `jwt`, a payload that
    /// does not decode is FATAL rather than "claims unavailable".
    #[serde(default = "default_token_format")]
    pub token_format: String,

    /// Hosts beyond the endpoints that also need the credential helper (a registry mirror, a
    /// BES backend).
    ///
    /// ⚠ THE ENDPOINT HOSTS ARE *NOT* LISTED HERE. They are derived by the client from the
    /// endpoints themselves, so the helper's host key and the endpoint it authenticates
    /// cannot be stated twice and cannot disagree. Listing them would reintroduce exactly
    /// the drift this protocol exists to make unrepresentable.
    #[serde(default)]
    pub extra_credential_hosts: Vec<String>,
}

/// ⚠ Defaults to `jwt` rather than `opaque`, i.e. to the STRICTER reading. A profile written
/// before this field existed is served by a Cognito pool, which issues JWTs; defaulting to
/// `opaque` would silently disarm the check for exactly those documents.
fn default_token_format() -> String {
    "jwt".to_string()
}

/// The half the server computes, and the half that is allowed to be wrong.
///
/// ⭐ VERSIONED, NOT PER-BUILD ADAPTIVE. Every field here is a property of
/// `config_version`, identical for every build that resolves it. An autotuner that varied
/// these per run would destroy the only thing that makes tuning possible — comparability
/// between two builds of the same commit — and would make a regression un-bisectable,
/// because the knobs would have moved underneath the bisect.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Recommendations {
    /// ⭐⭐ WHICH CACHE TIERS TO ENABLE — POLICY, AND DELIBERATELY NOT PATHS.
    ///
    /// The plane knows which tiers pay off against it. It does NOT know where a given executor
    /// has disk: `/bazel-cache` is a property of one ARC pod's PVC, not of tbzl-boston. A
    /// profile carrying absolute paths would describe a runner rather than a plane, and would
    /// weld every consumer to one hosted GHA fleet — a Buildkite agent, a laptop or a second
    /// pod shape could not use it. `layout` resolves the paths from the RUNNER instead, via
    /// `TBZL_CACHE_ROOT` / `TBZL_OUTPUT_ROOT`.
    #[serde(default)]
    pub caches: Caches,

    /// Client-side action concurrency.
    ///
    /// ⚠ MEASURED WRONG IN BOTH DIRECTIONS IN ONE DAY on this estate: a 2-core runner's
    /// default of 2 capped REMOTE actions at 2 in flight (90 minutes for 23 of 90 test
    /// suites), and 64 concurrent actions executed LOCALLY on the same 2-core runner
    /// thrashed and OOMed. The right value is a property of where the actions run, which is
    /// a platform fact, which is why it is served rather than guessed.
    #[serde(default)]
    pub jobs: Option<u32>,

    /// Concurrent gRPC connections to the CAS.
    ///
    /// ⭐ THE BANDWIDTH KNOB, AND THE MEASUREMENT SAYS LATENCY IS NOT THE CONSTRAINT. This
    /// estate measured GitHub at 0.46 ms RTT but only 6.3 MB/s per stream, FLAT across four
    /// concurrent streams. Flat is the finding: per-stream throughput did not degrade as
    /// streams were added, so aggregate throughput is linear in connection count over the
    /// measured range and this is the lever that moves input fetch.
    #[serde(default)]
    pub remote_max_connections: Option<u32>,

    #[serde(default)]
    pub remote_timeout_seconds: Option<u32>,

    /// `toplevel` | `minimal` | `all`.
    #[serde(default)]
    pub remote_download: Option<String>,

    /// ⛔⛔ DEFAULTS TO FALSE, AND THAT DEFAULT IS A SAFETY PROPERTY, NOT A PREFERENCE.
    ///
    /// With `--remote_local_fallback` on, an exec-property mismatch does not queue — it
    /// falls back and the build goes GREEN having run entirely on the runner. The plane is
    /// then unused and nobody finds out, because the only symptom is that the build was
    /// slow. Off, the same mismatch is a timeout that names the platform. A silent success
    /// is worse than a loud failure here, and it is worse by a wide margin.
    #[serde(default)]
    pub remote_local_fallback: bool,

    /// Free text: how these numbers were derived. Recorded, never parsed.
    #[serde(default)]
    pub basis: Option<String>,
}

/// Why a document was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    Empty,
    Malformed(String),
    /// The document declares a protocol family this binary does not implement.
    UnsupportedProtocol { found: String },
    /// The document requires a newer client than this binary.
    ClientTooOld { required: String, have: String },
    /// A plane that offers neither execution nor cache configures nothing.
    NoBackend,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "the platform returned an EMPTY build profile. \
                 setup-tbzl does not fall back to defaults — see README, constraint 1"
            ),
            Self::Malformed(e) => write!(f, "the build profile is not valid JSON: {e}"),
            Self::UnsupportedProtocol { found } => write!(
                f,
                "build profile declares protocol {found:?}, this binary implements {PROTOCOL:?}. \
                 Upgrade the pinned setup-tbzl version; do NOT guess at a document you do not understand"
            ),
            Self::ClientTooOld { required, have } => write!(
                f,
                "build profile requires setup-tbzl >= {required}, this is {have}. \
                 The server marked a field load-bearing that this binary would silently ignore"
            ),
            Self::NoBackend => write!(
                f,
                "build profile declares neither `facts.execution` nor `facts.cache` — \
                 there is nothing to configure. A plane that serves neither is a platform \
                 outage, not a reason to build locally"
            ),
        }
    }
}

impl Profile {
    /// Parse and validate a served document.
    ///
    /// ⛔ EVERY FAILURE PATH HERE RETURNS `Err`. There is no salvage mode, no partial parse,
    /// and no default profile. The credential helper this stack already depends on fails
    /// OPEN at four separate layers, and that property has now cost two fleet-wide outages
    /// that were misdiagnosed as unrelated systems. Nothing in this binary may do the same.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(ProtocolError::Empty);
        }
        let p: Profile = serde_json::from_slice(bytes)
            .map_err(|e| ProtocolError::Malformed(e.to_string()))?;

        // ⚠ Compared on the whole string, not on a parsed major. `tbzl.buildconfig/v2` must
        // be refused by a v1 client even though "2" is a perfectly readable integer.
        if p.protocol != PROTOCOL {
            return Err(ProtocolError::UnsupportedProtocol {
                found: p.protocol.clone(),
            });
        }
        if let Some(req) = &p.min_client {
            if version_lt(CLIENT_VERSION, req) {
                return Err(ProtocolError::ClientTooOld {
                    required: req.clone(),
                    have: CLIENT_VERSION.to_string(),
                });
            }
        }
        if p.facts.execution.is_none() && p.facts.cache.is_none() {
            return Err(ProtocolError::NoBackend);
        }
        Ok(p)
    }

    /// Every host that must be reachable through the credential helper.
    ///
    /// ⭐⭐ THE HOSTS ARE DERIVED FROM THE ENDPOINTS, NEVER TRANSCRIBED ALONGSIDE THEM. This
    /// one function is why "the `--credential_helper` host does not match the endpoint" stops
    /// being a thing a workflow can express. The two values now have a single origin.
    pub fn credential_hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        for ep in [
            self.facts.execution.as_ref().map(|e| e.endpoint.as_str()),
            self.facts.cache.as_ref().map(|c| c.endpoint.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(h) = host_of(ep) {
                if !hosts.contains(&h) {
                    hosts.push(h);
                }
            }
        }
        for h in &self.facts.auth.extra_credential_hosts {
            if !hosts.contains(h) {
                hosts.push(h.clone());
            }
        }
        hosts
    }
}

/// Extract the host from `scheme://host:port/path`, dropping scheme, userinfo and port.
///
/// ⚠ Deliberately hand-rolled and deliberately NOT a URL crate. The only inputs are gRPC
/// endpoints this platform itself emits, and a dependency here would be a dependency in the
/// hot path of every build on the plane.
pub fn host_of(endpoint: &str) -> Option<String> {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    // userinfo@host
    let rest = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    // ⚠ IPv6 literals keep their brackets, matching cred-helper's own `host_of`. Diverging
    // would derive a different env var name than the helper looks up — which is the exact
    // fail-open this binary exists to close.
    let host = if let Some(end) = rest.find(']') {
        &rest[..=end]
    } else {
        rest.split(':').next().unwrap_or("")
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// `a < b` over dot-separated numeric versions. Non-numeric components compare as 0.
fn version_lt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-', '+'])
            .map(|c| c.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (a, b) = (parse(a), parse(b));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

/// A minimal valid document, shared by the unit tests across this crate.
///
/// ⚠ Lives at module scope rather than inside `mod tests` so `verify`'s tests can use the same
/// bytes. Two hand-maintained copies of a fixture drift, and the copy that drifts is always the
/// one asserting the thing you care about.
#[cfg(test)]
pub(crate) const SAMPLE: &str = r#"{
          "protocol": "tbzl.buildconfig/v1",
          "config_version": "2026-08-05.1",
          "tenant": "savvifi",
          "plane": "tbzl-build-plane",
          "facts": {
            "runner_label": "tbzl-linux-x64",
            "execution": {
              "endpoint": "grpcs://rbe.tbzl.dev:8980",
              "exec_properties": {"OSFamily": "linux"},
              "advertised_platform": {"OSFamily": "linux"}
            },
            "auth": {
              "token_url": "https://x.example/oauth2/token",
              "scope": "fastverk-api/rbe:build",
              "issuer": "https://issuer.example"
            }
          }
        }"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> String {
        r#"{
          "protocol": "tbzl.buildconfig/v1",
          "config_version": "2026-08-05.1",
          "tenant": "savvifi",
          "plane": "tbzl-build-plane",
          "facts": {
            "runner_label": "tbzl-linux-x64",
            "execution": {
              "endpoint": "grpcs://rbe.tbzl.dev:8980",
              "exec_properties": {"OSFamily": "linux"},
              "advertised_platform": {"OSFamily": "linux"}
            },
            "auth": {
              "token_url": "https://x.example/oauth2/token",
              "scope": "fastverk-api/rbe:build",
              "issuer": "https://issuer.example"
            }
          }
        }"#
        .to_string()
    }

    #[test]
    fn parses_a_minimal_document() {
        let p = Profile::parse(minimal().as_bytes()).expect("valid");
        assert_eq!(p.tenant, "savvifi");
        assert_eq!(p.config_version, "2026-08-05.1");
        // Defaults must be the SAFE values, not the convenient ones.
        assert!(!p.recommendations.remote_local_fallback);
    }

    #[test]
    fn empty_is_refused_rather_than_defaulted() {
        assert_eq!(Profile::parse(b"   \n").unwrap_err(), ProtocolError::Empty);
    }

    #[test]
    fn a_future_protocol_major_is_refused() {
        let doc = minimal().replace("buildconfig/v1", "buildconfig/v2");
        assert!(matches!(
            Profile::parse(doc.as_bytes()),
            Err(ProtocolError::UnsupportedProtocol { .. })
        ));
    }

    #[test]
    fn min_client_refuses_an_old_binary() {
        let doc = minimal().replace(
            r#""config_version""#,
            r#""min_client": "9999.0.0", "config_version""#,
        );
        assert!(matches!(
            Profile::parse(doc.as_bytes()),
            Err(ProtocolError::ClientTooOld { .. })
        ));
    }

    #[test]
    fn unknown_fields_are_tolerated_so_the_server_can_add_advisory_data() {
        let doc = minimal().replace(r#""tenant""#, r#""observability_hint": {"a": 1}, "tenant""#);
        assert!(Profile::parse(doc.as_bytes()).is_ok());
    }

    /// ⭐ THE roma HALFWAY POINT. A cache-only backend must configure a cache and must NOT be
    /// mistaken for "no platform".
    #[test]
    fn a_cache_only_backend_is_a_complete_answer() {
        let doc = r#"{
          "protocol": "tbzl.buildconfig/v1", "config_version": "c", "tenant": "t", "plane": "p",
          "facts": {
            "runner_label": "l",
            "cache": {"endpoint": "grpcs://cache.tbzl.dev:8980"},
            "auth": {"token_url": "https://x/", "scope": "s", "issuer": "i"}
          }
        }"#;
        let p = Profile::parse(doc.as_bytes()).expect("cache-only is valid");
        assert!(p.facts.execution.is_none());
        assert_eq!(p.credential_hosts(), vec!["cache.tbzl.dev"]);
    }

    #[test]
    fn a_backend_that_serves_nothing_is_an_outage_not_a_local_build() {
        let doc = r#"{
          "protocol": "tbzl.buildconfig/v1", "config_version": "c", "tenant": "t", "plane": "p",
          "facts": {"runner_label": "l",
            "auth": {"token_url": "https://x/", "scope": "s", "issuer": "i"}}
        }"#;
        assert_eq!(
            Profile::parse(doc.as_bytes()).unwrap_err(),
            ProtocolError::NoBackend
        );
    }

    #[test]
    fn host_extraction_matches_the_helpers_rules() {
        assert_eq!(host_of("grpcs://rbe.tbzl.dev:8980").as_deref(), Some("rbe.tbzl.dev"));
        assert_eq!(host_of("https://u:p@Host.Example/x").as_deref(), Some("host.example"));
        assert_eq!(host_of("grpcs://[::1]:8980").as_deref(), Some("[::1]"));
        assert_eq!(host_of("").as_deref(), None);
    }

    #[test]
    fn credential_hosts_dedupe_when_cache_and_executor_share_a_host() {
        let doc = minimal().replace(
            r#""auth""#,
            r#""cache": {"endpoint": "grpcs://rbe.tbzl.dev:8980"}, "auth""#,
        );
        let p = Profile::parse(doc.as_bytes()).unwrap();
        assert_eq!(p.credential_hosts(), vec!["rbe.tbzl.dev"]);
    }
}
