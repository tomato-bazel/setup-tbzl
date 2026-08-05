//! Keep credentials out of logs and out of fixtures.
//!
//! ⛔⛔ THE TRAP THIS MODULE EXISTS FOR. `tomato-bazel/tbzl-profile` was made public and a
//! LIVE BuildBuddy API key was committed into it within hours, extracted from a Bazel Build
//! Event Protocol fixture. The BEP carries
//!
//! ```text
//! --remote_header=x-buildbuddy-api-key=<key>
//! ```
//!
//! ⚠ The fence is `text`, not bare indentation: rustdoc compiles an indented block as Rust
//! and this one is a command line, so `cargo test --doc` fails on it with an error about
//! `--remote_header` not being an identifier.
//!
//! **nine times across four events** (`unstructuredCommandLine`, `optionsParsed`, and BOTH
//! structured command lines), and **Bazel's JSON writer escapes `=` as `=`** — so
//! `grep 'api-key='` over the raw file finds NOTHING. That is an excellent way to convince
//! yourself a secret is absent when it is present nine times.
//!
//! ⭐ SO THE SCANNER NORMALIZES BEFORE IT MATCHES, and `tests/fixtures_are_scrubbed.rs` runs
//! it over every byte of every fixture in this repository as an ordinary test. A policy that
//! says "scrub your fixtures" is advice; a red test is a gate.
//!
//! ⚠ THIS IS NOT THE MERGE GATE. `.github/workflows/ci.yml` runs `gitleaks` over the full PR
//! history and is a required status check. This module catches the specific shape that
//! defeats a naive grep, in-tree, at the point a fixture is added. Both, deliberately.

/// A secret-shaped pattern that matched.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub pattern: &'static str,
    /// Byte offset in the NORMALIZED text. ⚠ Not the raw offset — the whole point is that the
    /// raw text may have been escaped, so the two do not correspond.
    pub at: usize,
}

/// Credential-bearing keys that appear in Bazel command lines and build events.
///
/// ⚠ AN ALLOWLIST OF SECRET SHAPES IS THE WRONG INSTRUMENT FOR CAPTURE, AND THE RIGHT ONE
/// FOR DETECTION. When deciding what to RECORD, this estate uses an allowlist of flag names,
/// because a denylist fails open the first time Bazel adds a flag nobody thought about. Here
/// the job is the opposite — proving a known-bad shape is absent from a file we control —
/// and for that a denylist of shapes is exactly right. Do not conflate the two.
const SECRET_KEYS: &[&str] = &[
    "x-buildbuddy-api-key",
    "authorization",
    "remote_header",
    "remote_cache_header",
    "remote_exec_header",
    "client_secret",
    "aws_secret_access_key",
    "private_key",
];

/// Undo the escapes that hide a secret from a naive grep, then lowercase.
///
/// ⭐ `=` is the one that mattered. `&` (`&`) and `<`/`>` are included
/// because Go's `encoding/json` — which every controller in this estate uses — escapes those
/// three by default in exactly the same way, for exactly the same HTML-safety reason.
pub fn normalize(text: &str) -> String {
    text.replace("\\u003d", "=")
        .replace("\\u003D", "=")
        .replace("\\u0026", "&")
        .replace("\\u003c", "<")
        .replace("\\u003e", ">")
        .replace("\\\"", "\"")
        .to_ascii_lowercase()
}

/// Find credential-bearing key/value pairs, raw or escaped.
///
/// ⚠ Matches `key=`, `key:` and `key":` — the three shapes a secret takes across a command
/// line, a header and a JSON object. A bare mention of the key with no value following is not
/// a hit, so this file's own documentation does not trip it.
pub fn scan(text: &str) -> Vec<Hit> {
    let n = normalize(text);
    let mut hits = Vec::new();
    for key in SECRET_KEYS {
        let mut from = 0;
        while let Some(i) = n[from..].find(key) {
            let at = from + i;
            let rest = &n[at + key.len()..];
            // The separator, then something that is not immediately whitespace/terminator.
            let sep_len = if rest.starts_with("\":") {
                2
            } else if rest.starts_with('=') || rest.starts_with(':') {
                1
            } else {
                from = at + key.len();
                continue;
            };
            let value = rest[sep_len..].trim_start_matches([' ', '"']);
            let token: String = value
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != ',' && *c != '}')
                .collect();
            // ⚠ A PLACEHOLDER IS NOT A FINDING, AND GETTING THIS SET WRONG IS HOW THE GATE
            // DIES. A scanner that fires on the scrubbed value a fixture is SUPPOSED to
            // contain produces a permanently red test, and a permanently red test gets
            // deleted — at which point the repository has no gate at all. It is a real
            // trade: every marker below is also a string an attacker could put in front of a
            // live key to slip past. That is acceptable here because this test's job is
            // catching an ACCIDENT (a real BEP pasted in whole), and gitleaks in CI is the
            // gate for everything else.
            //
            // ⭐ The `<` and `${` rules are not prefix-only. `--remote_header=
            // x-buildbuddy-api-key=<key>` puts the whole nested pair in the value position of
            // the OUTER key, so a `starts_with` test misses it and the module's own
            // documentation trips its own scanner.
            const PLACEHOLDERS: &[&str] = &[
                "redacted", "example", "xxxx", "fake", "notareal", "placeholder", "dummy",
                "<", "${",
            ];
            // ⭐ THE NESTED FORM: `--remote_header=x-buildbuddy-api-key=<secret>`. The OUTER
            // key's value position holds a HEADER NAME, not a secret — the secret sits one
            // level in, behind the second `=`. Reporting the outer match as well produces two
            // findings for one secret, and worse, it fires on `--remote_header=
            // x-buildbuddy-api-key=REDACTED`, where the scrubbed inner value is correctly
            // ignored but the outer one is not. That is a scanner that cannot be satisfied,
            // and a scanner that cannot be satisfied gets deleted. The inner key is scanned in
            // its own right, so nothing is lost by skipping the wrapper.
            let nested_header = SECRET_KEYS.iter().any(|k2| token.starts_with(k2));
            let placeholder = token.is_empty()
                || token.len() < 8
                || nested_header
                || PLACEHOLDERS.iter().any(|m| token.contains(m));
            if !placeholder {
                hits.push(Hit { pattern: key, at });
            }
            from = at + key.len();
        }
    }
    hits
}

/// Replace credential-bearing values with `REDACTED` for logging.
///
/// ⚠ Operates on the RAW text so the output still reads like the original; `scan` is what
/// normalizes. A redactor that rewrote escapes would produce a log line that does not match
/// what the tool actually saw.
pub fn mask(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let lower = text.to_ascii_lowercase();
    let mut i = 0;
    while i < text.len() {
        let hit = SECRET_KEYS
            .iter()
            .filter_map(|k| lower[i..].find(k).map(|p| (i + p, *k)))
            .min_by_key(|(p, _)| *p);
        let Some((at, key)) = hit else { break };
        let after = at + key.len();
        // Copy through the key and its separator.
        let sep = text[after..]
            .find(|c: char| !matches!(c, '=' | ':' | '"' | ' ' | '\\' | 'u' | '0' | '3' | 'd'))
            .map_or(text.len(), |p| after + p);
        out.push_str(&text[i..sep]);
        let end = text[sep..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '}')
            .map_or(text.len(), |p| sep + p);
        if end > sep {
            out.push_str("REDACTED");
        }
        i = end;
    }
    out.push_str(&text[i.min(text.len())..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ A SECRET-SHAPED VALUE, ASSEMBLED AT RUNTIME. It must not appear as a contiguous
    /// literal anywhere in this repository — `tests/fixtures_are_scrubbed.rs` walks these very
    /// files, and it cannot tell a deliberately planted secret from an accidental one. It
    /// must also avoid every `PLACEHOLDERS` marker, or `scan` would correctly ignore it and
    /// the tests below would pass while proving nothing.
    fn secret_shaped() -> String {
        format!("{}{}{}", "Zk3Qv91", "LmTr8", "Wb2Nc4Jh")
    }

    /// The six characters Bazel's JSON writer emits for `=`.
    ///
    /// ⚠ BUILT BY CONCATENATION, NOT WRITTEN AS A LITERAL. Every editor, formatter and review
    /// tool in the path renders `\u003d` back to `=` given half a chance, and a literal that
    /// quietly un-escapes turns the test below into a test of the RAW form — which already
    /// passes, so nothing would announce the loss.
    fn esc() -> &'static str {
        concat!("\\", "u003d")
    }

    /// ⛔⛔ THE EXACT SHAPE THAT GOT A LIVE KEY INTO A PUBLIC REPOSITORY. A naive grep for
    /// `api-key=` over these bytes returns nothing.
    ///
    /// ⚠ The value is fabricated. Reprinting the real key from the incident to prove a
    /// scanner works would be committing the secret a second time.
    #[test]
    fn the_json_escaped_form_is_caught_where_a_grep_finds_nothing() {
        let (e, k) = (esc(), secret_shaped());
        let bep = format!(
            r#"{{"optionsParsed":{{"cmdLine":["--remote_header{e}x-buildbuddy-api-key{e}{k}"]}}}}"#
        );
        assert!(
            !bep.contains("api-key="),
            "precondition: the raw text must NOT contain the unescaped form, or this test \
             proves nothing"
        );
        let hits = scan(&bep);
        assert!(!hits.is_empty(), "escaped secret must be found");
        // ⭐ Exactly ONE finding, on the INNER key. `--remote_header` wraps it and is not
        // itself a secret; reporting both would double-count and would fire on a properly
        // scrubbed line.
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].pattern, "x-buildbuddy-api-key");
    }

    /// ⭐ And the two forms must produce the SAME findings — the escape is a rendering detail,
    /// not a different secret.
    #[test]
    fn the_raw_form_is_caught_too_and_agrees_with_the_escaped_one() {
        let (e, k) = (esc(), secret_shaped());
        let raw = format!("--remote_header=x-buildbuddy-api-key={k}");
        let escaped = format!("--remote_header{e}x-buildbuddy-api-key{e}{k}");
        assert!(!scan(&raw).is_empty());
        assert_eq!(scan(&raw).len(), scan(&escaped).len());
    }

    /// ⚠ The wrapper is not the secret. A scrubbed inner value must leave NOTHING behind, or
    /// the scanner reports a file that is already clean.
    #[test]
    fn a_scrubbed_nested_header_produces_no_finding_at_all() {
        assert!(scan("--remote_header=x-buildbuddy-api-key=REDACTED").is_empty());
        assert!(scan("--remote_header=x-buildbuddy-api-key=<key>").is_empty());
    }

    #[test]
    fn scrubbed_placeholders_are_not_findings() {
        assert!(scan(r#"--remote_header=x-buildbuddy-api-key=REDACTED"#).is_empty());
        assert!(scan(r#"{"authorization": "Bearer <redacted>"}"#).is_empty());
        assert!(scan(r#"client_secret=${{ secrets.X }}"#).is_empty());
        // This module's own prose mentions the keys with no value after them.
        assert!(scan("the BEP carries x-buildbuddy-api-key nine times").is_empty());
    }

    #[test]
    fn masking_removes_the_value_and_keeps_the_shape() {
        // ⛔ THIS TEST ORIGINALLY CARRIED THE REAL KEY FROM THE INCIDENT, PASTED IN TO BE
        // REALISTIC, AND `no_fixture_or_source_file_carries_a_credential` CAUGHT IT. Left in,
        // this file would have shipped the leaked credential into a second public repository
        // — inside the module whose entire purpose is preventing that. The gate earned its
        // place before the repository had a first commit.
        let k = secret_shaped();
        let m = mask(&format!("--remote_header=x-buildbuddy-api-key={k} --jobs=64"));
        assert!(!m.contains(&k), "the secret must not survive masking: {m}");
        assert!(m.contains("--jobs=64"), "non-secret flags survive: {m}");
    }
}
