//! Read a bearer token's claims WITHOUT verifying its signature.
//!
//! ⚠ THIS IS NOT AUTHENTICATION AND MUST NEVER BE MISTAKEN FOR IT. The RBE frontend verifies
//! the signature against the pool's JWKS; that is the security boundary and it is somewhere
//! else. What happens here is diagnosis: a token that is structurally fine but was minted
//! against the wrong pool, or for the wrong scope, or an hour ago, produces exactly the same
//! `UNAUTHENTICATED` as no token at all — and this estate has repeatedly spent hours on that
//! ambiguity. Reading the claims locally turns three indistinguishable failures into three
//! different messages.
//!
//! ⛔ THE SCOPE CHECK IS A STRING MATCH BECAUSE THE SERVER'S IS. `fastverk-api/rbe:build` is
//! compared as a literal by the frontend, not parsed as a URI or a scope set. Normalizing it
//! here would make this check disagree with the thing it is predicting.
//!
//! ⚠ NO DEPENDENCY. base64url is thirty lines and a JWT crate would pull a signature stack
//! this binary has no use for — and would invite someone to think verification happens here.

/// The three claims worth checking before a build starts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Claims {
    pub issuer: Option<String>,
    pub scope: Option<String>,
    /// Seconds since the Unix epoch.
    pub expires_at: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JwtError {
    /// Not three dot-separated segments.
    NotAJwt,
    /// The payload segment is not valid base64url, or not valid JSON.
    Undecodable(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // ⚠ An opaque (non-JWT) access token is legal OAuth2. The caller decides whether
            // that is acceptable; this layer only reports that claims are unavailable.
            Self::NotAJwt => write!(f, "token is not a JWT — claims cannot be inspected"),
            Self::Undecodable(e) => write!(f, "token payload is undecodable: {e}"),
        }
    }
}

/// Decode the payload segment. The signature is neither read nor checked.
pub fn claims(token: &str) -> Result<Claims, JwtError> {
    let mut parts = token.split('.');
    let (_h, payload, sig) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) if !h.is_empty() && !p.is_empty() => (h, p, s),
        _ => return Err(JwtError::NotAJwt),
    };
    // ⚠ A fourth segment means JWE, not JWS, and its "payload" is ciphertext. Refuse rather
    // than decode noise into a claim set that reads as plausible.
    if parts.next().is_some() || sig.is_empty() {
        return Err(JwtError::NotAJwt);
    }
    let raw = b64url(payload).ok_or_else(|| JwtError::Undecodable("bad base64url".into()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| JwtError::Undecodable(e.to_string()))?;
    Ok(Claims {
        issuer: v.get("iss").and_then(|s| s.as_str()).map(str::to_string),
        // ⚠ Cognito client-credentials tokens carry `scope` as a SPACE-SEPARATED string, not
        // an array. Handle both: an array shows up on other issuers and silently reading
        // `None` there would disarm the check.
        scope: v.get("scope").and_then(|s| match s {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(a) => Some(
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            _ => None,
        }),
        expires_at: v.get("exp").and_then(|s| s.as_i64()),
    })
}

impl Claims {
    /// Does the token carry the exact scope string the frontend will match?
    ///
    /// ⚠ Split on whitespace and compare whole elements. A substring test would accept
    /// `fastverk-api/rbe:build-preview` as `fastverk-api/rbe:build`.
    pub fn has_scope(&self, want: &str) -> bool {
        self.scope
            .as_deref()
            .is_some_and(|s| s.split_whitespace().any(|c| c == want))
    }

    /// Seconds of validity left at `now`. Negative once expired.
    pub fn seconds_remaining(&self, now: i64) -> Option<i64> {
        self.expires_at.map(|e| e - now)
    }
}

/// base64url decode, padding optional.
fn b64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            // ⚠ Reject rather than skip. Standard-alphabet `+`/`/` here means someone passed
            // plain base64, and silently accepting it would make a real encoding bug look
            // like a claims problem.
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a JWT with the given payload JSON. Signature is a placeholder — nothing here
    /// verifies it, which is the point.
    fn jwt(payload: &str) -> String {
        format!("aGVhZGVy.{}.c2ln", b64url_encode(payload.as_bytes()))
    }

    fn b64url_encode(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            let take = chunk.len() + 1;
            for i in 0..take {
                out.push(A[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn reads_the_three_claims_that_matter() {
        let t = jwt(r#"{"iss":"https://pool","scope":"fastverk-api/rbe:build","exp":2000000000}"#);
        let c = claims(&t).unwrap();
        assert_eq!(c.issuer.as_deref(), Some("https://pool"));
        assert!(c.has_scope("fastverk-api/rbe:build"));
        assert_eq!(c.seconds_remaining(1_999_999_000), Some(1000));
    }

    /// ⛔ THE SCOPE IS STRING-MATCHED BY THE SERVER, so a prefix is not a match.
    #[test]
    fn a_scope_prefix_is_not_the_scope() {
        let t = jwt(r#"{"scope":"fastverk-api/rbe:build-preview"}"#);
        assert!(!claims(&t).unwrap().has_scope("fastverk-api/rbe:build"));
    }

    #[test]
    fn an_array_scope_is_read_too() {
        let t = jwt(r#"{"scope":["a","fastverk-api/rbe:build"]}"#);
        assert!(claims(&t).unwrap().has_scope("fastverk-api/rbe:build"));
    }

    #[test]
    fn an_expired_token_reports_negative_remaining() {
        let t = jwt(r#"{"exp":1000}"#);
        assert_eq!(claims(&t).unwrap().seconds_remaining(2000), Some(-1000));
    }

    #[test]
    fn an_opaque_token_is_reported_not_guessed() {
        assert_eq!(claims("not-a-jwt"), Err(JwtError::NotAJwt));
        assert_eq!(claims("a.b"), Err(JwtError::NotAJwt));
        // JWE — five segments. Its payload is ciphertext, not claims.
        assert_eq!(claims("a.b.c.d.e"), Err(JwtError::NotAJwt));
    }

    #[test]
    fn plain_base64_is_refused_rather_than_half_decoded() {
        assert!(b64url("ab+/").is_none());
    }
}
