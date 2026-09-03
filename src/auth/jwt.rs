//! JWT verification for RS256, ES256 and EdDSA against a JWKS.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::signature;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported alg {0}")]
    Alg(String),
    #[error("no matching key")]
    NoKey,
    #[error("bad signature")]
    Signature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYet,
    #[error("wrong issuer")]
    Issuer,
    #[error("wrong audience")]
    Audience,
    #[error("jti already used")]
    Replay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Audience,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    None,
}

impl Audience {
    fn contains(&self, a: &str) -> bool {
        match self {
            Audience::One(s) => s == a,
            Audience::Many(v) => v.iter().any(|s| s == a),
            Audience::None => false,
        }
    }
}

const LEEWAY: u64 = 60;

/// Verify signature, `exp`/`nbf`, issuer and audience.
pub fn verify(
    token: &str,
    jwks: &Jwks,
    issuer: &str,
    audience: &str,
    now: SystemTime,
) -> Result<Claims, Error> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed);
    };
    let header: Header = serde_json::from_slice(&B64.decode(h).map_err(|_| Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    let sig = B64.decode(s).map_err(|_| Error::Malformed)?;
    let msg = &token.as_bytes()[..h.len() + 1 + p.len()];

    let key = jwks
        .keys
        .iter()
        .filter(|k| header.kid.is_none() || k.kid == header.kid)
        .filter(|k| k.alg.as_deref().is_none_or(|a| a == header.alg))
        .find_map(|k| match verify_sig(&header.alg, k, msg, &sig) {
            Ok(()) => Some(Ok(())),
            Err(Error::NoKey) => None,
            Err(e) => Some(Err(e)),
        })
        .unwrap_or(Err(Error::NoKey));
    key?;
    let claims: Claims = serde_json::from_slice(&B64.decode(p).map_err(|_| Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    check_claims(claims, issuer, audience, now)
}

fn check_claims(
    claims: Claims,
    issuer: &str,
    audience: &str,
    now: SystemTime,
) -> Result<Claims, Error> {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if claims.iss != issuer {
        return Err(Error::Issuer);
    }
    if !claims.aud.contains(audience) {
        return Err(Error::Audience);
    }
    match claims.exp {
        Some(exp) if exp + LEEWAY < now => return Err(Error::Expired),
        None => return Err(Error::Expired),
        _ => {}
    }
    if claims.nbf.is_some_and(|nbf| nbf > now + LEEWAY) {
        return Err(Error::NotYet);
    }
    Ok(claims)
}

fn b64(field: Option<&String>) -> Result<Vec<u8>, Error> {
    B64.decode(field.ok_or(Error::NoKey)?)
        .map_err(|_| Error::Malformed)
}

fn verify_sig(alg: &str, k: &Jwk, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let bad = |_| Error::Signature;
    match (alg, k.kty.as_str()) {
        ("RS256", "RSA") => {
            let pk = signature::RsaPublicKeyComponents {
                n: b64(k.n.as_ref())?,
                e: b64(k.e.as_ref())?,
            };
            pk.verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
                .map_err(bad)
        }
        ("ES256", "EC") if k.crv.as_deref() == Some("P-256") => {
            let mut point = vec![0x04];
            point.extend(b64(k.x.as_ref())?);
            point.extend(b64(k.y.as_ref())?);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(msg, sig)
                .map_err(bad)
        }
        ("EdDSA", "OKP") if k.crv.as_deref() == Some("Ed25519") => {
            signature::UnparsedPublicKey::new(&signature::ED25519, b64(k.x.as_ref())?)
                .verify(msg, sig)
                .map_err(bad)
        }
        ("RS256" | "ES256" | "EdDSA", _) => Err(Error::NoKey),
        (other, _) => Err(Error::Alg(other.into())),
    }
}

/// `oidc:<name>:<sub>` plus `oidc:<name>:<claim>:<value>` for the
/// configured claims; list claims yield one principal per element.
#[must_use]
pub fn principals(name: &str, claims: &Claims, principal_claims: &[String]) -> Vec<String> {
    let mut out = vec![format!("oidc:{name}:{}", claims.sub)];
    for c in principal_claims {
        let Some(v) = claims.extra.get(c) else {
            continue;
        };
        let mut one = |v: &Value| match v {
            Value::String(s) => out.push(format!("oidc:{name}:{c}:{s}")),
            Value::Bool(b) => out.push(format!("oidc:{name}:{c}:{b}")),
            Value::Number(n) => out.push(format!("oidc:{name}:{c}:{n}")),
            _ => {}
        };
        match v {
            Value::Array(items) => items.iter().for_each(&mut one),
            v => one(v),
        }
    }
    out
}

/// Remembers `jti`s until their token expires so each is accepted once
/// per relay process.
#[derive(Default)]
pub struct JtiSet {
    seen: Mutex<HashMap<String, u64>>,
}

impl JtiSet {
    pub fn check(&self, claims: &Claims, now: SystemTime) -> Result<(), Error> {
        let Some(jti) = &claims.jti else {
            return Ok(());
        };
        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut seen = self.seen.lock().expect("poisoned");
        seen.retain(|_, exp| *exp + LEEWAY >= now);
        let key = format!("{}\0{jti}", claims.iss);
        if seen.contains_key(&key) {
            return Err(Error::Replay);
        }
        seen.insert(key, claims.exp.unwrap_or(now + 3600));
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
    };

    pub fn ed25519_issuer() -> (Ed25519KeyPair, Jwks) {
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: Some("k1".into()),
                kty: "OKP".into(),
                alg: None,
                crv: Some("Ed25519".into()),
                x: Some(B64.encode(kp.public_key().as_ref())),
                n: None,
                e: None,
                y: None,
            }],
        };
        (kp, jwks)
    }

    pub fn sign_ed25519(kp: &Ed25519KeyPair, claims: &Value) -> String {
        let h = B64.encode(br#"{"alg":"EdDSA","kid":"k1"}"#);
        let p = B64.encode(serde_json::to_vec(claims).unwrap());
        let msg = format!("{h}.{p}");
        let s = B64.encode(kp.sign(msg.as_bytes()).as_ref());
        format!("{msg}.{s}")
    }

    fn now(secs: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    #[test]
    fn ed25519_happy_and_claim_checks() {
        let (kp, jwks) = ed25519_issuer();
        let claims = serde_json::json!({
            "iss": "https://i", "sub": "repo:x", "aud": ["relay", "other"],
            "exp": 1000, "jti": "a", "groups": ["admin", "dev"], "email": "j@x"
        });
        let tok = sign_ed25519(&kp, &claims);
        let c = verify(&tok, &jwks, "https://i", "relay", now(900)).unwrap();
        assert_eq!(
            principals(
                "n",
                &c,
                &["groups".into(), "email".into(), "missing".into()]
            ),
            [
                "oidc:n:repo:x",
                "oidc:n:groups:admin",
                "oidc:n:groups:dev",
                "oidc:n:email:j@x"
            ]
        );
        assert_eq!(
            verify(&tok, &jwks, "https://i", "relay", now(2000)).unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            verify(&tok, &jwks, "https://x", "relay", now(900)).unwrap_err(),
            Error::Issuer
        );
        assert_eq!(
            verify(&tok, &jwks, "https://i", "nope", now(900)).unwrap_err(),
            Error::Audience
        );
        let mut tampered = tok.clone();
        tampered.push('A');
        assert!(verify(&tampered, &jwks, "https://i", "relay", now(900)).is_err());

        let jti = JtiSet::default();
        jti.check(&c, now(900)).unwrap();
        assert_eq!(jti.check(&c, now(901)).unwrap_err(), Error::Replay);
    }

    #[test]
    fn es256() {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng).unwrap();
        let pk = kp.public_key().as_ref();
        let jwks = Jwks {
            keys: vec![Jwk {
                kid: None,
                kty: "EC".into(),
                alg: Some("ES256".into()),
                crv: Some("P-256".into()),
                x: Some(B64.encode(&pk[1..33])),
                y: Some(B64.encode(&pk[33..65])),
                n: None,
                e: None,
            }],
        };
        let h = B64.encode(br#"{"alg":"ES256"}"#);
        let p = B64.encode(br#"{"iss":"i","sub":"s","aud":"a","exp":100}"#);
        let msg = format!("{h}.{p}");
        let s = B64.encode(kp.sign(&rng, msg.as_bytes()).unwrap().as_ref());
        let tok = format!("{msg}.{s}");
        assert_eq!(verify(&tok, &jwks, "i", "a", now(50)).unwrap().sub, "s");
    }
}
