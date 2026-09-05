//! Signed, stateless cookies: the dashboard session and the short-lived
//! login state. The key is random per process, so a relay restart logs
//! everyone out, which is acceptable for a 12 h session.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::hmac;
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub struct Signer(hmac::Key);

impl Default for Signer {
    fn default() -> Self {
        let mut k = [0u8; 32];
        SystemRandom::new().fill(&mut k).expect("rng");
        Self(hmac::Key::new(hmac::HMAC_SHA256, &k))
    }
}

impl Signer {
    #[must_use]
    pub fn seal<T: Serialize>(&self, v: &T) -> String {
        let body = B64.encode(serde_json::to_vec(v).expect("serializable"));
        let tag = hmac::sign(&self.0, body.as_bytes());
        format!("{body}.{}", B64.encode(tag.as_ref()))
    }

    #[must_use]
    pub fn open<T: DeserializeOwned>(&self, s: &str) -> Option<T> {
        let (body, tag) = s.rsplit_once('.')?;
        hmac::verify(&self.0, body.as_bytes(), &B64.decode(tag).ok()?).ok()?;
        serde_json::from_slice(&B64.decode(body).ok()?).ok()
    }
}

#[must_use]
pub fn random() -> String {
    let mut b = [0u8; 32];
    SystemRandom::new().fill(&mut b).expect("rng");
    B64.encode(b)
}

#[must_use]
pub fn cookie<'a>(req: &'a hyper::Request<hyper::body::Incoming>, name: &str) -> Option<&'a str> {
    req.headers()
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(name)?.strip_prefix('='))
}

#[must_use]
pub fn set_cookie(name: &str, value: &str, max_age: u64) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let s = Signer::default();
        let c = s.seal(&vec!["a", "b"]);
        assert_eq!(s.open::<Vec<String>>(&c).unwrap(), ["a", "b"]);
        let mut t = c.clone().into_bytes();
        t[0] ^= 1;
        assert!(
            s.open::<Vec<String>>(std::str::from_utf8(&t).unwrap())
                .is_none()
        );
        assert!(Signer::default().open::<Vec<String>>(&c).is_none());
    }
}
