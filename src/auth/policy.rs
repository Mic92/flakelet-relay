//! Who may be which agent, and who may deploy which `host/flakelet`.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Rule {
    pub principals: Vec<String>,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Policy {
    /// host id → principals allowed to connect as it
    pub agents: BTreeMap<String, Vec<String>>,
    pub groups: BTreeMap<String, Vec<String>>,
    pub rules: BTreeMap<String, Rule>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostError {
    #[error("no agents entry matches")]
    None,
    #[error("principals match more than one host: {0:?}")]
    Ambiguous(Vec<String>),
}

impl Policy {
    /// The single host these principals may act as.
    pub fn host_for(&self, principals: &[String]) -> Result<&str, HostError> {
        let hits: Vec<&str> = self
            .agents
            .iter()
            .filter(|(_, allowed)| allowed.iter().any(|a| principals.contains(a)))
            .map(|(h, _)| h.as_str())
            .collect();
        match hits.as_slice() {
            [h] => Ok(h),
            [] => Err(HostError::None),
            many => Err(HostError::Ambiguous(
                many.iter().map(|s| (*s).to_owned()).collect(),
            )),
        }
    }

    /// Name of a rule allowing `host/flakelet` for these principals.
    #[must_use]
    pub fn rule_for(&self, principals: &[String], host: &str, flakelet: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|(_, r)| {
                r.principals.iter().any(|p| principals.contains(p))
                    && r.targets
                        .iter()
                        .any(|t| self.target_matches(t, host, flakelet))
            })
            .map(|(n, _)| n.as_str())
    }

    /// Whether any rule of `principals` covers some flakelet on `host`.
    #[must_use]
    pub fn sees_host(&self, principals: &[String], host: &str) -> bool {
        self.rules.values().any(|r| {
            r.principals.iter().any(|p| principals.contains(p))
                && r.targets.iter().any(|t| {
                    t.split_once('/')
                        .is_some_and(|(hp, _)| self.host_matches(hp, host))
                })
        })
    }

    #[must_use]
    pub fn host_matches(&self, pattern: &str, host: &str) -> bool {
        match pattern.strip_prefix('@') {
            Some(g) => self
                .groups
                .get(g)
                .is_some_and(|m| m.iter().any(|m| glob(m, host))),
            None => glob(pattern, host),
        }
    }

    fn target_matches(&self, pattern: &str, host: &str, flakelet: &str) -> bool {
        pattern
            .split_once('/')
            .is_some_and(|(hp, fp)| self.host_matches(hp, host) && glob(fp, flakelet))
    }

    /// Config mistakes worth failing on at load time.
    pub fn validate(&self) -> Result<(), String> {
        for (name, r) in &self.rules {
            for t in &r.targets {
                let Some((hp, fp)) = t.split_once('/') else {
                    return Err(format!("rule {name}: target {t:?} is not host/flakelet"));
                };
                if fp.contains('/') {
                    return Err(format!("rule {name}: target {t:?} has more than one slash"));
                }
                if let Some(g) = hp.strip_prefix('@')
                    && !self.groups.contains_key(g)
                {
                    return Err(format!("rule {name}: unknown group @{g}"));
                }
            }
        }
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for (host, ps) in &self.agents {
            for p in ps {
                if let Some(other) = seen.insert(p, host)
                    && other != host
                {
                    return Err(format!(
                        "principal {p} listed for agents {other} and {host}"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `*` matches any run of characters, everything else is literal.
#[must_use]
pub fn glob(pattern: &str, s: &str) -> bool {
    let Some((head, tail)) = pattern.split_once('*') else {
        return pattern == s;
    };
    let Some(rest) = s.strip_prefix(head) else {
        return false;
    };
    if !tail.contains('*') {
        return rest.ends_with(tail) && rest.len() >= tail.len();
    }
    (0..=rest.len())
        .filter(|i| rest.is_char_boundary(*i))
        .any(|i| glob(tail, &rest[i..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        serde_json::from_value(serde_json::json!({
            "agents": { "eve": ["x509:dns:eve.r"], "eliza": ["x509:dns:eliza.r"], "jamie": ["x509:dns:jamie.r"] },
            "groups": { "tum": ["eliza", "jamie"] },
            "rules": {
                "tribuchet": { "principals": ["oidc:nixbot:repo:github:Mic92/tribuchet:ref:refs/heads/main"],
                               "targets": ["eve/tribuchet-hub", "@tum/tribuchet-worker"] },
                "nixbot": { "principals": ["oidc:nixbot:repo:github:Mic92/nixbot:ref:refs/heads/main"], "targets": ["*/nixbot"] },
                "admin": { "principals": ["x509:email:joerg@thalheim.io"], "targets": ["*/*"] }
            }
        }))
        .unwrap()
    }

    #[test]
    fn globbing() {
        assert!(glob("*", "anything"));
        assert!(glob("a*c", "abc"));
        assert!(glob("a*c", "ac"));
        assert!(!glob("a*c", "acd"));
        assert!(glob("*-worker", "tribuchet-worker"));
        assert!(!glob("eve", "eva"));
        assert!(glob("a*b*c", "aXbYc"));
    }

    #[test]
    fn deploy_rules() {
        let p = policy();
        p.validate().unwrap();
        let trib = vec!["oidc:nixbot:repo:github:Mic92/tribuchet:ref:refs/heads/main".to_owned()];
        assert_eq!(p.rule_for(&trib, "eve", "tribuchet-hub"), Some("tribuchet"));
        assert_eq!(
            p.rule_for(&trib, "eliza", "tribuchet-worker"),
            Some("tribuchet")
        );
        assert_eq!(p.rule_for(&trib, "eve", "nixbot"), None);
        assert_eq!(p.rule_for(&trib, "eva", "tribuchet-worker"), None);
        let admin = vec!["x509:email:joerg@thalheim.io".to_owned()];
        assert_eq!(p.rule_for(&admin, "any", "thing"), Some("admin"));
        assert_eq!(p.rule_for(&[], "eve", "tribuchet-hub"), None);
    }

    #[test]
    fn agent_identity() {
        let mut p = policy();
        assert_eq!(p.host_for(&["x509:dns:eliza.r".into()]), Ok("eliza"));
        assert_eq!(
            p.host_for(&["x509:dns:mallory.r".into()]),
            Err(HostError::None)
        );
        p.agents
            .get_mut("eve")
            .unwrap()
            .push("x509:dns:eliza.r".into());
        assert!(matches!(
            p.host_for(&["x509:dns:eliza.r".into()]),
            Err(HostError::Ambiguous(_))
        ));
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_catches_unknown_group() {
        let mut p = policy();
        p.rules
            .get_mut("admin")
            .unwrap()
            .targets
            .push("@nope/x".into());
        assert!(p.validate().unwrap_err().contains("@nope"));
    }
}
