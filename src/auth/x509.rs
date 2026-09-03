//! Client certificate SANs to principals.

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer as _;

/// One `x509:{dns,email,uri}:<value>` per SAN of the leaf certificate.
#[must_use]
pub fn principals(leaf_der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(leaf_der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::DNSName(d) => Some(format!("x509:dns:{d}")),
            GeneralName::RFC822Name(e) => Some(format!("x509:email:{e}")),
            GeneralName::URI(u) => Some(format!("x509:uri:{u}")),
            _ => None,
        })
        .collect()
}
