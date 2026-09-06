//! rustls configuration from PEM files.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {0}: {1}")]
    Pem(PathBuf, rustls::pki_types::pem::Error),
    #[error("no private key in {0}")]
    NoKey(PathBuf),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    Verifier(#[from] rustls::server::VerifierBuilderError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect)
        .map_err(|e| Error::Pem(path.to_owned(), e))
}

fn key(path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| match e {
        rustls::pki_types::pem::Error::NoItemsFound => Error::NoKey(path.to_owned()),
        e => Error::Pem(path.to_owned(), e),
    })
}

fn roots(ca_files: &[PathBuf]) -> Result<RootCertStore, Error> {
    let mut roots = RootCertStore::empty();
    for f in ca_files {
        for c in certs(f)? {
            roots.add(c)?;
        }
    }
    Ok(roots)
}

/// Server side of the agent listener. Client certificates are requested
/// but optional so bearer-only clients can use the same port.
pub fn server(cert: &Path, key_file: &Path, client_cas: &[PathBuf]) -> Result<ServerConfig, Error> {
    let provider = provider();
    let roots = roots(client_cas)?;
    let verifier = if roots.is_empty() {
        WebPkiClientVerifier::no_client_auth()
    } else {
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .allow_unauthenticated()
            .build()?
    };
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(cert)?, key(key_file)?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Client side for agent and push: `ca_file` pins the relay CA, otherwise
/// WebPKI roots. `identity` presents a client certificate.
pub fn client(
    ca_file: Option<&Path>,
    identity: Option<(&Path, &Path)>,
) -> Result<ClientConfig, Error> {
    let roots = if let Some(f) = ca_file {
        roots(&[f.to_owned()])?
    } else {
        let mut r = RootCertStore::empty();
        r.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        r
    };
    let b = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let cfg = match identity {
        Some((c, k)) => b.with_client_auth_cert(certs(c)?, key(k)?)?,
        None => b.with_no_client_auth(),
    };
    Ok(cfg)
}
