use std::{io, net::SocketAddr, sync::Arc};

#[cfg(feature = "rt_tokio")]
pub use tokio_rustls::rustls;

#[cfg(feature = "rt_tokio")]
pub use tokio_rustls::{server::TlsStream, TlsAcceptor, TlsConnector};

#[cfg(not(feature = "rt_tokio"))]
pub use futures_rustls::rustls;

#[cfg(not(feature = "rt_tokio"))]
pub use futures_rustls::{server::TlsStream, TlsAcceptor, TlsConnector};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "client")]
use rustls::{client::WantsClientCert, ClientConfig, RootCertStore, WantsVerifier};
#[cfg(feature = "server")]
use rustls::{server::ResolvesServerCert, server::WantsServerCert, ServerConfig};

pub struct CertKey {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl CertKey {
    pub fn from_buf(cert: &mut dyn io::BufRead, key: &mut dyn io::BufRead) -> io::Result<Self> {
        let certs = certs_collected(cert)?;
        if let Some(key) = rustls_pemfile::private_key(key)? {
            Ok(Self {
                cert_chain: certs,
                key,
            })
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Key not found."))
        }
    }
    pub fn from_file<P: AsRef<std::path::Path>>(cert: P, key: P) -> io::Result<Self> {
        CertKey::from_buf(
            &mut io::BufReader::new(&mut std::fs::File::open(cert)?),
            &mut io::BufReader::new(&mut std::fs::File::open(key)?),
        )
    }
}

fn certs_collected(cert: &mut dyn io::BufRead) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(cert)
        .map(|cert_result| cert_result.map_err(|e| e))
        .collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No certificate found.",
        ));
    }
    Ok(certs)
}

#[cfg(feature = "server")]
pub enum ServerCertProvider {
    SingleCert(CertKey),
    SingleCertOCSP(CertKey, Vec<u8>),
    Resolver(Arc<dyn ResolvesServerCert>),
}

#[cfg(feature = "server")]
impl ServerCertProvider {
    fn apply(
        &self,
        config: rustls::ConfigBuilder<ServerConfig, WantsServerCert>,
    ) -> io::Result<ServerConfig> {
        match self {
            ServerCertProvider::SingleCert(cert_key) => {
                match config.with_single_cert(cert_key.cert_chain.clone(), cert_key.key.clone_key())
                {
                    Ok(config) => Ok(config),
                    Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                }
            }
            ServerCertProvider::SingleCertOCSP(_, _) => todo!(),
            ServerCertProvider::Resolver(_) => todo!(),
        }
    }
}

#[cfg(feature = "server")]
pub struct AuthTlsServerProperties {
    pub server_name: &'static str,
    pub server_addr: SocketAddr,
    pub server_cert: ServerCertProvider,
}

#[cfg(feature = "server")]
impl AuthTlsServerProperties {
    pub(crate) fn new_server_config(&self) -> io::Result<ServerConfig> {
        let config = ServerConfig::builder().with_no_client_auth();
        let config = self.server_cert.apply(config)?;

        Ok(config)
    }
}

#[cfg(feature = "client")]
pub struct RootCertStoreProvider {
    pub roots: Arc<RootCertStore>,
}

#[cfg(feature = "client")]
impl RootCertStoreProvider {
    pub fn from_buf(cert: &mut dyn io::BufRead) -> io::Result<Self> {
        let certs = certs_collected(cert)?;
        let mut roots = RootCertStore::empty();
        for cert in certs {
            if let Err(e) = roots.add(cert) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }

        Ok(Self {
            roots: Arc::new(roots),
        })
    }
    pub fn from_file<P: AsRef<std::path::Path>>(cert: P) -> io::Result<Self> {
        RootCertStoreProvider::from_buf(&mut io::BufReader::new(&mut std::fs::File::open(cert)?))
    }

    fn apply(
        &self,
        config: rustls::ConfigBuilder<ClientConfig, WantsVerifier>,
    ) -> rustls::ConfigBuilder<ClientConfig, WantsClientCert> {
        config.with_root_certificates(Arc::clone(&self.roots))
    }
}

#[cfg(feature = "client")]
pub struct AuthTlsClientProperties {
    pub server_name: &'static str,
    pub server_addr: SocketAddr,
    pub root_cert_store: RootCertStoreProvider,
}

#[cfg(feature = "client")]
impl AuthTlsClientProperties {
    pub(crate) fn new_client_config(&self) -> ClientConfig {
        let config = rustls::ClientConfig::builder();
        let config = self.root_cert_store.apply(config).with_no_client_auth();

        config
    }
}
