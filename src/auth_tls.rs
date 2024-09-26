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

/// Wrapper to store the certificate chain and key.
pub struct CertKey {
    /// Certificates.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Key.
    pub key: PrivateKeyDer<'static>,
}

impl CertKey {
    /// Loads certificates and key from buf.
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

    /// Loads certificates and key from files.
    /// # Examples
    /// ```rust,no_run
    /// let cert_key = CertKey::from_file(
    ///     "certificates/server_cert.pem",
    ///     "certificates/server_key.pem",
    /// );
    /// ```
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

/// Certificates providers options.
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
            ServerCertProvider::SingleCertOCSP(cert_key, ocsp) => {
                match config.with_single_cert_with_ocsp(
                    cert_key.cert_chain.clone(),
                    cert_key.key.clone_key(),
                    ocsp.clone(),
                ) {
                    Ok(config) => Ok(config),
                    Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                }
            }
            ServerCertProvider::Resolver(cert_resolver) => {
                Ok(config.with_cert_resolver(Arc::clone(&cert_resolver)))
            }
        }
    }
}

/// Properties to bind a server with Tls authenticator.
#[cfg(feature = "server")]
pub struct AuthTlsServerProperties {
    /// Dns name of the server.
    pub server_name: &'static str,
    /// Addr to bind the Tcp socket.
    pub server_addr: SocketAddr,
    /// Certificate provider.
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

/// Root certificate provider.
#[cfg(feature = "client")]
pub struct RootCertStoreProvider {
    pub roots: Arc<RootCertStore>,
}

#[cfg(feature = "client")]
impl RootCertStoreProvider {
    /// Loads certificates from buf.
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

    /// Loads certificates from files.
    /// # Examples
    /// ```rust,no_run
    /// let root_cert_store = RootCertStoreProvider::from_file(
    ///     "certificates/ca_cert.pem",
    /// );
    /// ```
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

/// Properties to connect a client with Tls authenticator.
#[cfg(feature = "client")]
pub struct AuthTlsClientProperties {
    /// Dns name of the server.
    pub server_name: &'static str,
    /// Addr to the server Tcp socket.
    pub server_addr: SocketAddr,
    /// Certificate root store.
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
