use std::{error::Error, fmt::Display, net::SocketAddr};

use lyanne::server::BindError;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Errors {
    BindFail(BindError),
    UnexpectedAddrToAuth(SocketAddr),
    UnexpectedConnectResult,
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for Errors {}
