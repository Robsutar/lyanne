use std::{error::Error, fmt::Display};

use lyanne::{
    client::ConnectError,
    server::{BindError, ClientDisconnectReason},
};

#[derive(Debug)]
#[allow(dead_code)]
pub enum Errors {
    BindFail(BindError),
    ConnectFail(ConnectError),
    InvalidPacketDowncast(usize),
    UnexpectedHelloPacketName(usize),
    UnexpectedMessageContent(usize),
    UnexpectedServerDisconnectInfo,
    AdditionalAuthentication,
    ClientUnexpectedDisconnection,
    UnexpectedBehavior(usize),
    DisconnectionConfirmFailedByClient(ClientDisconnectReason),
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for Errors {}
