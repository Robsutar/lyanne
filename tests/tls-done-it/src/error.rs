use std::{error::Error, fmt::Display};

use lyanne::{
    client::{ConnectError, ServerDisconnectReason},
    server::{BindError, ServerDisconnectClientState},
};

#[derive(Debug)]
#[allow(dead_code)]
pub enum Errors {
    BindFail(BindError),
    ConnectFail(ConnectError),
    TimedOut,
    InvalidPacketDowncast(usize),
    UnexpectedHelloPacketName(usize),
    UnexpectedMessageContent(usize),
    UnexpectedServerDisconnectInfo,
    AdditionalAuthentication,
    ClientUnexpectedDisconnection,
    ServerShouldBeDisconnected,
    UnexpectedBehavior(usize),
    DisconnectionConfirmFailedByClient(ServerDisconnectClientState),
    DisconnectionConfirmFailedByServer(ServerDisconnectReason),
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for Errors {}
