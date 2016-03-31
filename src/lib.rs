extern crate byteorder;
extern crate chrono;
extern crate encoding;
extern crate net2;

use std::borrow::Cow;
use std::convert::From;
use std::error;
use std::io;

mod protocol;
mod conn;
mod stmt;
mod types;
pub use conn::*;
pub use stmt::*;
pub use types::*;

pub static LIB_NAME: &'static str = "tiberius";

/// An error returned by the SQL-server
pub type ServerError = protocol::TokenStreamError;

#[derive(Debug)]
pub enum TdsProtocolError {
    InvalidValue(String, u64),
    InvalidLength(String)
}

#[derive(Debug)]
pub enum TdsError {
    ProtocolError(TdsProtocolError),
    UnexpectedEOF,
    IoError(io::Error),
    /// An error returned by the SQL-server
    ServerError(ServerError),
    Other(String),
    Conversion(Box<error::Error + Sync + Send>)
}

pub type TdsResult<T> = std::result::Result<T, TdsError>;

impl From<io::Error> for TdsError {
    fn from(err: io::Error) -> TdsError {
        TdsError::IoError(err)
    }
}

impl From<Cow<'static, str>> for TdsError {
    fn from(err: Cow<'static, str>) -> TdsError {
        TdsError::Other(err.into_owned())
    }
}

impl From<TdsProtocolError> for TdsError {
    fn from(err: TdsProtocolError) -> TdsError {
        TdsError::ProtocolError(err)
    }
}
