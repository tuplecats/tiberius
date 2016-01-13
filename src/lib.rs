extern crate byteorder;
extern crate chrono;
extern crate encoding;
extern crate net2;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::borrow::Cow;
use std::convert::From;
use std::io::prelude::*; //dbg
use std::io;
use client::Client;

mod packets;
mod client;

/// An error returned by the SQL-server
pub type ServerError = packets::TokenStreamError;

#[derive(Debug)]
pub enum TdsProtocolError {
    InvalidValue(String)
}

#[derive(Debug)]
pub enum TdsError {
    ProtocolError(TdsProtocolError),
    UnexpectedEOF,
    IoError(io::Error),
    /// An error returned by the SQL-server
    ServerError(ServerError),
    Other(String)
}

pub type TdsResult<T> = std::result::Result<T, TdsError>;

impl From<io::Error> for TdsError {
    fn from(err: io::Error) -> TdsError {
        TdsError::IoError(err)
    }
}

impl From<byteorder::Error> for TdsError {
    fn from(err: byteorder::Error) -> TdsError {
        match err {
            byteorder::Error::Io(x) => TdsError::IoError(x),
            byteorder::Error::UnexpectedEOF => TdsError::UnexpectedEOF
        }
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

#[test]
fn main()
{
    //let mut test = vec![];
    //let mut cl = Client::new(test);
    let mut cl = Client::connect_tcp("127.0.0.1", 1433).unwrap();
    cl.initialize_connection().unwrap();
    let rows = cl.exec("INSERT INTO [test].[dbo].[test](test) VALUES('hello2');").unwrap();
    println!("rows: {:?}", rows);
    //let mut buffer = [0; 4096];
    //cl.stream.read(&mut buffer).unwrap();
    //println!("{:?}", buffer.to_vec());
    //println!("{:?}", cl.stream);
}
