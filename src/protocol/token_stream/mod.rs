mod err;
mod loginack;
mod env_change;
mod done;
mod colmetadata;
mod row;
pub mod rpc;
mod retval;

use std::io::Cursor;
use std::io::prelude::*;
use byteorder::{LittleEndian, WriteBytesExt};
use stmt::StatementInfo;
use ::{TdsResult};

pub use self::err::*;
pub use self::loginack::*;
pub use self::env_change::*;
pub use self::done::*;
pub use self::colmetadata::*;
pub use self::row::*;
pub use self::rpc::*;
pub use self::retval::*;

#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum MessageTypeToken
{
    Done = 0xFD,
    DoneProc = 0xFE,
    DoneInProc = 0xFF,
    EnvChange = 0xE3,
    Error = 0xAA,
    LoginAck = 0xAD,
    ReturnStatus = 0x79,
    Colmetadata = 0x81,
    ReturnValue = 0xAC,
    Row = 0xD1,
    Order = 0xA9,
}
impl_from_primitive!(MessageTypeToken, Done, DoneProc, DoneInProc, EnvChange, Error, LoginAck, ReturnStatus, Colmetadata, ReturnValue, Row, Order);

pub trait DecodeTokenStream {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<Self> where Self: Sized;
}

pub trait WriteTokenStream<T> {
    fn write_token_stream(&mut self, data: T) -> TdsResult<()>;
}

pub trait DecodeStmtTokenStream {
    fn decode_stmt<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, stmt: &mut StatementInfo) -> TdsResult<Self> where Self: Sized;
}

#[derive(Debug)]
pub enum TokenStream<'a> {
    Error(TokenStreamError),
    LoginAck(TokenStreamLoginAck),
    EnvChange(TokenStreamEnvChange),
    Done(TokenStreamDone),
    DoneProc(TokenStreamDone),
    DoneInProc(TokenStreamDone),
    Colmetadata(TokenStreamColmetadata),
    Row(TokenStreamRow<'a>),
    ReturnStatus(i32),
    Order(Vec<u16>),
    ReturnValue(TokenStreamRetVal<'a>),
}

#[derive(Debug)]
pub enum PacketDataHeader {
    Transaction(PacketDataHeaderTransaction)
}

/// headers for a specific (packet-)data type 2.2.5.3
#[derive(Debug)]
#[allow(dead_code)]
#[repr(u16)]
pub enum PacketDataHeaderType {
    QueryNotifications = 1,
    TransactionDescriptor = 2,
    TraceActivity = 3
}

#[derive(Debug)]
pub struct PacketDataHeaderTransaction {
    pub transaction_descriptor: u64,
    pub outstanding_requests: u32,
}

pub trait WriteDataHeader<T> {
    fn write_data_header(&mut self, data: &T) -> TdsResult<()>;
}

impl<W: Write> WriteDataHeader<PacketDataHeaderTransaction> for W {
    fn write_data_header(&mut self, data: &PacketDataHeaderTransaction) -> TdsResult<()>
    {
        try!(self.write_u64::<LittleEndian>(data.transaction_descriptor));
        try!(self.write_u32::<LittleEndian>(data.outstanding_requests));
        Ok(())
    }
}

impl<W: Write> WriteDataHeader<PacketDataHeader> for W {
    fn write_data_header(&mut self, data: &PacketDataHeader) -> TdsResult<()> {
        let mut buf = vec![];
        let header_type = match *data {
            PacketDataHeader::Transaction(ref tx_header) => {
                try!(buf.write_data_header(tx_header));
                PacketDataHeaderType::TransactionDescriptor
            }
        };
        try!(self.write_u32::<LittleEndian>(buf.len() as u32 + 10)); // total length of ALL_HEADERS (including this)
        try!(self.write_u32::<LittleEndian>(buf.len() as u32 + 6)); // length of this header (including this)
        try!(self.write_u16::<LittleEndian>(header_type as u16));
        try!(self.write_all(&buf));

        Ok(())
    }
}
