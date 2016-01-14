mod err;
mod loginack;
mod env_change;
mod done;
mod colmetadata;

use std::io::Cursor;
use std::io::prelude::*;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use ::{TdsResult};

pub use self::err::*;
pub use self::loginack::*;
pub use self::env_change::*;
pub use self::done::*;
pub use self::colmetadata::*;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum MessageTypeToken
{
    Done = 0xFD,
    EnvChange = 0xE3,
    Error = 0xAA,
    LoginAck = 0xAD,
    //Colmetadata = 0x81,
}
impl_from_primitive!(MessageTypeToken, Done, EnvChange, Error, LoginAck);

pub trait DecodeTokenStream {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<Self> where Self: Sized;
}

#[derive(Debug)]
pub enum TokenStream {
    Error(TokenStreamError),
    LoginAck(TokenStreamLoginAck),
    EnvChange(TokenStreamEnvChange),
    Done(TokenStreamDone)
}

#[derive(Debug)]
pub enum PacketDataHeader {
    Transaction(PacketDataHeaderTransaction)
}

/// headers for a specific (packet-)data type 2.2.5.3
#[derive(Debug)]
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
        let header_type = match data {
            &PacketDataHeader::Transaction(ref tx_header) => {
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
