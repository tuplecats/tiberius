use std::io::prelude::*;
use std::io::Cursor;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt, WriteBytesExt};
use encoding::Encoding;

#[macro_use]
mod login;
mod prelogin;

pub use self::prelogin::{EncryptionSetting, OptionTokenPair, ReadOptionToken, WriteOptionToken};
pub use self::login::Login7;

use protocol::util::{WriteUtf16, WriteCharStream};
use protocol::token_stream::*;
use stmt::StatementInfo;
use ::{TdsResult, TdsError, TdsProtocolError};

pub trait ReadPacket {
    fn read_packet(&mut self) -> TdsResult<RawPacket>;
}

pub trait WritePacket {
    fn write_packet(&mut self, header: &mut PacketHeader, data: &Packet) -> TdsResult<()>;
}

#[derive(Debug)]
pub struct RawPacket
{
    pub header: PacketHeader,
    pub data: Vec<u8>,
}

#[inline]
fn handle_token_stream<'a, C: AsRef<[u8]>>(token_type: MessageTypeToken, cursor: &mut Cursor<C>) -> TdsResult<TokenStream<'a>> {
    match token_type {
        MessageTypeToken::Error => {
            Ok(TokenStream::Error(try!(TokenStreamError::decode(cursor))))
        },
        MessageTypeToken::LoginAck => {
            Ok(TokenStream::LoginAck(try!(TokenStreamLoginAck::decode(cursor))))
        },
        MessageTypeToken::EnvChange => {
            Ok(TokenStream::EnvChange(try!(TokenStreamEnvChange::decode(cursor))))
        },
        MessageTypeToken::Done => {
            Ok(TokenStream::Done(try!(TokenStreamDone::decode(cursor))))
        },
        MessageTypeToken::DoneProc => {
            Ok(TokenStream::DoneProc(try!(TokenStreamDone::decode(cursor))))
        },
        MessageTypeToken::DoneInProc => {
            Ok(TokenStream::DoneInProc(try!(TokenStreamDone::decode(cursor))))
        },
        MessageTypeToken::ReturnStatus => {
            Ok(TokenStream::ReturnStatus(try!(cursor.read_i32::<LittleEndian>())))
        },
        MessageTypeToken::ReturnValue => {
            Ok(TokenStream::ReturnValue(try!(TokenStreamRetVal::decode(cursor))))
        },
        _ => Err(TdsError::Other(format!("token {:?} not supported yet", token_type)))
    }
}

impl RawPacket {
    pub fn into_prelogin<'a>(self) -> TdsResult<Packet<'a>> {
        assert_eq!(self.header.ptype, PacketType::TabularResult);
        assert_eq!(self.header.status, PacketStatus::EndOfMessage);
        let mut token_pairs: Vec<OptionTokenPair> = Vec::new();
        {
            let terminator = OptionTokenPair::Terminator.token();

            let mut cursor = Cursor::new(self.data);
            let mut token;

            let initial_pos = cursor.position();

            while { token = try!(cursor.read_u8()); token != terminator }
            {
                let data_offset = try!(cursor.read_u16::<BigEndian>());
                let data_length = try!(cursor.read_u16::<BigEndian>());
                let old_pos = cursor.position();
                cursor.set_position(initial_pos + data_offset as u64);
                token_pairs.push(try!(cursor.read_option_token(token, data_length)));
                cursor.set_position(old_pos);
            }
        }
        Ok(Packet::PreLogin(token_pairs))
    }

    pub fn into_general_token_stream<'a>(self) -> TdsResult<Packet<'a>> {
        let mut streams: Vec<TokenStream> = vec![];
        {
            let packet_len = self.data.len();
            let mut cursor = Cursor::new(self.data);

            while cursor.position() < packet_len as u64 {
                let token_type = read_packet_data!(None, cursor, read_u8, from_u8, "unknown message token '0x{:x}'", cursor.position());
                let stream = try!(handle_token_stream(token_type, &mut cursor));
                streams.push(stream);
            }
            assert_eq!(cursor.position(), packet_len as u64);
        }
        Ok(Packet::TokenStream(streams))
    }

    pub fn into_stmt_token_stream<'a>(self, stmt: &mut StatementInfo) -> TdsResult<Packet<'a>> {
        let mut streams: Vec<TokenStream> = vec![];
        {
            let packet_len = self.data.len();
            let mut cursor = Cursor::new(self.data);

            while cursor.position() < packet_len as u64 {
                let token_type = read_packet_data!(None, cursor, read_u8, from_u8, "unknown message token '0x{:x}'", cursor.position());
                streams.push(match token_type {
                    MessageTypeToken::Colmetadata => TokenStream::Colmetadata(try!(TokenStreamColmetadata::decode_stmt(&mut cursor, stmt))),
                    MessageTypeToken::Row => TokenStream::Row(try!(TokenStreamRow::decode_stmt(&mut cursor, stmt))),
                    _ => try!(handle_token_stream(token_type, &mut cursor))
                })
            }
            assert_eq!(cursor.position(), packet_len as u64);
        }
        Ok(Packet::TokenStream(streams))
    }
}

/// 8-byte packet headers as described in 2.2.3.
#[derive(Debug)]
pub struct PacketHeader
{
    pub ptype: PacketType,
    pub status: PacketStatus,
    /// Length (received as BigEndian) as specified by 2.2.3.1.3
    pub length: u16,
    /// (debug only) as specified by 2.2.3.1.4
    pub spid: [u8; 2],
    /// packet id as specified by 2.2.3.1.5
    pub id: u8,
    /// unused as specified by 2.2.3.1.6
    pub window: u8
}

impl PacketHeader {
    #[inline]
    pub fn new() -> PacketHeader {
        PacketHeader {
            ptype: PacketType::Unknown,
            status: PacketStatus::NormalMessage,
            length: 0,
            spid: [0, 0],
            id: 0,
            window: 0
        }
    }
}

/// The types a packet header can contain, as specified by 2.2.3.1.1
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum PacketType
{
    /// invalid
    Unknown       = 0,
    SqlBatch      = 1,
    Rpc           = 3,
    TabularResult = 4,
    Attention     = 6,
    BulkLoadData  = 7,
    FedAuthToken  = 8,
    TransactionManagerReq = 14,
    /// Login used for >=TDS v7
    Login         = 16,
    Sspi          = 17,
    PreLogin      = 18
}
impl_from_primitive!(PacketType, Unknown, SqlBatch, Rpc, TabularResult, Attention, BulkLoadData, FedAuthToken,
    TransactionManagerReq, Login, Sspi, PreLogin);

#[derive(Debug)]
pub enum Packet<'a>
{
    None,
    /// as specified in 2.2.6.5
    PreLogin(Vec<OptionTokenPair>),
    /// as specified by 2.2.6.4
    Login(Login7),
    /// as specified in 2.2.6.7
    RpcRequest(&'a RpcRequestData<'a>),
    SqlBatch(&'a str),
    TokenStream(Vec<TokenStream<'a>>)
}

impl<'a> Packet<'a> {
    /// Check if the tokenstream in the packet contains an error token
    pub fn catch_error(&self) -> TdsResult<()> {
        match *self {
            Packet::TokenStream(ref tokens) => {
                for token in tokens {
                    match *token {
                        TokenStream::Error(ref err) => {
                            return Err(TdsError::ServerError(err.clone()))
                        },
                        _ => ()
                    }
                }
            },
            _ => ()
        }
        Ok(())
    }
}

/// 2.2.3.1.2
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum PacketStatus
{
    NormalMessage = 0,
    EndOfMessage = 1,
    IgnoreEvent = 1 | 2,
    ResetConnection = 8,
    ResetConnectionSkipTransaction = 16
}
impl_from_primitive!(PacketStatus, NormalMessage, EndOfMessage, IgnoreEvent, ResetConnection, ResetConnectionSkipTransaction);

impl<R: Read> ReadPacket for R
{
    fn read_packet(&mut self) -> TdsResult<RawPacket> {
        let mut header = PacketHeader::new();
        header.ptype = read_packet_data!(None, self, read_u8, from_u8, "header: unknown packet type {}");
        header.status = read_packet_data!(None, self, read_u8, from_u8, "header: unknown status {}");
        header.length = read_packet_data!(BigEndian, self, read_u16, from_u16, "header: invalid header length {}");
        header.spid[0] = read_packet_data!(None, self, read_u8, from_u8, "header: invalid spid[0] {}");
        header.spid[1] = read_packet_data!(None, self, read_u8, from_u8, "header: invalid spid[1] {}");
        header.id = read_packet_data!(None, self, read_u8, from_u8, "header: invalid id {}");
        header.window = read_packet_data!(None, self, read_u8, from_u8, "header: invalid window {}");

        let mut buf = vec![0 as u8; header.length as usize - 8];
        let read_bytes = try!(self.read(&mut buf[..]));
        assert_eq!(read_bytes, buf.len());
        Ok(RawPacket { header: header, data: buf })
    }
}

impl<W: Write> WritePacket for W
{
   fn write_packet(&mut self, header: &mut PacketHeader, packet: &Packet) -> TdsResult<()> {
        // prealloc header size so we can return the packet as a whole [including header]
        let mut buf = vec![];

        match *packet {
            Packet::SqlBatch(ref sql_) => {
                header.status = PacketStatus::EndOfMessage;
                header.ptype = PacketType::SqlBatch;

                //TODO: transaction support, move this out
                try!(buf.write_data_header(&PacketDataHeader::Transaction(PacketDataHeaderTransaction {
                    outstanding_requests: 1,
                    transaction_descriptor: 0
                })));
                try!(buf.write_as_utf16(sql_));
            },
            Packet::RpcRequest(ref req) => {
                header.status = PacketStatus::EndOfMessage;
                header.ptype = PacketType::Rpc;

                //TODO: transaction support, move this out
                try!(buf.write_data_header(&PacketDataHeader::Transaction(PacketDataHeaderTransaction {
                    outstanding_requests: 1,
                    transaction_descriptor: 0
                })));

                try!(buf.write_rpc_procid(&req.proc_id));
                try!(buf.write_u16::<LittleEndian>(req.flags));
                // write parameter data
                for meta in &req.params {
                    try!(buf.write_b_varchar(&meta.name));
                    try!(buf.write_u8(meta.status_flags));
                    //write TYPE_INFo
                    try!(buf.write_token_stream(&meta.value));
                }
            },
            Packet::PreLogin(ref token_vec) => {
                header.status = PacketStatus::EndOfMessage;
                header.ptype = PacketType::PreLogin;
                try!(buf.write_token_stream(&token_vec[..]));
            },
            Packet::Login(ref login7) => {
                header.status = PacketStatus::EndOfMessage;
                header.ptype = PacketType::Login;
                try!(buf.write_token_stream(login7));
            },
            _ => panic!("Writing of {:?} not supported!", packet)
        }
        // write packet header, length is 8 [header-size, preallocated] + length of the packet data
        header.length = 8 + buf.len() as u16;
        {
            try!(self.write_u8(header.ptype as u8));
            try!(self.write_u8(header.status as u8));
            try!(self.write_u16::<BigEndian>(header.length));
            try!(self.write_u8(header.spid[0]));
            try!(self.write_u8(header.spid[1]));
            try!(self.write_u8(header.id));
            try!(self.write_u8(header.window));
        }
        try!(self.write_all(&buf));
        Ok(())
    }
}
