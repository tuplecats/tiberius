use std::io::prelude::*;
use std::io::Cursor;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt, WriteBytesExt};
use encoding::{Encoding, EncoderTrap};
use encoding::all::UTF_16LE;

#[macro_use]
mod login;
mod prelogin;

pub use self::prelogin::{EncryptionSetting, OptionTokenPair, ReadOptionToken, WriteOptionToken};
pub use self::login::Login7;

use protocol::util::{WriteUtf16, WriteCharStream};
use protocol::token_stream::*;
use protocol::types::{VarLenType};
use stmt::StatementInfo;
use types::ColumnType;
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
                let token_type = read_packet_data!(cursor, read_u8, from_u8, "unknown message token '0x{:x}'");
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
                let token_type = read_packet_data!(cursor, read_u8, from_u8, "unknown message token '0x{:x}'");
                match token_type {
                    MessageTypeToken::Colmetadata => streams.push(TokenStream::Colmetadata(try!(TokenStreamColmetadata::decode_stmt(&mut cursor, stmt)))),
                    MessageTypeToken::Row => streams.push(TokenStream::Row(try!(TokenStreamRow::decode_stmt(&mut cursor, stmt)))),
                    _ => { streams.push(try!(handle_token_stream(token_type, &mut cursor))); }
                }
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
        header.ptype = read_packet_data!(self, read_u8, from_u8, "header: unknown packet type {}");
        header.status = read_packet_data!(self, read_u8, from_u8, "header: unknown status {}");
        header.length = read_packet_data!(self, read_u16, BigEndian, from_u16, "header: invalid header length {}");
        header.spid[0] = read_packet_data!(self, read_u8, from_u8, "header: invalid spid[0] {}");
        header.spid[1] = read_packet_data!(self, read_u8, from_u8, "header: invalid spid[1] {}");
        header.id = read_packet_data!(self, read_u8, from_u8, "header: invalid id {}");
        header.window = read_packet_data!(self, read_u8, from_u8, "header: invalid window {}");

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
                    match meta.value {
                        ColumnType::I32(ref val) => {
                            try!(buf.write_u8(VarLenType::Intn as u8));
                            try!(buf.write_u8(4));
                            try!(buf.write_u8(4));
                            try!(buf.write_i32::<LittleEndian>(*val));
                        },
                        ColumnType::String(ref val) => {
                            let len = (val.len() as u32 * 2) as u16;
                            try!(buf.write_u8(VarLenType::NVarchar as u8));
                            try!(buf.write_u16::<LittleEndian>(len));
                            try!(buf.write_all(&[0, 0, 0, 0, 0])); //todo use a non-hardcoded collation
                            try!(buf.write_u16::<LittleEndian>(len));
                            try!(buf.write_as_utf16(&val));
                        },
                        _ => panic!("rpc: encoding of ColumnType {:?} not supported", meta.value)
                    }
                }
            },
            Packet::PreLogin(ref token_vec) => {
                let mut cursor = Cursor::new(buf);
                header.status = PacketStatus::EndOfMessage;
                header.ptype = PacketType::PreLogin;
                // write prelogin options (token, offset, length) [5 bytes] OR terminator
                let mut data_offset: u16 = 5 * token_vec.len() as u16 + 1;
                for option in token_vec {
                    let old_position = cursor.position();
                    cursor.set_position(data_offset as u64);
                    try!(cursor.write_option_token(option));
                    let option_len = (cursor.position() - data_offset as u64) as u16;
                    cursor.set_position(old_position);

                    try!(cursor.write_u8(option.token()));
                    try!(cursor.write_u16::<BigEndian>(data_offset));
                    try!(cursor.write_u16::<BigEndian>(option_len));
                    data_offset += option_len;
                }
                try!(cursor.write_u8(OptionTokenPair::Terminator.token()));
                buf = cursor.into_inner();
            },
            Packet::Login(ref login7) => {
                let mut cursor = Cursor::new(buf);
                header.status = PacketStatus::EndOfMessage;
                header.ptype = PacketType::Login;
                let pos = cursor.position();
                // write the length at the end, skip 4 bytes for it (u32)
                cursor.set_position(pos + 4);
                try!(cursor.write_u32::<BigEndian>(login7.tds_version));
                try!(cursor.write_u32::<LittleEndian>(login7.packet_size));
                try!(cursor.write_u32::<LittleEndian>(login7.client_prog_ver));
                try!(cursor.write_u32::<LittleEndian>(login7.client_pid));
                try!(cursor.write_u32::<LittleEndian>(login7.conn_id));
                try!(cursor.write_u8(login7.flags1));
                try!(cursor.write_u8(login7.flags2));
                try!(cursor.write_u8(login7.type_flags));
                try!(cursor.write_u8(login7.flags3));
                try!(cursor.write_i32::<LittleEndian>(login7.timezone));
                try!(cursor.write_u32::<LittleEndian>(login7.lcid)); //LE? unused anyways
                let data_start: u16 = cursor.position() as u16 + (13 * 4) + 6;
                let mut data_pos = data_start;

                for (i, val) in [&login7.hostname, &login7.username, &login7.password, &login7.app_name, &login7.server_name,
                    &login7.library_name, &login7.language, &login7.default_db].iter().enumerate() {
                    let old_pos = cursor.position();
                    cursor.set_position(data_pos as u64);
                    //try!(cursor.write_cstr(val));
                    let mut data_len = 0;
                    if val.len() > 0 {
                        // encode password
                        if i == 2 {
                            let mut bytes = try!(UTF_16LE.encode(val, EncoderTrap::Strict));
                            for byte in bytes.iter_mut() {
                                *byte = (*byte >> 4) | ((*byte & 0x0f) << 4);
                                *byte ^= 0xa5;
                            }
                            try!(cursor.write_all(&bytes));
                            data_len = bytes.len() as u16;
                        } else {
                            data_len = try!(cursor.write_as_utf16(val)) as u16;
                        }
                    }
                    cursor.set_position(old_pos);
                    write_login_offset!(cursor, data_pos, val.len() as u16, data_len);      //1,2,3,4,6,7,8,9

                    if i == 4 {
                        write_login_offset!(cursor, data_pos, 0);                           //5 [unused in TDSV7.3]
                    }
                }
                try!(cursor.write(&login7.client_id));                                      //client unique ID
                write_login_offset!(cursor, data_pos, 0);                                   //10 [ibSSPI & cbSSPI]
                write_login_offset!(cursor, data_pos, 0);                                   //11 [ibAtchDBFile & cchAtchDBFile]
                write_login_offset!(cursor, data_pos, 0);                                   //12 [ibChangePassword & cchChangePassword]
                try!(cursor.write_u32::<LittleEndian>(0));                                  //13 [cbSSPILong]

                // write remaining data
                assert_eq!(cursor.position() as u16, data_start);
                // write length
                cursor.set_position(0);
                try!(cursor.write_u32::<LittleEndian>(data_pos as u32));
                buf = cursor.into_inner();
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
