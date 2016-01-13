use std::convert::AsRef;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use ::{TdsResult, TdsError, TdsProtocolError};

use byteorder::{LittleEndian, BigEndian, ReadBytesExt, WriteBytesExt};
//TODO: make chrono optional
use chrono::{Offset, Local};
use encoding::{Encoding, EncoderTrap, DecoderTrap};
use encoding::all::UTF_16LE;

static LIB_NAME: &'static str = "tiberius";

#[doc(hidden)]
trait WriteCStr {
    fn write_cstr(&mut self, s: &str) -> io::Result<()>;
}

impl<W: Write> WriteCStr for W {
    fn write_cstr(&mut self, s: &str) -> io::Result<()> {
        try!(self.write_all(s.as_bytes()));
        Ok(try!(self.write_u8(0)))
    }
}

#[doc(hidden)]
pub trait ReadPacket {
    fn read_packet(&mut self) -> TdsResult<Packet>;
}

#[doc(hidden)]
pub trait WritePacket {
    fn write_packet(&mut self, packet: &mut Packet) -> TdsResult<()>;
}

#[doc(hidden)]
trait WriteUtf16 {
    fn write_as_utf16(&mut self, s: &str) -> TdsResult<usize>;
}

impl<W: Write> WriteUtf16 for W {
    /// Writes a UTF-16 string with double null terminator
    fn write_as_utf16(&mut self, s: &str) -> TdsResult<usize> {
        let bytes = try!(UTF_16LE.encode(s, EncoderTrap::Strict));
        try!(self.write_all(&bytes));
        Ok(bytes.len())
    }
}

#[doc(hidden)]
trait ReadCharStream {
    fn read_varchar(&mut self, length: usize) -> TdsResult<String>;
    fn read_us_varchar(&mut self) -> TdsResult<String>;
    fn read_b_varchar(&mut self) -> TdsResult<String>;
}

impl<R: Read> ReadCharStream for R {
    fn read_varchar(&mut self, length: usize) -> TdsResult<String> {
        let length = length * 2;
        let mut bytes: Vec<u8> = vec![0; length];
        assert_eq!(try!(self.read(&mut bytes[..])), length);
        Ok(try!(UTF_16LE.decode(&bytes, DecoderTrap::Strict)))
    }

    #[inline]
    fn read_us_varchar(&mut self) -> TdsResult<String> {
        let len = try!(self.read_u16::<LittleEndian>()) as usize;
        self.read_varchar(len)
    }

    #[inline]
    fn read_b_varchar(&mut self) -> TdsResult<String> {
        let len = try!(self.read_u8()) as usize;
        self.read_varchar(len)
    }
}

/// The types a packet header can contain, as specified by 2.2.3.1.1
trait FromPrimitive<T>: Sized {
    fn from(i: T) -> Option<Self>;
}

macro_rules! impl_from_primitive_ty {
    ($($ty:ident),*) => {
        $(
        impl FromPrimitive<$ty> for $ty {
            #[inline]
            fn from(i: $ty) -> Option<$ty> {
                Some(i)
            }
        }
        )*
    }
}
impl_from_primitive_ty!(u8, u16);

macro_rules! impl_from_primitive {
    ($name: ident, $($field: ident),*) => {
        impl FromPrimitive<u8> for $name {
            fn from(i: u8) -> Option<$name> {
                match i {
                    $( x if x == $name::$field as u8 => Some($name::$field), )*
                    _ => None
                }
            }
        }

        impl FromPrimitive<u16> for $name {
            fn from(i: u16) -> Option<$name> {
                match i {
                    $( x if x == $name::$field as u16 => Some($name::$field), )*
                    _ => None
                }
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum PacketType
{
    /// invalid
    Unknown       = 0,
    SqlBatch      = 1,
    RPC           = 2,
    TabularResult = 4,
    Attention     = 6,
    BulkLoadData  = 7,
    FedAuthToken  = 8,
    TransactionManagerReq = 14,
    /// Login used for >=TDS v7
    Login         = 16,
    SSPI          = 17,
    PreLogin      = 18
}
impl_from_primitive!(PacketType, Unknown, SqlBatch, RPC, TabularResult, Attention, BulkLoadData, FedAuthToken,
    TransactionManagerReq, Login, SSPI, PreLogin);

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

#[derive(Debug)]
pub struct Packet<'a>
{
    pub header: PacketHeader,
    pub data: PacketData<'a>
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
    transaction_descriptor: u64,
    outstanding_requests: u32,
}

trait WriteDataHeader<T> {
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
        try!(self.write_u32::<LittleEndian>(buf.len() as u32 + 10));
        try!(self.write_u32::<LittleEndian>(buf.len() as u32 + 6));
        try!(self.write_u16::<LittleEndian>(header_type as u16));
        try!(self.write_all(&buf));

        Ok(())
    }
}

macro_rules! extract_raw_data {
    ($_self:expr) => ({
        match $_self.data {
            PacketData::RawData(ref raw) => raw,
            _ => panic!("Attempting to try an already transformed packet. Can only transform once!")
        }
    })
}

macro_rules! read_packet_data {
    ($_self:expr,$read_fn:ident,$from_fn:ident,$msg:expr) => ({
        let read_data = try!($_self.$read_fn());
        try!(FromPrimitive::from(read_data).ok_or(TdsProtocolError::InvalidValue(format!($msg, read_data))))
    });
    ($_self:expr,$read_fn:ident,$read_gen:ty,$from_fn:ident,$msg:expr) => ({
        let read_data = try!($_self.$read_fn::<$read_gen>());
        try!(FromPrimitive::from(read_data).ok_or(TdsProtocolError::InvalidValue(format!($msg, read_data))))
    })
}

macro_rules! write_login_offset {
    ($cursor:expr, $pos:expr, $len:expr) => (write_login_offset!($cursor, $pos, $len, $len));
    ($cursor:expr, $pos:expr, $len:expr, $data_len:expr) => ({
        try!($cursor.write_u16::<LittleEndian>($pos));
        try!($cursor.write_u16::<LittleEndian>($len));
        $pos += $data_len;
    });
}

impl<'a> Packet<'a> {
    pub fn parse_as_prelogin(&mut self) -> TdsResult<()> {
        assert_eq!(self.header.ptype, PacketType::TabularResult);
        assert_eq!(self.header.status, PacketStatus::EndOfMessage);
        let mut token_pairs: Vec<OptionTokenPair> = Vec::new();
        {
            let packet_data = extract_raw_data!(self);
            let terminator = OptionTokenPair::Terminator.token();

            let mut cursor = Cursor::new(packet_data);
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
        self.data = PacketData::PreLogin(token_pairs);
        Ok(())
    }

    pub fn parse_as_token_stream(&mut self) -> TdsResult<()> {
        let mut streams: Vec<TokenStream> = vec![];
        {
            let packet_data = extract_raw_data!(self);
            let mut cursor = Cursor::new(packet_data);

            while cursor.position() < packet_data.len() as u64 {
                let token_type = read_packet_data!(cursor, read_u8, from_u8, "unknown message token '0x{:x}'");
                match token_type {
                    MessageTypeToken::Error => {
                        streams.push(TokenStream::Error(try!(TokenStreamError::decode(&mut cursor))));
                    },
                    MessageTypeToken::LoginAck => {
                        streams.push(TokenStream::LoginAck(try!(TokenStreamLoginAck::decode(&mut cursor))));
                    },
                    MessageTypeToken::EnvChange => {
                        streams.push(TokenStream::EnvChange(try!(TokenStreamEnvChange::decode(&mut cursor))));
                    },
                    MessageTypeToken::Done => {
                        streams.push(TokenStream::Done(try!(TokenStreamDone::decode(&mut cursor))));
                    }
                    //_ => panic!("token {:?} not supported yet", token_type)
                }
            }
            assert_eq!(cursor.position(), packet_data.len() as u64);
        }
        self.data = PacketData::TokenStream(streams);
        Ok(())
    }
}

#[derive(Debug)]
pub enum PacketData<'a>
{
    None,
    RawData(Vec<u8>),
    /// as specified in 2.2.6.5
    PreLogin(Vec<OptionTokenPair>),
    /// as specified by 2.2.6.4
    Login(Login7),
    /// as specified in 2.2.6.7
    SqlBatch(&'a str),
    TokenStream(Vec<TokenStream>)
}

/// Login7 Packet as specified by 2.2.6.4
#[derive(Debug)]
pub struct Login7
{
    tds_version: u32,
    packet_size: u32,
    client_prog_ver: u32,
    client_pid: u32,
    conn_id: u32,
    /// consisting of: byteOrder[1-bit], charset[1b], float-type[2b], dump-load[1b], use-db[1b], succeed_database[1b], warn_lang_change[1b]
    flags1: u8,
    /// consisting of: succeed_lang[1b], is_odbc[1b], trans_boundary[1b], cacheconnect[1b], user_type[3b], integrated_security[1b]
    flags2: u8,
    /// consisting of: sql_type[4b], ole_db[1b], read_only_intent[1b], reserved[2b]
    type_flags: u8,
    /// consisting of: change_pwd[1b], send_yukon_binary_xml[1b], user_instance[1b], unknown_collation_handling[1b]
    flags3: u8,
    /// timezone offset to UTC [in minutes]
    timezone: i32,
    /// language code identifier
    lcid: u32,
    //OffsetLength
    hostname: String,
    username: String,
    password: String,
    app_name: String,
    server_name: String,
    library_name: String,
    /// initial lang
    language: String,
    /// initial db
    default_db: String,
    /// unique client identifier created by using the NIC-Address/MAC
    client_id: [u8; 6]
}

impl Login7 {
    /// Create a new Login7 packet for TDS7.3
    pub fn new() -> Login7 {
        Login7 {
            tds_version: 0x03000B73,
            packet_size: 0x1000,
            client_prog_ver: 0,
            client_pid: 0,
            conn_id: 0,
            flags1: 0,
            flags2: 0,
            flags3: 0,
            type_flags: 0,
            timezone: Local::now().offset().local_minus_utc().num_minutes() as i32,
            lcid: 0x00000409,
            hostname: "localhost".to_owned(), //TODO
            username: "test".to_owned(),
            password: "test".to_owned(),
            app_name: LIB_NAME.to_owned(),
            server_name: "localhost".to_owned(), //TODO
            library_name: LIB_NAME.to_owned(),
            language: "".to_owned(),
            default_db: "tempdb".to_owned(),
            client_id: [1, 2, 3, 4, 5, 6]
        }
    }
}

impl<R: Read> ReadPacket for R
{
    fn read_packet(&mut self) -> TdsResult<Packet> {
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
        Ok(Packet { header: header, data: PacketData::RawData(buf) })
    }
}

impl<W: Write> WritePacket for W
{
   fn write_packet(&mut self, packet: &mut Packet) -> TdsResult<()> {
        // prealloc header size so we can return the packet as a whole [including header]
        let mut buf = vec![];

        match packet.data {
            PacketData::SqlBatch(sql_) => {
                packet.header.status = PacketStatus::EndOfMessage;
                packet.header.ptype = PacketType::SqlBatch;

                buf.write_data_header(&PacketDataHeader::Transaction(PacketDataHeaderTransaction {
                    outstanding_requests: 1,
                    transaction_descriptor: 0
                }));
                try!(buf.write_as_utf16(sql_));
            },
            PacketData::PreLogin(ref token_vec) => {
                let mut cursor = Cursor::new(buf);
                packet.header.status = PacketStatus::EndOfMessage;
                packet.header.ptype = PacketType::PreLogin;
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
            PacketData::Login(ref login7) => {
                let mut cursor = Cursor::new(buf);
                packet.header.status = PacketStatus::EndOfMessage;
                packet.header.ptype = PacketType::Login;
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
                cursor.write(&login7.client_id);                                            //client unique ID
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
            _ => panic!("Writing of {:?} not supported!", packet.data)
        }
        // write packet header, length is 8 [header-size, preallocated] + length of the packet data
        packet.header.length = 8 + buf.len() as u16;
        {
            try!(self.write_u8(packet.header.ptype as u8));
            try!(self.write_u8(packet.header.status as u8));
            try!(self.write_u16::<BigEndian>(packet.header.length));
            try!(self.write_u8(packet.header.spid[0]));
            try!(self.write_u8(packet.header.spid[1]));
            try!(self.write_u8(packet.header.id));
            try!(self.write_u8(packet.header.window));
        }
        self.write_all(&buf);
        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum EncryptionSetting
{
    EncryptOff = 0,
    EncryptOn = 1,
    EncryptNotSupported = 2,
    EncryptRequired = 3
}
impl_from_primitive!(EncryptionSetting, EncryptOff, EncryptOn, EncryptNotSupported, EncryptRequired);

#[derive(Debug)]
pub enum OptionTokenPair
{
    /// UL_VERSION (big-endian), US_SUBBUILD
    Version(u32, u16),
    Encryption(EncryptionSetting),
    Instance(String),
    ThreadId(u32),
    Mars(u8),
    TraceId([u8; 16], [u8; 20]),
    FedAuthRequired(u8),
    Nonce([u8; 32]),
    /// 0xFF
    Terminator
}

impl OptionTokenPair {
    fn token(&self) -> u8 {
        match *self {
            OptionTokenPair::Version(_, _) => 0,
            OptionTokenPair::Encryption(_) => 1,
            OptionTokenPair::Instance(_) => 2,
            OptionTokenPair::ThreadId(_) => 3,
            OptionTokenPair::Mars(_) => 4,
            OptionTokenPair::TraceId(_, _) => 5,
            OptionTokenPair::FedAuthRequired(_) => 6,
            OptionTokenPair::Nonce(_) => 7,
            OptionTokenPair::Terminator => 255
        }
    }
}

trait ReadOptionToken {
    fn read_option_token(&mut self, token: u8, max_len: u16) -> TdsResult<OptionTokenPair>;
}

trait WriteOptionToken {
    fn write_option_token(&mut self, option: &OptionTokenPair) -> io::Result<()>;
}

impl<R: BufRead> ReadOptionToken for R {
    fn read_option_token(&mut self, token: u8, max_len: u16) -> TdsResult<OptionTokenPair> {
        Ok(match token {
            0 => OptionTokenPair::Version(try!(self.read_u32::<BigEndian>()), try!(self.read_u16::<BigEndian>())),
            1 => {
                let read_data = try!(self.read_u8());
                OptionTokenPair::Encryption(try!(FromPrimitive::from(read_data).ok_or(TdsProtocolError::InvalidValue(format!("prelogin: could not parse encryption: {}", read_data)))))
            },
            2 => {
                let mut buf = vec![0 as u8; max_len as usize - 1];
                try!(self.read(&mut buf));
                OptionTokenPair::Instance(try!(String::from_utf8(buf).map_err(|err| TdsProtocolError::InvalidValue(format!("prelogin: invalid string for instance name")))))
            },
            3 =>  OptionTokenPair::ThreadId(if max_len > 0 { try!(self.read_u32::<BigEndian>()) } else { 0 }),
            4 => OptionTokenPair::Mars(try!(self.read_u8())),
            5 => {
                let mut guid_connid = [0 as u8; 16];
                let mut activity_id = [0 as u8; 20];
                try!(self.read(&mut guid_connid));
                try!(self.read(&mut activity_id));
                OptionTokenPair::TraceId(guid_connid, activity_id)
            }
            6 => OptionTokenPair::FedAuthRequired(try!(self.read_u8())),
            7 => {
                let mut nonce = [0 as u8; 32];
                try!(self.read(&mut nonce));
                OptionTokenPair::Nonce(nonce)
            },
            255 => OptionTokenPair::Terminator,
            _ => return Err(TdsError::from(TdsProtocolError::InvalidValue(format!("prelogin: option_token: invalid value {}", token))))
        })
    }
}

impl<W: Write> WriteOptionToken for W {
    fn write_option_token(&mut self, option: &OptionTokenPair) -> io::Result<()> {
        match *option {
            OptionTokenPair::Version(version, subbuild) => {
                try!(self.write_u32::<BigEndian>(version));
                try!(self.write_u16::<BigEndian>(subbuild));
            },
            OptionTokenPair::Encryption(ref setting) => try!(self.write_u8(*setting as u8)),
            OptionTokenPair::Instance(ref instance) => try!(self.write_cstr(instance)),
            OptionTokenPair::ThreadId(id) => try!(self.write_u32::<BigEndian>(id)),
            OptionTokenPair::Mars(mars) => try!(self.write_u8(mars)),
            OptionTokenPair::TraceId(guid_connid, activity_id) => {
                for b in guid_connid.iter().chain(activity_id.iter()) {
                    try!(self.write_u8(*b));
                }
            },
            OptionTokenPair::FedAuthRequired(fedauth) => try!(self.write_u8(fedauth)),
            OptionTokenPair::Nonce(nonce) => {
                for b in nonce.iter() {
                    try!(self.write_u8(*b));
                }
            },
            OptionTokenPair::Terminator => {}
        };
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum MessageTypeToken
{
    Done = 0xFD,
    EnvChange = 0xE3,
    Error = 0xAA,
    LoginAck = 0xAD
}
impl_from_primitive!(MessageTypeToken, Done, EnvChange, Error, LoginAck);

trait DecodeTokenStream {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<Self> where Self: Sized;
}

#[derive(Debug)]
enum TokenStream {
    Error(TokenStreamError),
    LoginAck(TokenStreamLoginAck),
    EnvChange(TokenStreamEnvChange),
    Done(TokenStreamDone)
}

/// The token stream "DONE" as described by 2.2.7.5
#[derive(Debug)]
struct TokenStreamDone {
    /// A combination of flags defined in TokenStreamDoneStatus
    status: u16,
    cur_cmd: u16,
    done_row_count: u64
}

#[repr(u16)]
enum TokenStreamDoneStatus {
    DoneFinal = 0x00,
    DoneMore = 0x01,
    DoneError = 0x02,
    DoneInxact = 0x04,
    DoneCount = 0x10,
    DoneAttn = 0x20,
    DoneSrvErr = 0x100
}

impl DecodeTokenStream for TokenStreamDone {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamDone> {
        Ok(TokenStreamDone {
            status: try!(cursor.read_u16::<LittleEndian>()),
            cur_cmd: try!(cursor.read_u16::<LittleEndian>()),
            done_row_count: try!(cursor.read_u64::<LittleEndian>())
        })
    }
}

/// The environment change token stream "ENVCHANGE" as described by 2.2.7.8
#[derive(Debug)]
enum TokenStreamEnvChange {
    /// Change of database from old_value to new_value
    Database(String, Option<String>),
    PacketSize(String, Option<String>)
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
enum EnvChangeType {
    Database = 1,
    Language = 2,
    CharacterSet = 3,
    PacketSize = 4,
    /// Unicode data sorting local id
    UnicodeDataSortLID = 5,
    /// Unicode data sorting comparison flags
    UnicodeDataSortLCF = 6,
    SqlCollation = 7,
    BeginTransaction = 8,
    CommitTransaction = 9,
    RollbackTransaction = 10,
    EnlistDTCTransaction = 11,
    DefectTransaction = 12,
    /// Real Time Log Shipping
    Rtls = 13,
    PromoteTransaction = 15,
    TransactionManagerAddr= 16,
    TransactionEnded = 17,
    /// RESETCONNECTION/RESETCONNECTIONSKIPTRAN Completion Acknowledgement
    ResetConnectionAck= 18,
    /// Sends back name of user instance started per login request
    SessStartUserInst = 19,
    RoutingInformation = 20
}
impl_from_primitive!(EnvChangeType, Database, Language, CharacterSet, PacketSize, UnicodeDataSortLID, UnicodeDataSortLCF,
    SqlCollation, BeginTransaction, CommitTransaction, RollbackTransaction, EnlistDTCTransaction, DefectTransaction, Rtls,
    PromoteTransaction, TransactionManagerAddr, TransactionEnded, ResetConnectionAck, SessStartUserInst, RoutingInformation
);

impl DecodeTokenStream for TokenStreamEnvChange {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamEnvChange> {
        let start_pos = cursor.position();
        let end_pos = start_pos + try!(cursor.read_u16::<LittleEndian>()) as u64;
        let token_type: EnvChangeType = read_packet_data!(cursor, read_u8, from_u8, "unknown envchange token type '0x{:x}'");
        Ok(match token_type {
            EnvChangeType::PacketSize => TokenStreamEnvChange::PacketSize(try!(cursor.read_b_varchar()), if cursor.position() < end_pos { Some(try!(cursor.read_b_varchar())) } else { None }),
            _ => panic!("unsupported envchange token: 0x{:x}", token_type as u8)
        })
    }
}

/// The token stream "ERROR" as described by 2.2.7.9
#[derive(Debug)]
struct TokenStreamError {
    /// ErrorCode
    code: u32,
    /// ErrorState (describing code)
    state: u8,
    /// The class (severity) of the error
    class: u8,
    /// The error message
    message: String,
    server_name: String,
    proc_name: String,
    line_number: u32
}

impl DecodeTokenStream for TokenStreamError {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamError> {
        let length = try!(cursor.read_u16::<LittleEndian>());

        Ok(TokenStreamError {
            code: try!(cursor.read_u32::<LittleEndian>()),
            state: try!(cursor.read_u8()),
            class: try!(cursor.read_u8()),
            message: try!(cursor.read_us_varchar()),
            server_name: try!(cursor.read_b_varchar()),
            proc_name: try!(cursor.read_b_varchar()),
            line_number: try!(cursor.read_u32::<LittleEndian>())
        })
    }
}

/// The login acknowledgement token stream "LOGINACK" as described by 2.2.7.13
#[derive(Debug)]
struct TokenStreamLoginAck {
    interface: u8,
    tds_version: u32,
    /// The name of the server
    prog_name: String,
    major_version: u8,
    minor_version: u8,
    build_num_high: u8,
    build_num_low: u8
}

impl DecodeTokenStream for TokenStreamLoginAck {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamLoginAck> {
        let length = try!(cursor.read_u16::<LittleEndian>());

        Ok(TokenStreamLoginAck {
            interface: try!(cursor.read_u8()),
            tds_version: try!(cursor.read_u32::<LittleEndian>()),
            prog_name: try!(cursor.read_b_varchar()),
            major_version: try!(cursor.read_u8()),
            minor_version: try!(cursor.read_u8()),
            build_num_high: try!(cursor.read_u8()),
            build_num_low: try!(cursor.read_u8())
        })
    }
}
