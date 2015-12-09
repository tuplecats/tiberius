use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use ::{Result, TdsError, TdsProtocolError};

use byteorder::{LittleEndian, BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{Offset, Local};
use encoding::{Encoding, EncoderTrap, DecoderTrap};
use encoding::all::UTF_16LE;
use num::FromPrimitive;

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
    fn read_packet(&mut self) -> Result<Packet>;
}

#[doc(hidden)]
pub trait WritePacket {
    fn write_packet(&mut self, packet: &mut Packet) -> Result<()>;
}

#[doc(hidden)]
trait WriteUtf16 {
    fn write_as_utf16(&mut self, s: &str) -> Result<usize>;
}

impl<W: Write> WriteUtf16 for W {
    /// Writes a UTF-16 string with double null terminator
    fn write_as_utf16(&mut self, s: &str) -> Result<usize> {
        let bytes = try!(UTF_16LE.encode(s, EncoderTrap::Strict));
        try!(self.write_all(&bytes));
        Ok(bytes.len())
    }
}

#[doc(hidden)]
trait ReadUsVarchar {
    fn read_us_varchar(&mut self) -> Result<String>;
}

impl<R: Read> ReadUsVarchar for R {
    fn read_us_varchar(&mut self) -> Result<String> {
        let len = try!(self.read_u16::<LittleEndian>()) * 2;
        let mut bytes: Vec<u8> = vec![0; len as usize];
        assert_eq!(try!(self.read(&mut bytes[..])), len as usize);
        Ok(try!(UTF_16LE.decode(&bytes, DecoderTrap::Strict)))
    }
}

/// The types a packet header can contain, as specified by 2.2.3.1.1

#[derive(Copy, Clone, Debug, NumFromPrimitive, PartialEq)]
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

/// 2.2.3.1.2
#[derive(Copy, Clone, Debug, NumFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum PacketStatus
{
    NormalMessage = 0,
    EndOfMessage = 1,
    IgnoreEvent = 1 | 2,
    ResetConnection = 8,
    ResetConnectionSkipTransaction = 16
}

#[derive(Copy, Clone, Debug, NumFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum MessageTypeToken
{
    EnvChange = 0xE3,
    Error = 0xAA,
    LoginAck = 0xAD
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

#[derive(Debug)]
pub struct Packet
{
    pub header: PacketHeader,
    pub data: PacketData
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
        try!(FromPrimitive::$from_fn(read_data).ok_or(TdsProtocolError::InvalidValue(format!($msg, read_data))))
    });
    ($_self:expr,$read_fn:ident,$read_gen:ty,$from_fn:ident,$msg:expr) => ({
        let read_data = try!($_self.$read_fn::<$read_gen>());
        try!(FromPrimitive::$from_fn(read_data).ok_or(TdsProtocolError::InvalidValue(format!($msg, read_data))))
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

impl Packet {
    pub fn parse_as_prelogin(&mut self) -> Result<()> {
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

    pub fn parse_as_token_stream(&mut self) -> Result<()> {
        let packet_data = extract_raw_data!(self);
        let mut cursor = Cursor::new(packet_data);

        let token_type = read_packet_data!(cursor, read_u8, from_u8, "unknown message token '0x{:x}'");
        match token_type {
            MessageTypeToken::Error => {
                let length = try!(cursor.read_u16::<LittleEndian>());
                let error_num = try!(cursor.read_u32::<LittleEndian>());
                let state = try!(cursor.read_u8());
                let class = try!(cursor.read_u8());
                let msg = try!(cursor.read_us_varchar());

                println!("error: {}", msg);
            },
            _ => panic!("token {:?} not supported yet", token_type)
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum PacketData
{
    None,
    RawData(Vec<u8>),
    /// as specified in 2.2.6.5
    PreLogin(Vec<OptionTokenPair>),
    /// as specified by 2.2.6.4
    Login(Login7)
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
    fn read_packet(&mut self) -> Result<Packet> {
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
   fn write_packet(&mut self, packet: &mut Packet) -> Result<()> {
        // prealloc header size so we can return the packet as a whole [including header]
        let mut buf = vec![];

        match packet.data {
            PacketData::None | PacketData::RawData(_) => { panic!("Writing none, should not happen"); },
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
            }
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

#[derive(Copy, Clone, Debug, NumFromPrimitive)]
#[repr(u8)]
pub enum EncryptionSetting
{
    EncryptOff = 0,
    EncryptOn = 1,
    EncryptNotSupported = 2,
    EncryptRequired = 3
}

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
    fn read_option_token(&mut self, token: u8, max_len: u16) -> Result<OptionTokenPair>;
}

trait WriteOptionToken {
    fn write_option_token(&mut self, option: &OptionTokenPair) -> io::Result<()>;
}

impl<R: BufRead> ReadOptionToken for R {
    fn read_option_token(&mut self, token: u8, max_len: u16) -> Result<OptionTokenPair> {
        Ok(match token {
            0 => OptionTokenPair::Version(try!(self.read_u32::<BigEndian>()), try!(self.read_u16::<BigEndian>())),
            1 => {
                let read_data = try!(self.read_u8());
                OptionTokenPair::Encryption(try!(FromPrimitive::from_u8(read_data).ok_or(TdsProtocolError::InvalidValue(format!("prelogin: could not parse encryption: {}", read_data)))))
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
