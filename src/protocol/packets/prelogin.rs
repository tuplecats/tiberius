use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use protocol::FromPrimitive;
use protocol::util::WriteCStr;
use protocol::WriteTokenStream;
use ::{TdsResult, TdsError, TdsProtocolError};

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

impl<'a, W: Write> WriteTokenStream<&'a [OptionTokenPair]> for W {
    fn write_token_stream(&mut self, tokens: &'a [OptionTokenPair]) -> TdsResult<()> {
        let buf = vec![];
        let mut cursor = Cursor::new(buf);
        // write prelogin options (token, offset, length) [5 bytes] OR terminator
        let mut data_offset: u16 = 5 * tokens.len() as u16 + 1;
        for option in tokens {
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
        try!(self.write_all(&cursor.into_inner()));
        Ok(())
    }
}

impl OptionTokenPair {
    pub fn token(&self) -> u8 {
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

pub trait ReadOptionToken {
    fn read_option_token(&mut self, token: u8, max_len: u16) -> TdsResult<OptionTokenPair>;
}

pub trait WriteOptionToken {
    fn write_option_token(&mut self, option: &OptionTokenPair) -> io::Result<()>;
}

impl<R: BufRead> ReadOptionToken for R {
    fn read_option_token(&mut self, token: u8, max_len: u16) -> TdsResult<OptionTokenPair> {
        Ok(match token {
            0 => OptionTokenPair::Version(try!(self.read_u32::<BigEndian>()), try!(self.read_u16::<BigEndian>())),
            1 => {
                let read_data = try!(self.read_u8());
                OptionTokenPair::Encryption(try!(FromPrimitive::from(read_data).ok_or(TdsProtocolError::InvalidValue(format!("prelogin: could not parse encryption: {}", read_data), 0))))
            },
            2 => {
                let mut buf = vec![0 as u8; max_len as usize - 1];
                try!(self.read(&mut buf));
                OptionTokenPair::Instance(try!(String::from_utf8(buf).map_err(|_| TdsProtocolError::InvalidValue(format!("prelogin: invalid string for instance name"), 0))))
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
            _ => return Err(TdsError::from(TdsProtocolError::InvalidValue(format!("prelogin: option_token: invalid value {}", token), 0)))
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
