use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use super::DecodeTokenStream;
use protocol::util::ReadCharStream;
use ::{TdsResult};

/// The login acknowledgement token stream "LOGINACK" as described by 2.2.7.13
#[derive(Debug)]
pub struct TokenStreamLoginAck {
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
