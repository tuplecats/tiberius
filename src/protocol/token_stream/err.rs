use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use super::DecodeTokenStream;
use protocol::util::ReadCharStream;
use ::{TdsResult};

/// The token stream "ERROR" as described by 2.2.7.9
#[derive(Clone, Debug)]
pub struct TokenStreamError {
    /// ErrorCode
    pub code: u32,
    /// ErrorState (describing code)
    pub state: u8,
    /// The class (severity) of the error
    pub class: u8,
    /// The error message
    pub message: String,
    pub server_name: String,
    pub proc_name: String,
    pub line_number: u32
}

impl DecodeTokenStream for TokenStreamError {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamError> {
        try!(cursor.read_u16::<LittleEndian>()); //length

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
