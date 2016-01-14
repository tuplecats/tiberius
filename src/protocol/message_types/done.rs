use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use super::DecodeTokenStream;
use ::{TdsResult};

/// The token stream "DONE" as described by 2.2.7.5
#[derive(Debug)]
pub struct TokenStreamDone {
    /// A combination of flags defined in TokenStreamDoneStatus
    pub status: u16,
    pub cur_cmd: u16,
    pub done_row_count: u64
}

#[repr(u16)]
pub enum TokenStreamDoneStatus {
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
