use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use super::{DecodeTokenStream, DecodeStmtTokenStream};
use protocol::util::{FromPrimitive, ReadCharStream};
use protocol::types::*;
use stmt::Statement;
use ::{TdsResult, TdsProtocolError};

/// 2.2.7.4
#[derive(Debug)]
pub enum TokenStreamColmetadata {
    None
}

impl DecodeStmtTokenStream for TokenStreamColmetadata {
    fn decode_stmt<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, stmt: &mut Statement) -> TdsResult<TokenStreamColmetadata> {
        //TODO support packets with more than 1 column
        let count = try!(cursor.read_u16::<LittleEndian>());
        match try!(cursor.read_u16::<LittleEndian>()) {
            // NoMetaData 0xFFFF / (1 *ColumnData)
            0xFFFF => (),
            _ => {
                let pos = cursor.position() - 2;
                cursor.set_position(pos);
                stmt.column_infos.push(try!(ColumnData::decode(cursor)));
            }
        };

        // This directly writes to the specified meta data object and does not use the return value
        Ok(TokenStreamColmetadata::None)
    }
}
