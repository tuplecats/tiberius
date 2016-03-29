use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use super::{DecodeTokenStream, DecodeStmtTokenStream};
use protocol::types::*;
use stmt::StatementInfo;
use ::{TdsResult};

/// 2.2.7.4
#[derive(Debug)]
pub enum TokenStreamColmetadata {
    None
}

impl DecodeStmtTokenStream for TokenStreamColmetadata {
    fn decode_stmt<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, stmt: &mut StatementInfo) -> TdsResult<TokenStreamColmetadata> {
        let count = try!(cursor.read_u16::<LittleEndian>());

        // This is not documented but nothing is sent after the count
        if count == 0xFFFF {
            return Ok(TokenStreamColmetadata::None)
        }

        // NoMetaData 0xFFFF / (1 *ColumnData)
        match try!(cursor.read_u16::<LittleEndian>()) {
            0xFFFF => (),
            _ => {
                stmt.column_infos.clear();
                let pos = cursor.position() - 2;
                cursor.set_position(pos);
                for _ in 0..count {
                    stmt.column_infos.push(try!(ColumnData::decode(cursor)));
                };
            }
        };

        // This directly writes to the specified meta data object and does not use the return value
        Ok(TokenStreamColmetadata::None)
    }
}
