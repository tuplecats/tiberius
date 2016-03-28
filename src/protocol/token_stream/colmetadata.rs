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

        // TODO: for prepared statements we may have to cache a stack of column types (for multi-queries)
        stmt.column_infos.clear();
        // NoMetaData 0xFFFF / (1 *ColumnData)
        match try!(cursor.read_u16::<LittleEndian>()) {
            0xFFFF => (),
            _ => {
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
