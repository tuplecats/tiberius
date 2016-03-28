use std::borrow::Cow;
use std::io::Cursor;
use std::io::prelude::*;
use encoding::{Encoding, DecoderTrap};
use encoding::all::UTF_16LE;
use byteorder::{LittleEndian, ReadBytesExt};
use super::{DecodeTokenStream, DecodeStmtTokenStream};
use protocol::types::*;
use stmt::StatementInfo;
use types::{ColumnValue, ColumnType, Guid};

use ::{TdsResult, TdsError, TdsProtocolError};


/*enum VarByte {
    /// 0xFF
    Null,
    /// character type: 0xFFFF, binary type: [0xFF; 4]
    CharNull,
    // TODO,
    Var(VarLen, Vec<u8>)
}*/

/// 2.2.7.19
#[derive(Debug)]
pub struct TokenStreamRow<'a> {
    // text_ptr and timestamp are not specified if the value can be NULL
    // text_ptr: Vec<u8>, //slice possible?
    // timestamp: [u8; 8],
    // data: VarByte
    pub data: Vec<ColumnValue<'a>>
}

/// This does not implement `DecodeTokenStream` since it requires access to meta information
impl<'a> DecodeStmtTokenStream for TokenStreamRow<'a> {
    fn decode_stmt<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, stmt: &mut StatementInfo) -> TdsResult<TokenStreamRow<'a>> {
        let mut values = Vec::with_capacity(stmt.column_infos.len());
        for column in &stmt.column_infos {
            /*text_ptr: ??? let text_len = try!(cursor.read_u8());
            let mut bytes = vec![0; text_len as usize];
            for c in 0..text_len {
                bytes[c as usize] = try!(cursor.read_u8());
            }*/

            /* text/image let mut timestamp = [0; 8];
            for c in 0..8 {
                timestamp[c] = try!(cursor.read_u8());
            } */

            //println!("{:?}", timestamp);

            values.push(try!(ColumnValue::decode(cursor, &column.type_info)));
        }
        Ok(TokenStreamRow{ data: values })
    }
}
