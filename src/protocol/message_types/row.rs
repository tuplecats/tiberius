use std::io::Cursor;
use std::io::prelude::*;
use byteorder::{LittleEndian, ReadBytesExt};
use super::{DecodeTokenStream, DecodeStmtTokenStream};
use protocol::util::{ReadCharStream};
use protocol::types::*;
use stmt::{ColumnValue, Statement};

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
pub struct TokenStreamRow {
    // text_ptr and timestamp are not specified if the value can be NULL
    // text_ptr: Vec<u8>, //slice possible?
    // timestamp: [u8; 8],
    // data: VarByte
    pub data: Vec<ColumnValue>
}

/// This does not implement `DecodeTokenStream` since it requires access to meta information
/// TODO: for the future, if there are multiple of these functions requiring meta information
/// add a new trait for function decode_meta
impl DecodeStmtTokenStream for TokenStreamRow {
    fn decode_stmt<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, stmt: &mut Statement) -> TdsResult<TokenStreamRow> {
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

            values.push(match column.type_info {
                TypeInfo::FixedLenType(ref f_type) => {
                    match *f_type {
                        FixedLenType::Int2 => ColumnValue::I16(try!(cursor.read_i16::<LittleEndian>())),
                        _ => panic!("unsupported ftype {:?}", f_type)
                    }
                },
                TypeInfo::VarLenType(ref v_type, _, ref collation) => {
                    match *v_type {
                        VarLenType::BigVarChar => {
                            let len = try!(cursor.read_u16::<LittleEndian>());
                            let mut buf = vec![0; len as usize];
                            try!(cursor.read(&mut buf));
                            match String::from_utf8(buf) {
                                Err(x) => return Err(TdsError::Conversion(Box::new(x))),
                                Ok(x) => ColumnValue::String(x)
                            }
                        },
                        _ => panic!("unsupported vtype {:?}", v_type)
                    }
                },
                _ => panic!("unsupported type {:?}", column.type_info)
            });
        }
        Ok(TokenStreamRow{ data: values })
    }
}
