use std::io::Cursor;
use std::io::prelude::*;
use byteorder::{LittleEndian, ReadBytesExt};
use super::{DecodeTokenStream, DecodeStmtTokenStream};
use protocol::types::*;
use stmt::Statement;
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
                        FixedLenType::Bit => ColumnValue::Some(ColumnType::Bool(try!(cursor.read_u8()) == 1)),
                        FixedLenType::Int1 => ColumnValue::Some(ColumnType::I8(try!(cursor.read_i8()))),
                        FixedLenType::Int2 => ColumnValue::Some(ColumnType::I16(try!(cursor.read_i16::<LittleEndian>()))),
                        FixedLenType::Int4 => ColumnValue::Some(ColumnType::I32(try!(cursor.read_i32::<LittleEndian>()))),
                        FixedLenType::Int8 => ColumnValue::Some(ColumnType::I64(try!(cursor.read_i64::<LittleEndian>()))),
                        FixedLenType::Float4 => ColumnValue::Some(ColumnType::F32(try!(cursor.read_f32::<LittleEndian>()))),
                        FixedLenType::Float8 => ColumnValue::Some(ColumnType::F64(try!(cursor.read_f64::<LittleEndian>()))),
                        _ => panic!("unsupported ftype {:?}", f_type)
                    }
                },
                TypeInfo::VarLenType(ref v_type, _, ref collation) => {
                    match *v_type {
                        VarLenType::BigChar | VarLenType::BigVarChar => {
                            let len = try!(cursor.read_u16::<LittleEndian>());
                            match column.is_nullable() && len == 0xFFFF {
                                true => ColumnValue::None,
                                false => {
                                    let mut buf = vec![0; len as usize];
                                    try!(cursor.read(&mut buf));
                                    match String::from_utf8(buf) {
                                        Err(x) => return Err(TdsError::Conversion(Box::new(x))),
                                        Ok(x) => ColumnValue::Some(ColumnType::String(x))
                                    }
                                }
                            }
                        },
                        VarLenType::Text => {
                            // TODO what is textptr dummy stuff...
                            match try!(cursor.read_u8()) {
                                0 => ColumnValue::None,
                                text_ptr_len => {
                                    let mut buf = vec![0; text_ptr_len as usize]; //text_ptr
                                    try!(cursor.read(&mut buf));
                                    // Timestamp TODO: what is this..
                                    let mut timestamp = [0; 8];
                                    try!(cursor.read(&mut timestamp));
                                    let len = try!(cursor.read_i32::<LittleEndian>());

                                    if len < -1 {
                                        return Err(TdsError::ProtocolError(TdsProtocolError::InvalidLength(format!("text: invalid length of {}", len))));
                                    }
                                    match column.is_nullable() && len < 0 {
                                        true => ColumnValue::None,
                                        false => {
                                            let mut buf = vec![0; len as usize];
                                            try!(cursor.read(&mut buf));
                                            match String::from_utf8(buf) {
                                                Err(x) => return Err(TdsError::Conversion(Box::new(x))),
                                                Ok(x) => ColumnValue::Some(ColumnType::String(x))
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        VarLenType::Intn => {
                            let len = try!(cursor.read_u8());
                            match len {
                                0 => ColumnValue::None,
                                1 => ColumnValue::Some(ColumnType::I8(try!(cursor.read_i8()))),
                                2 => ColumnValue::Some(ColumnType::I16(try!(cursor.read_i16::<LittleEndian>()))),
                                4 => ColumnValue::Some(ColumnType::I32(try!(cursor.read_i32::<LittleEndian>()))),
                                8 => ColumnValue::Some(ColumnType::I64(try!(cursor.read_i64::<LittleEndian>()))),
                                _ => return Err(TdsError::ProtocolError(TdsProtocolError::InvalidLength(format!("intn: length of {} is invalid", len))))
                            }
                        },
                        VarLenType::Guid => {
                            let len = try!(cursor.read_u8());
                            match len {
                                0x10 => ColumnValue::Some(ColumnType::Guid(try!(Guid::decode(cursor)))),
                                0x00 => ColumnValue::None,
                                _ => return Err(TdsError::ProtocolError(TdsProtocolError::InvalidLength(format!("guid: length of {} is invalid", len))))
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
