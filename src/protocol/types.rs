use std::borrow::Cow;
use std::io::prelude::*;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use encoding::{Encoding, EncoderTrap, DecoderTrap};
use encoding::all::UTF_16LE;
use protocol::util::{FromPrimitive, ReadCharStream};
use types::{ColumnValue, ColumnType, Guid};
use super::{DecodeTokenStream};
use ::{TdsResult, TdsError, TdsProtocolError};

#[derive(Debug)]
pub struct Collation {
    // lcid is first 20 bits (12 left), the next 8 bits are copied into flags, the next 4 into version
    lcid: u32,
    /// ignoreCase[1b], ignoreAccent[1b], ignoreKana[1b], ignoreWidth[1b], binary[1b], binary2[1b], reserved[2b]
    flags: u8,
    /// 4 bits!
    version: u8,
    sortid: u8
}

impl DecodeTokenStream for Collation {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<Collation> {
        let mut collation = Collation {
            lcid: try!(cursor.read_u32::<LittleEndian>()),
            sortid: try!(cursor.read_u8()),
            version: 0,
            flags: 0
        };
        collation.flags = (collation.lcid & 0x00000FF0) as u8;
        collation.version = (collation.lcid & 0x0000000F) as u8;
        collation.lcid = collation.lcid & 0xFFFFF000;
        Ok(collation)
    }
}

/// 2.2.5.4.1
#[derive(PartialEq, Debug, Clone)]
#[repr(u8)]
pub enum FixedLenType {
    // not supported yet, TODO: what is this?
    Null = 0x1F,
    Int1 = 0x30,
    Bit = 0x32,
    Int2 = 0x34,
    Int4 = 0x38,
    /// Small Date Time
    // not supported yet
    DateTim4 = 0x3A,
    Float4 = 0x3B,
    // not supported yet
    Money8 = 0x3C,
    // not supported yet
    DateTime = 0x3D,
    Float8 = 0x3E,
    Money4 = 0x7A,
    Int8 = 0x7F,
}
impl_from_primitive!(FixedLenType, Null, Int1, Bit, Int2, Int4, DateTim4, Float4, Money8, DateTime, Float8, Money4, Int8);

/// 2.2.5.4.2
#[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum VarLenType {
    Guid = 0x24,
    Intn = 0x26,
    // not supported yet (scale, precision)
    Decimal = 0x37,
    // not supported yet "
    Numeric = 0x3F,
    // not supported yet
    Bitn = 0x68,
    // not supported yet "
    Decimaln = 0x6A,
    // not supported yet "
    Numericn = 0x6C,
    // not supported yet
    Floatn = 0x6D,
    // not supported yet
    Money = 0x6E,
    // not supported yet
    Datetimen = 0x6F,
    //Daten = 0x28 ; (introduced in TDS 7.3 TODO add support)
    //Timen = 0x29 ; (introduced in TDS 7.3)
    //Datetime2 = 0x2A ; (introduced in TDS 7.3)
    //DatetimeOffsetn = 0x2B ; (introduced in TDS 7.3)
    /// legacy types

    // not supported yet
    Char = 0x2F,
    // not supported yet
    VarChar = 0x27,
    // not supported yet
    Binary = 0x2D,
    // not supported yet
    VarBinary = 0x25,
    /// big types

    // not supported yet
    BigVarBin = 0xA5,
    BigVarChar = 0xA7,
    BigBinary = 0xAD,
    BigChar = 0xAF,
    NVarchar = 0xE7,
    // not supported yet
    NChar = 0xEF,
    // not supported yet
    Xml = 0xF1,
    // not supported yet
    Udt = 0xF0,
    Text = 0x23,
    // not supported yet
    Image = 0x22,
    // not supported yet
    NText = 0x63,
    // not supported yet
    SSVariant = 0x62
}
impl_from_primitive!(VarLenType, Guid, Intn, Decimal, Numeric, Bitn, Decimaln, Numericn, Floatn, Money, Datetimen, Char, VarChar, Binary, VarBinary,
    BigVarBin, BigVarChar, BigBinary, BigChar, NVarchar, NChar, Xml, Udt, Text, Image, NText, SSVariant);

#[derive(Debug)]
pub enum VarLen {
    Byte(u8),
    UShortCharBin(u16),
    Long(i32)
}

#[derive(Debug)]
pub enum TypeInfo {
    FixedLenType(FixedLenType),
    /// VARLENTYPE TYPE_VARLEN [COLLATION]
    VarLenType(VarLenType, VarLen, Option<Collation>),
    /// VARLENTYPE TYPE_VARLEN [PRECISION SCALE]
    VarLenTypeP(VarLenType, VarLen, u8, u8),
}

impl DecodeTokenStream for TypeInfo {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TypeInfo> {
        let tyid = try!(cursor.read_u8());
        let tmp = FromPrimitive::from(tyid);

        Ok(match tmp {
            None => {
                let tmp: Option<VarLenType> = FromPrimitive::from(tyid);
                match tmp {
                    None => return Err(TdsError::Other(format!("column data type {} not supported", tyid))),
                    Some(var_len_type) => {
                        let mut has_collation = false;

                        let len = match var_len_type {
                            VarLenType::Guid | VarLenType::Intn => VarLen::Byte(try!(cursor.read_u8())),
                            VarLenType::NVarchar | VarLenType::BigChar | VarLenType::BigVarChar => {
                                // TODO: BIGCHARTYPE, BIGVARCHRTYPE, TEXTTYPE, NTEXTTYPE,NCHARTYPE, NVARCHARTYPE also include collation
                                has_collation = true;
                                VarLen::UShortCharBin(try!(cursor.read_u16::<LittleEndian>()))
                            },
                            VarLenType::BigBinary => {
                                VarLen::UShortCharBin(try!(cursor.read_u16::<LittleEndian>()))
                            },
                            VarLenType::Text => {
                                has_collation = true;
                                VarLen::Long(try!(cursor.read_i32::<LittleEndian>()))
                            },
                            _ => return Err(TdsError::Other(format!("variable length type {:?} not supported", var_len_type)))
                        };
                        if has_collation {
                            TypeInfo::VarLenType(var_len_type, len, Some(try!(Collation::decode(cursor))))
                        } else {
                            TypeInfo::VarLenType(var_len_type, len, None)
                        }
                    }
                }
            },
            Some(x) => TypeInfo::FixedLenType(x)
        })
    }
}

/// 2.2.7.4
#[derive(Debug)]
pub struct ColumnData {
    pub user_type: u32,
    /// fNullable[1b], fCaseSen[1b], usUpdateable[2b], fIdentity[1b], fComputed[1b], usReservedODBC[2b]
    /// fFixedLenCLRType[1b], usReserved[4b], fHidden[1b], fKey[1b], fNullableUnknown[1b]
    pub flags: u16,
    pub type_info: TypeInfo,
    pub table_name: Option<Vec<String>>,
    pub col_name: Option<String>,
}

impl DecodeTokenStream for ColumnData {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<ColumnData> {
        let user_type = try!(cursor.read_u32::<LittleEndian>());
        let flags = try!(cursor.read_u16::<LittleEndian>());

        let type_info = try!(TypeInfo::decode(cursor));
        let has_tablename = match type_info {
            TypeInfo::VarLenType(ref ty, _, _) | TypeInfo::VarLenTypeP(ref ty, _, _, _) => {
                match *ty {
                    VarLenType::Text => true,
                    _ => false
                }
            },
            _ => false
        };
        let tablename = match has_tablename {
            true => {
                let parts = try!(cursor.read_u8());
                match parts {
                    0 => None,
                    _ => {
                        let mut data: Vec<String> = Vec::with_capacity(parts as usize);
                        for _ in 0..parts {
                            data.push(try!(cursor.read_us_varchar()));
                        }
                        Some(data)
                    }
                }
            },
            false => None
        };

        // colname
        let colname = try!(cursor.read_b_varchar());
        Ok(ColumnData {
            user_type: user_type,
            flags: flags,
            type_info: type_info,
            table_name: tablename,
            col_name: Some(colname)
        })
    }
}

impl ColumnData {
    #[inline]
    pub fn is_nullable(&self) -> bool {
        (self.flags & 1) == 1
    }
}

/// basically decodes a TYPE_VARBYTE
impl<'a> ColumnValue<'a> {
    pub fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, tyinfo: &TypeInfo) -> TdsResult<ColumnValue<'a>> {
        Ok(match *tyinfo {
            TypeInfo::FixedLenType(ref f_type) => {
                match *f_type {
                    FixedLenType::Bit => ColumnValue::Some(ColumnType::Bool(try!(cursor.read_u8()) == 1)),
                    FixedLenType::Int1 => ColumnValue::Some(ColumnType::I8(try!(cursor.read_i8()))),
                    FixedLenType::Int2 => ColumnValue::Some(ColumnType::I16(try!(cursor.read_i16::<LittleEndian>()))),
                    FixedLenType::Int4 => ColumnValue::Some(ColumnType::I32(try!(cursor.read_i32::<LittleEndian>()))),
                    FixedLenType::Int8 => ColumnValue::Some(ColumnType::I64(try!(cursor.read_i64::<LittleEndian>()))),
                    FixedLenType::Float4 => ColumnValue::Some(ColumnType::F32(try!(cursor.read_f32::<LittleEndian>()))),
                    FixedLenType::Money4 => ColumnValue::Some(ColumnType::F32(try!(cursor.read_i32::<LittleEndian>()) as f32 / (10u32.pow(4) as f32))),
                    FixedLenType::Float8 => ColumnValue::Some(ColumnType::F64(try!(cursor.read_f64::<LittleEndian>()))),
                    //FixedLenType::Money8 => ColumnValue::Some(ColumnType::F64(try!(cursor.read_i64::<BigEndian>()) as f64 / (10u32.pow(4) as f64))),
                    _ => panic!("unsupported ftype {:?}", f_type)
                }
            },
            TypeInfo::VarLenType(ref v_type, _, ref collation) => {
                match *v_type {
                    VarLenType::BigChar | VarLenType::BigVarChar => {
                        let len = try!(cursor.read_u16::<LittleEndian>());
                        match len == 0xFFFF {
                            true => ColumnValue::None,
                            false => {
                                let mut buf = vec![0; len as usize];
                                try!(cursor.read(&mut buf));
                                match String::from_utf8(buf) {
                                    Err(x) => return Err(TdsError::Conversion(Box::new(x))),
                                    Ok(x) => ColumnValue::Some(ColumnType::String(Cow::Owned(x)))
                                }
                            }
                        }
                    },
                    VarLenType::NVarchar => {
                        let len = try!(cursor.read_u16::<LittleEndian>());
                        match len == 0xFFFF {
                            true => ColumnValue::None,
                            false => {
                                let mut buf = vec![0; len as usize];
                                try!(cursor.read(&mut buf));
                                ColumnValue::Some(ColumnType::String(Cow::Owned(try!(UTF_16LE.decode(&buf, DecoderTrap::Strict)))))
                            }
                        }
                    },
                    VarLenType::BigBinary => {
                        let len = try!(cursor.read_u16::<LittleEndian>());
                        match len == 0xFFFF {
                            true => ColumnValue::None,
                            false => {
                                let mut buf = vec![0; len as usize];
                                try!(cursor.read(&mut buf));
                                ColumnValue::Some(ColumnType::Binary(buf))
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
                                match len < 0 {
                                    true => ColumnValue::None,
                                    false => {
                                        let mut buf = vec![0; len as usize];
                                        try!(cursor.read(&mut buf));
                                        match String::from_utf8(buf) {
                                            Err(x) => return Err(TdsError::Conversion(Box::new(x))),
                                            Ok(x) => ColumnValue::Some(ColumnType::String(Cow::Owned(x)))
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
            _ => panic!("unsupported type {:?}", tyinfo)
        })
    }
}