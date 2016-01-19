use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use protocol::util::{FromPrimitive, ReadCharStream};
use super::{DecodeTokenStream};
use ::{TdsResult, TdsError};

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
#[derive(PartialEq, Debug)]
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
    Money = 0x3C,
    // not supported yet
    DateTime = 0x3D,
    Float8 = 0x3E,
    // not supported yet
    Money4 = 0x7A,
    Int8 = 0x7F,
}
impl_from_primitive!(FixedLenType, Null, Int1, Bit, Int2, Int4, DateTim4, Float4, Money, DateTime, Float8, Money4, Int8);

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

        let tyid = try!(cursor.read_u8());
        let tmp = FromPrimitive::from(tyid);
        let mut has_tablename = false;

        let type_info = match tmp {
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
                                has_tablename = true;
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
        };
        let tablename = if has_tablename {
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
        } else { None };

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
