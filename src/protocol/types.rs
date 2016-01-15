use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use protocol::util::{FromPrimitive, ReadCharStream};
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

impl Collation {
    pub fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<Collation> {
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
#[derive(Debug)]
#[repr(u8)]
pub enum FixedLenType {
    Null = 0x1F,
    Int1 = 0x30,
    Bit = 0x32,
    Int2 = 0x34,
    Int4 = 0x38,
    /// Small Date Time
    DateTim4 = 0x3A,
    Float4 = 0x3B,
    Money = 0x3C,
    DateTime = 0x3D,
    Float8 = 0x3E,
    Money4 = 0x7A,
    Int8 = 0x7F,
}
impl_from_primitive!(FixedLenType, Null, Int1, Bit, Int2, Int4, DateTim4, Float4, Money, DateTime, Float8, Money4, Int8);

/// 2.2.5.4.2
#[repr(u8)]
#[derive(Debug)]
pub enum VarLenType {
    Guid = 0x24,
    Intn = 0x26,
    Decimal = 0x37,
    Numeric = 0x3F,
    Bitn = 0x68,
    Decimaln = 0x6A,
    Numericn = 0x6C,
    Floatn = 0x6D,
    Money = 0x6E,
    Datetimen = 0x6F,
    //Daten = 0x28 ; (introduced in TDS 7.3 TODO add support)
    //Timen = 0x29 ; (introduced in TDS 7.3)
    //Datetime2 = 0x2A ; (introduced in TDS 7.3)
    //DatetimeOffsetn = 0x2B ; (introduced in TDS 7.3)
    // legacy types
    Char = 0x2F,
    VarChar = 0x27,
    Binary = 0x2D,
    VarBinary = 0x25,
    // big types
    BigVarBin = 0xA5,
    BigVarChar = 0xA7,
    BigBinary = 0xAD,
    BigChar = 0xAF,
    NVarchar = 0xE7,
    NChar = 0xEF,
    Xml = 0xF1,
    Udt = 0xF0,
    Text = 0x23,
    Image = 0x22,
    NText = 0x63,
    SSVariant = 0x62
}
impl_from_primitive!(VarLenType, Guid, Intn, Decimal, Numeric, Bitn, Decimaln, Numericn, Floatn, Money, Datetimen, Char, VarChar, Binary, VarBinary,
    BigVarBin, BigVarChar, BigBinary, BigChar, NVarchar, NChar, Xml, Udt, Text, Image, NText, SSVariant);

#[derive(Debug)]
pub enum VarLen {
    Byte(u8),
    UShortCharBin(u16),
    Long(u32)
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
    pub table_name: Option<String>,
    pub col_name: Option<String>,
}

impl ColumnData {
    pub fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<ColumnData> {

        let user_type = try!(cursor.read_u32::<LittleEndian>());
        let flags = try!(cursor.read_u16::<LittleEndian>());

        let tyid = try!(cursor.read_u8());
        let tmp = FromPrimitive::from(tyid);
        let type_info = match tmp {
            None => {
                let tmp: Option<VarLenType> = FromPrimitive::from(tyid);
                match tmp {
                    None => return Err(TdsError::Other(format!("column data type {} not supported", tyid))),
                    Some(var_len_type) => {
                        let mut has_collation = false;
                        let len = match var_len_type {
                            VarLenType::BigVarChar => {
                                // TODO: BIGCHARTYPE, BIGVARCHRTYPE, TEXTTYPE, NTEXTTYPE,NCHARTYPE, NVARCHARTYPE also include collation
                                has_collation = true;
                                VarLen::UShortCharBin(try!(cursor.read_u16::<LittleEndian>()))
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
        // tablename TODO
        // colname
        let colname = try!(cursor.read_b_varchar());
        Ok(ColumnData {
            user_type: user_type,
            flags: flags,
            type_info: type_info,
            table_name: None, //TODO
            col_name: Some(colname)
        })
    }
}
