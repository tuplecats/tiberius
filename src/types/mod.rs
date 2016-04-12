///! The SQL type mapping to rust
use std::borrow::Cow;
use std::io::Cursor;
use byteorder::{ReadBytesExt};
use chrono::{NaiveDateTime, NaiveDate, NaiveTime, DateTime, TimeZone, UTC, Local};
use protocol::{DecodeTokenStream};
use ::{TdsResult};

/// The converted SQL value of a column
#[derive(Debug)]
pub enum ColumnType<'a> {
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    String(Cow<'a, str>),
    Guid(Guid),
    Datetime(NaiveDateTime),
    Date(NaiveDate),
    Time(NaiveTime),
    Binary(Vec<u8>),
}

#[derive(Debug)]
pub enum ColumnValue<'a> {
    Some(ColumnType<'a>),
    None
}

pub trait ToColumnType {
    fn to_column_type(&self) -> ColumnType;
    fn column_type<'a>(&self) -> &'a str;
}

macro_rules! column_sql {
    ($ty:ty, $cty:ident, $name:expr) => { column_sql!($ty, $cty, $name, $ty); };
    ($ty:ty, $cty:ident, $name:expr, $cast:ty) => {
        impl ToColumnType for $ty {
            fn to_column_type(&self) -> ColumnType {
                ColumnType::$cty(*self as $cast)
            }

            fn column_type(&self) -> &'static str {
                $name
            }
        }
    }
}
column_sql!(i8, I8, "tinyint");
column_sql!(i16, I16, "smallint");
column_sql!(i32, I32, "int");
column_sql!(i64, I64, "bigint");
column_sql!(u8, I8, "tinyint", i8);
column_sql!(u16, I16, "smallint", i16);
column_sql!(u32, I32, "int", i32);
column_sql!(u64, I64, "bigint", i64);
// https://msdn.microsoft.com/en-us/library/ms173773.aspx
column_sql!(f32, F32, "float(24)");
column_sql!(f64, F64, "float(53)");

impl<'a> ToColumnType for &'a str {
    fn to_column_type(&self) -> ColumnType {
        ColumnType::String(Cow::Borrowed(self))
    }

    fn column_type(&self) -> &'static str {
        "nvarchar"
    }
}

macro_rules! column_conv_unpack {
    (pack, true, $val:expr) => (Some($val));
    (pack, false, $val:expr) => ($val);
    ($val:expr, true, $id:ident, $is_nullable:ident) => {
        match $val {
            ColumnValue::Some(ColumnType::$id(ref val)) => column_conv_unpack!(pack, $is_nullable, Some(val)),
            ColumnValue::None => column_conv_unpack!(pack, $is_nullable, None),
            _ => None
        }
    };
    ($val:expr, false, $id:ident, $is_nullable:ident) => {
        match $val {
            ColumnValue::Some(ColumnType::$id(val)) => column_conv_unpack!(pack, $is_nullable, Some(val)),
            ColumnValue::None => column_conv_unpack!(pack, $is_nullable, None),
            _ => None
        }
    }
}

macro_rules! column_conv_nullable {
    ($ty:ty, $id:ident, $by_ref:ident) => {
        impl <'a> From<&'a ColumnValue<'a>> for Option<Option<$ty>> {
            fn from(val: &'a ColumnValue) -> Option<Option<$ty>> {
                column_conv_unpack!(*val, $by_ref, $id, true)
            }
        }
    };
}

macro_rules! column_conv {
    ($ty:ty, $id:ident) => { column_conv!($ty, $id, false); };
    ($ty:ty, $id:ident, $by_ref:ident) => {
        impl <'a> From<&'a ColumnValue<'a>> for Option<$ty> {
            fn from(val: &'a ColumnValue) -> Option<$ty> {
                column_conv_unpack!(*val, $by_ref, $id, false)
            }
        }

        column_conv_nullable!($ty, $id, $by_ref);
    }
}

column_conv!(bool, Bool);
column_conv!(i32, I32);
column_conv!(f32, F32);
column_conv!(f64, F64);
column_conv!(&'a str, String, true);
column_conv!(&'a Guid, Guid, true);
column_conv!(&'a [u8], Binary, true);
column_conv!(&'a NaiveDateTime, Datetime, true);
column_conv!(&'a NaiveDate, Date, true);
column_conv!(&'a NaiveTime, Time, true);

impl <'a> From<&'a ColumnValue<'a>> for Option<DateTime<Local>> {
    fn from(val: &'a ColumnValue) -> Option<DateTime<Local>> {
        match *val {
            ColumnValue::Some(ColumnType::Datetime(ref dt)) => Some(UTC.from_utc_datetime(dt).with_timezone(&Local)),
            _ => None
        }
    }
}

impl <'a> From<&'a ColumnValue<'a>> for Option<Option<DateTime<Local>>> {
    fn from(val: &'a ColumnValue) -> Option<Option<DateTime<Local>>> {
        match *val {
            ColumnValue::None => Some(None),
            ColumnValue::Some(ColumnType::Datetime(ref dt)) => Some(Some(UTC.from_utc_datetime(dt).with_timezone(&Local))),
            _ => None
        }
    }
}

/// A TSQL uniqueidentifier/GUID
#[derive(Debug)]
pub struct Guid([u8; 16], Option<String>);
impl DecodeTokenStream for Guid {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<Guid> {
        let mut data = [0; 16];
        for c in 0..16 {
            data[c] = try!(cursor.read_u8());
        }
        Ok(Guid(data, None))
    }
}

impl<'a> Guid {
    pub fn as_str(&'a self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[3], self.0[2], self.0[1], self.0[0], self.0[5], self.0[4],
            self.0[7], self.0[6], self.0[8], self.0[9], self.0[10], self.0[11],
            self.0[12], self.0[13], self.0[14], self.0[15]
        )
    }
}
