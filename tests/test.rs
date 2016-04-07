extern crate tiberius;
extern crate chrono;
use self::chrono::{NaiveDateTime};
use tiberius::{AuthenticationMethod, Guid, Connection, ConnectionOptBuilder, TcpConnection};

pub fn get_connection<'a>() -> Connection<'a> {
    let opts = ConnectionOptBuilder::new()
        .auth(AuthenticationMethod::internal("test", "test"))
        .db("test")
        .build();
    TcpConnection::connect(&("127.0.0.1", 1433), opts).unwrap()
}

#[test]
fn test_datatypes_nullable() {
    let cl = get_connection();
    let rows = cl.query("SELECT * FROM [test].[dbo].[test] ORDER BY id;").unwrap();
    assert_eq!(rows.len(), 6);
    // varchar(50): nullable
    let mut str1: Option<&str> = rows.get(0).get("col_varchar_50");
    assert_eq!(str1, Some("HelloWorld"));
    // int32: nullable
    let mut int1: Option<i32> = rows.get(0).get("col_int");
    assert_eq!(int1, None);
    // int32: nullable with value
    int1 = rows.get(2).get("col_int");
    assert_eq!(int1, Some(666));
    // guid: nullable with value
    let guid: Option<&Guid> = rows.get(1).get("col_guid");
    assert_eq!(guid.unwrap().as_str(), "e40c4fdc-2420-49a7-ab63-c0d51e9eb7f4");
    // char
    str1 = rows.get(3).get("col_char");
    assert_eq!(str1, Some("ab"));
    // text
    str1 = rows.get(3).get("col_text");
    assert_eq!(str1, None);
    str1 = rows.get(4).get("col_text");
    assert_eq!(str1, Some("hello world!"));
    // binary(50)
    let binary: &[u8] = rows.get(4).get("col_binary");
    assert!(binary.iter().take(6).eq([1, 2, 3, 4, 5, 6].iter()));
    // float
    let fl: f64 = rows.get(2).get("col_float");
    assert_eq!(fl, 42.42);
    // money
    let m: f64 = rows.get(3).get("col_money");
    assert_eq!(m, 52.26);
    // bit
    let b: bool = rows.get(1).get("col_bit");
    assert_eq!(b, true);
    // ntext
    let mut ntext: &str = rows.get(4).get("col_ntext");
    assert_eq!(ntext, "chinese:莊子");
    // text (16k)
    ntext = rows.get(5).get("col_text");
    assert_eq!(ntext.len(), 4096);
    assert!(ntext.chars().all(|c| c == 't'));
}

#[test]
fn test_datatypes_not_nullable() {
    let cl = get_connection();
    let rows = cl.query("SELECT * FROM [test].[dbo].[test_not_nullable];").unwrap();
    assert_eq!(rows.len(), 1);
    // varchar(50)
    let str1: &str = rows.get(0).get("col_varchar_50");
    assert_eq!(str1, "textvalue");
    // int32
    let int1: i32 = rows.get(0).get("col_int");
    assert_eq!(int1, 666);
    // guid
    let guid: &Guid = rows.get(0).get("col_guid");
    assert_eq!(guid.as_str(), "e40c4fdc-2420-49a7-ab63-c0d51e9eb7f4");
    // bit
    let bit1: bool = rows.get(0).get("col_bit");
    assert_eq!(bit1, true);
    // float8
    let float8: f64 = rows.get(0).get("col_float");
    assert_eq!(float8, 42.42);
    // nvarchar(50)
    let nvarchar: &str = rows.get(0).get("col_nvarchar_50");
    assert_eq!(nvarchar, "chinese:莊子");
    // smallmoney
    let money: f32 = rows.get(0).get("col_money4");
    assert_eq!(money, 52.10);
    // money
    let money: f64 = rows.get(0).get("col_money8");
    assert_eq!(money, 42.66);
    // datetime4
    let mut time: &NaiveDateTime = rows.get(0).get("col_datetime4");
    assert_eq!(time.to_string(), "2016-03-29 12:16:00");
    // datetime4
    time = rows.get(0).get("col_datetime8");
    assert_eq!(time.to_string(), "2015-02-26 12:42:00");
    // decimal(4, 2)
    let dec: f64 = rows.get(0).get("col_decimal");
    assert_eq!(dec, 42.42);
    // numeric(18, 0)
    let dec: f64 = rows.get(0).get("col_numeric");
    assert_eq!(dec, -43f64);
    // varbinary(5=)
    let bytes: &[u8] = rows.get(0).get("col_varbinary");
    assert_eq!(bytes, [0x00, 0x00, 0x01, 0x00]);
    // nchar(5)
    let nc: &str = rows.get(0).get("col_nchar");
    assert_eq!(nc, "abc       ");
    // col_image
    let mut test = [0u8; 30];
    test[28] = 2;
    let b: &[u8] = rows.get(0).get("col_image");
    assert_eq!(b, test);
}

#[test]
fn test_send_long_packet() {
    let cl = get_connection();
    let query = format!("SELECT col_varchar_50 FROM [test].[dbo].[test_not_nullable];{:4096}", "");
    let rows = cl.query(query).unwrap();
    assert_eq!(rows.len(), 1);
    // varchar(50)
    let str1: &str = rows.get(0).get("col_varchar_50");
    assert_eq!(str1, "textvalue");
}

#[test]
fn test_v73_datatypes() {
    let cl = get_connection();
    let rows = cl.query("SELECT * FROM [test].[dbo].[test_v73]").unwrap();
    assert_eq!(rows.len(), 1);
    let time: &NaiveDateTime = rows.get(0).get("col_datetime2");
    assert_eq!(time.to_string(), "2016-04-07 23:19:27.587");
}
