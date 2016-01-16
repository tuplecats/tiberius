extern crate tiberius;
use std::net::TcpStream;
use tiberius::{Guid, Connection};

fn main()
{
    //let mut test = vec![];
    //let mut cl = Client::new(test);
    let mut cl = Connection::connect_tcp("127.0.0.1", 1433).unwrap();
    let rows = cl.query("SELECT * FROM [test].[dbo].[test];").unwrap();
    println!("rows: {:?}", rows);
    for row in rows {
        let d: Option<&Guid> = row.get("test3");
        match d {
            None => (),
            Some(ref x) => println!("{}", x.as_str())
        }
        println!("data: {:?}", d);
    }
    //let mut buffer = [0; 4096];
    //cl.stream.read(&mut buffer).unwrap();
    //println!("{:?}", buffer.to_vec());
    //println!("{:?}", cl.stream);
}

fn get_connection() -> Connection<TcpStream> {
    Connection::connect_tcp("127.0.0.1", 1433).unwrap()
}

#[test]
fn test_datatypes_nullable() {
    let mut cl = get_connection();
    println!("--0");
    let rows = cl.query("SELECT * FROM [test].[dbo].[test];").unwrap();
    assert_eq!(rows.len(), 5);
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
}

#[test]
fn test_datatypes_not_nullable() {
    let mut cl = get_connection();
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
}
