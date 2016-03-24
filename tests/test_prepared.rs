extern crate tiberius;
use std::net::TcpStream;
use tiberius::{Guid, Connection};
mod test;
use test::get_connection;

#[test]
fn test_simple_prepared() {
    let mut cl = get_connection();
    let mut stmt = cl.prepare("SELECT * FROM [test].[dbo].[test_not_nullable];").unwrap();
    //{
    //    let rows = stmt.query(&[&1i32]);
    //    println!("{:?}", rows)
    //}
}
