extern crate tiberius;
use std::net::TcpStream;
use tiberius::{Guid, Connection};
mod test;
use test::get_connection;

#[test]
fn test_simple_prepared() {
    let cl = get_connection();
    let stmt = cl.prepare("SELECT * FROM [test].[dbo].[test] WHERE id=@P1;").unwrap();
    {
        let rows = stmt.query(&[&3i32]);
        println!("{:?}", rows)
    }
}
