extern crate tiberius;
use std::net::TcpStream;
use tiberius::{Guid, Connection};
mod test;
use test::get_connection;

#[test]
fn test_simple_prepared() {
    let mut cl = get_connection();
    let stmt = cl.prepare("SELECT * FROM [test].[dbo].[test_not_nullable];");
    {
        //let rows = stmt.query([]);
        //println!("{:?}", rows)
    }
}
