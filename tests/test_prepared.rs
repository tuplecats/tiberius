extern crate tiberius;
mod test;
use test::get_connection;

#[test]
fn test_simple_prepared() {
    let cl = get_connection();
    let stmt = cl.prepare("SELECT * FROM [test].[dbo].[test] WHERE id=@P1;").unwrap();
    {
        let rows = stmt.query(&[&3i32]).unwrap();
        let int1: i32 = rows.get(0).get("col_int");
        assert_eq!(int1, 666);
    }
}
