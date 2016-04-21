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

/// this test only ensures that preparing is possible for common data types
/// else there's a compile failure
#[test]
fn test_common_prepare_types() {
    let cl = get_connection();
    let stmt = cl.prepare("SELECT * FROM [test].[dbo].[test] WHERE id=@P1;").unwrap();
    stmt.query(&[&1u8, &1u16, &1u32, &1u64]).unwrap();
    stmt.query(&[&1i8, &1i16, &1i32, &1i64]).unwrap();
    stmt.query(&[&12.12f32, &23.23f64, &0f64, &0f64]).unwrap();
    stmt.query(&[&"12", &0f64, &0f64, &0f64]).unwrap();
}
