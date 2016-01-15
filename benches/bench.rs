#![feature(test)]
extern crate test;
use test::Bencher;

extern crate tiberius;
use tiberius::Connection;


#[bench]
fn bench_simple_query(b: &mut Bencher) {
    let mut cl = Connection::connect_tcp("127.0.0.1", 1433).unwrap();
    b.iter(|| {
        let rows = cl.query("SELECT test FROM [test].[dbo].[test];").unwrap();
        for row in rows {
            let d: &str = row.get("test");
            assert_eq!(d, "query-test");
            break;
        }
    });
}
