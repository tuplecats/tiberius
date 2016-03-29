#![feature(test)]
extern crate test;
use test::Bencher;

extern crate tiberius;
use tiberius::Connection;


#[bench]
fn bench_simple_query(b: &mut Bencher) {
    let cl = Connection::connect_tcp("127.0.0.1", 1433).unwrap();
    b.iter(|| {
        let rows = cl.query(r#"SELECT col_text FROM [test].[dbo].[test] WHERE col_text NOT LIKE "test";"#).unwrap();
        for row in rows {
            let d: Option<&str> = row.get("col_text");
            assert_eq!(d, Some("hello world!"));
            break;
        }
    });
}

#[bench]
fn bench_simple_query_prepared(b: &mut Bencher) {
    let cl = Connection::connect_tcp("127.0.0.1", 1433).unwrap();
    let query = cl.prepare("SELECT col_text FROM [test].[dbo].[test] WHERE col_text NOT LIKE @P1;").unwrap();
    b.iter(|| {
        let rows = query.query(&[&"test"]).unwrap();
        for row in rows {
            let d: Option<&str> = row.get("col_text");
            assert_eq!(d, Some("hello world!"));
            break;
        }
    });
}
