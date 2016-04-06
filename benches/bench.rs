#![feature(test)]
extern crate test;
use test::Bencher;

extern crate tiberius;
use tiberius::{AuthenticationMethod, Connection, ConnectionOptBuilder, TcpConnection};

pub fn get_connection<'a>() -> Connection<'a> {
    let opts = ConnectionOptBuilder::new()
        .auth(AuthenticationMethod::internal("test", "test"))
        .db("test")
        .build();
    TcpConnection::connect(&("127.0.0.1", 1433), opts).unwrap()
}

#[bench]
fn bench_simple_query(b: &mut Bencher) {
    let cl = get_connection();
    b.iter(|| {
        let rows = cl.query(r#"SELECT col_text FROM [test].[dbo].[test] WHERE col_text LIKE "hello%";"#).unwrap();
        assert_eq!(rows.len(), 1);
        for row in rows {
            let d: Option<&str> = row.get("col_text");
            assert_eq!(d, Some("hello world!"));
            break;
        }
    });
}

#[bench]
fn bench_simple_query_prepared(b: &mut Bencher) {
    let cl = get_connection();
    let query = cl.prepare("SELECT col_text FROM [test].[dbo].[test] WHERE col_text LIKE @P1 + '%';").unwrap();
    b.iter(|| {
        let rows = query.query(&[&"hello"]).unwrap();
        assert_eq!(rows.len(), 1);
        for row in rows {
            let d: Option<&str> = row.get("col_text");
            assert_eq!(d, Some("hello world!"));
            break;
        }
    });
}
