use std::borrow::Borrow;
use std::convert::From;
use std::fmt::Debug;
use std::rc::Rc;
use std::io::prelude::*;
use std::ops::Deref;
use protocol::*;
use conn::{InternalConnection, ClientState};
use ::{TdsResult, TdsError};

#[derive(Debug)]
#[doc(hidden)]
pub struct Statement {
    pub column_infos: Vec<ColumnData>
}

impl Statement {
    pub fn new() -> Statement {
        Statement {
            column_infos: vec![],
        }
    }
}

/// A result row of a resultset of a query
#[derive(Debug)]
pub struct Row {
    stmt: Rc<Statement>,
    values: Vec<ColumnValue>
}

pub trait RowIndex {
    fn get_index(&self, row: &Row) -> Option<usize>;
}

impl RowIndex for usize {
    #[inline]
    fn get_index(&self, row: &Row) -> Option<usize> {
        Some(*self)
    }
}

impl<'a> RowIndex for &'a str {
    fn get_index(&self, row: &Row) -> Option<usize> {
        for (idx, column) in row.stmt.column_infos.iter().enumerate() {
            match column.col_name {
                Some(ref col_name) if col_name == *self => return Some(idx),
                _ => ()
            }
        }
        None
    }
}

impl<'a> Row {
    pub fn get<I: RowIndex + Debug, T>(&'a self, idx: I) -> T where Option<T>: From<&'a ColumnValue> {
        let idx = match idx.get_index(self) {
            Some(x) => x,
            None => panic!("unknown index: {:?}", idx)
        };
        match From::from(&self.values[idx]) {
            Some(x) => x,
            None => panic!("type mismatch for: {}, got instead: {:?}", idx, self.values[idx])
        }
    }
}

/// The converted SQL value of a column
#[derive(Debug)]
pub enum ColumnValue {
    I16(i16),
    String(String)
}

impl<'a> From<&'a ColumnValue> for Option<i16> {
    fn from(val: &'a ColumnValue) -> Option<i16> {
        match *val {
            ColumnValue::I16(i) => Some(i),
            _ => None
        }
    }
}

impl<'a> From<&'a ColumnValue> for Option<&'a str> {
    fn from(val: &'a ColumnValue) -> Option<&'a str> {
        match *val {
            ColumnValue::String(ref str_) => Some(str_),
            _ => None
        }
    }
}

/// The resultset of a query (containing the resulting rows)
#[derive(Debug)]
pub struct QueryResult {
    rows: Option<Vec<Row>>,
    stmt: Rc<Statement>
}

impl IntoIterator for QueryResult {
    type Item = Row;
    type IntoIter = ::std::vec::IntoIter<Row>;

    fn into_iter(self) -> Self::IntoIter {
        match self.rows {
            Some(x) => x.into_iter(),
            None => vec![].into_iter()
        }
    }
}

#[doc(hidden)]
pub struct StatementInternal<'a, S: 'a> where S: Read + Write {
    conn: &'a mut InternalConnection<S>,
    query: &'a str,
    statement: Statement
}

impl<'a, S: 'a> StatementInternal<'a, S> where S: Read + Write {
    pub fn new(conn: &'a mut InternalConnection<S>, query: &'a str) -> StatementInternal<'a, S> {
        StatementInternal {
            conn: conn,
            query: query,
            statement: Statement::new()
        }
    }

    pub fn execute_into_query(mut self) -> TdsResult<QueryResult> {
        try!(self.conn.internal_exec(self.query));
        let mut packet = try!(self.conn.stream.read_packet());
        try!(packet.parse_as_stmt_token_stream(&mut self.statement));
        let mut query_result = QueryResult {
            rows: None,
            stmt: Rc::new(self.statement)
        };
        match packet.data {
            PacketData::TokenStream(tokens) => {
                let mut rows = Vec::with_capacity(tokens.len());
                for token in tokens {
                    match token {
                        TokenStream::Error(x) => return Err(TdsError::ServerError(x)),
                        TokenStream::Row(row) => rows.push(Row { values: row.data, stmt: query_result.stmt.clone() }),
                        _ => ()
                    }
                }
                query_result.rows = Some(rows);
                return Ok(query_result)
            },
            _ => ()
        }
        Ok(query_result)
    }
}
