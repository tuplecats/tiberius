use std::convert::From;
use std::fmt::Debug;
use std::rc::Rc;
use std::io::prelude::*;
use protocol::*;
use conn::{InternalConnection};
use types::{ColumnValue};
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
    fn get_index(&self, _: &Row) -> Option<usize> {
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

/// The resultset of a query (containing the resulting rows)
#[derive(Debug)]
pub struct QueryResult {
    rows: Option<Vec<Row>>,
    stmt: Rc<Statement>
}

impl QueryResult {
    /// return the number of contained rows
    pub fn len(&self) -> usize {
        return match self.rows {
            None => 0,
            Some(ref rows) => rows.len()
        }
    }

    /// return the row on a specific index, panics if the idx is out of bounds
    pub fn get<'a>(&'a self, idx: usize) -> &'a Row {
        match self.rows {
            None => (),
            Some(ref rows) => {
                if rows.len() > idx {
                    return &rows[idx]
                }
            }
        }
        panic!("queryresult: get: idx out of bounds");
    }
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

    pub fn execute(&mut self) -> TdsResult<usize> {
        try!(self.conn.internal_exec(self.query));
        let mut packet = try!(self.conn.stream.read_packet());
        try!(packet.parse_as_general_token_stream());
        match packet.data {
            PacketData::TokenStream(ref tokens) => {
                for token in tokens {
                    match *token {
                        TokenStream::Error(ref err) => {
                            return Err(TdsError::ServerError(err.clone()))
                        },
                        TokenStream::Done(ref done_token) => {
                            assert_eq!(done_token.status, TokenStreamDoneStatus::DoneCount as u16);
                            return Ok(done_token.done_row_count as usize)
                        },
                        _ => return Err(TdsError::Other(format!("exec: unexpected TOKEN {:?}", token)))
                    }
                }
            }
            , _ => ()
        }
        return Err(TdsError::Other(format!("exec: Unexpected packet {:?}", packet)))
    }
}

pub struct PreparedStatement<'a, S: 'a> where S: Read + Write {
    conn: &'a mut InternalConnection<S>
}

impl<'a, S> PreparedStatement<'a, S> where S: Read + Write {
    pub fn new(conn: &'a mut InternalConnection<S>, sql: &str) -> TdsResult<PreparedStatement<'a, S>> {
        let params_meta = vec![
            RpcParamMetaData {
                name: "handle",
                status_flags: 0,
                type_info: TypeInfo::FixedLenType(FixedLenType::Int4)
            },
            RpcParamMetaData {
                name: "params",
                status_flags: 0,
                type_info: TypeInfo::VarLenType(VarLenType::NVarchar, VarLen::Long(5), None) //TODO
            },
            RpcParamMetaData {
                name: "stmt",
                status_flags: 0,
                type_info: TypeInfo::VarLenType(VarLenType::NVarchar, VarLen::Long(sql.len() as i32), None)
            }
        ];
        //TODO
        let rpc_req = RpcRequestData {
            proc_id: RpcProcIdValue::Id(RpcProcId::SpPrepare),
            flags: 0,
            params: params_meta,
        };
        try!(conn.send_packet(PacketData::RpcRequest(&rpc_req)));
        {
            let mut packet = try!(conn.stream.read_packet());
            try!(packet.parse_as_general_token_stream());
            println!("{:?}", packet);
        }
        Ok(PreparedStatement{ conn: conn })
    }
}
