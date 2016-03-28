use std::borrow::Cow;
use std::convert::From;
use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::io::prelude::*;
use protocol::*;
use conn::{Connection};
use types::{ColumnType, ColumnValue, ToColumnType};
use ::{TdsResult, TdsError};

#[derive(Debug)]
#[doc(hidden)]
pub struct StatementInfo {
    pub column_infos: Vec<ColumnData>,
    /// The handle for e.g. prepared statements
    pub handle: Option<u32>,
}

impl StatementInfo {
    pub fn new() -> StatementInfo {
        StatementInfo {
            column_infos: vec![],
            handle: None,
        }
    }
}

/// A result row of a resultset of a query
#[derive(Debug)]
pub struct Row<'a> {
    stmt: Rc<RefCell<StatementInfo>>,
    values: Vec<ColumnValue<'a>>
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
        for (idx, column) in row.stmt.borrow().column_infos.iter().enumerate() {
            match column.col_name {
                Some(ref col_name) if col_name == *self => return Some(idx),
                _ => ()
            }
        }
        None
    }
}

impl<'a> Row<'a> {
    pub fn get<I: RowIndex + Debug, T>(&'a self, idx: I) -> T where Option<T>: From<&'a ColumnValue<'a>> {
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
pub struct QueryResult<'a> {
    rows: Option<Vec<Row<'a>>>,
    //stmt: Rc<RefCell<StatementInfo>>
}

impl<'a> QueryResult<'a> {
    /// return the number of contained rows
    pub fn len(&self) -> usize {
        return match self.rows {
            None => 0,
            Some(ref rows) => rows.len()
        }
    }

    /// return the row on a specific index, panics if the idx is out of bounds
    pub fn get(&self, idx: usize) -> &Row {
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

impl<'a> IntoIterator for QueryResult<'a> {
    type Item = Row<'a>;
    type IntoIter = ::std::vec::IntoIter<Row<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        match self.rows {
            Some(x) => x.into_iter(),
            None => vec![].into_iter()
        }
    }
}

#[doc(hidden)]
pub struct StatementInternal<'a, S: 'a> where S: Read + Write {
    conn: Connection<S>,
    query: &'a str,
    stmt: Rc<RefCell<StatementInfo>>,
}

fn handle_execute_packet(packet: &Packet) -> TdsResult<usize> {
    match *packet {
        Packet::TokenStream(ref tokens) => {
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
        },
        _ => ()
    }
    return Err(TdsError::Other(format!("exec: Unexpected packet {:?}", packet)))
}

fn handle_query_packet<'a>(packet: Packet<'a>, stmt: Rc<RefCell<StatementInfo>>) -> TdsResult<QueryResult<'a>> {
    let mut query_result = QueryResult {
        rows: None,
    };
    match packet {
        Packet::TokenStream(tokens) => {
            let mut rows = Vec::with_capacity(tokens.len());
            for token in tokens {
                match token {
                    TokenStream::Error(x) => return Err(TdsError::ServerError(x)),
                    TokenStream::Row(row) => rows.push(Row { values: row.data, stmt: stmt.clone() }),
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

impl<'a, S: 'a> StatementInternal<'a, S> where S: Read + Write {
    pub fn new(conn: Connection<S>, query: &'a str) -> StatementInternal<'a, S> {
        StatementInternal {
            conn: conn,
            query: query,
            stmt: Rc::new(RefCell::new(StatementInfo::new()))
        }
    }

    pub fn execute_into_query(mut self) -> TdsResult<QueryResult<'a>> {
        let mut conn = self.conn.borrow_mut();
        try!(conn.internal_exec(self.query));
        let packet = try!(try!(conn.stream.read_packet()).into_stmt_token_stream(&mut *self.stmt.borrow_mut()));
        handle_query_packet(packet, self.stmt)
    }

    pub fn execute(&mut self) -> TdsResult<usize> {
        let mut conn = self.conn.borrow_mut();
        try!(conn.internal_exec(self.query));
        let packet = try!(try!(conn.stream.read_packet()).into_general_token_stream());
        handle_execute_packet(&packet)
    }
}

pub struct PreparedStatement<'a, S: 'a> where S: Read + Write {
    conn: Connection<S>,
    stmt: Rc<RefCell<StatementInfo>>,
    sql: &'a str,
}

impl<'a, S> PreparedStatement<'a, S> where S: Read + Write {
    pub fn new(conn: Connection<S>, sql: &'a str) -> TdsResult<PreparedStatement<'a, S>> {
        Ok(PreparedStatement{
            conn: conn,
            sql: sql,
            stmt: Rc::new(RefCell::new(StatementInfo::new())),
        })
    }

    /// Prepares the actual statement
    fn do_prepare(&self, params: &[&ToColumnType]) -> TdsResult<()> {
        let mut param_str = String::new();
        // determine the types from the given params
        let mut i = 0;
        for param in params.iter() {
            if i > 0 {
                param_str.push(',')
            }
            i += 1;
            param_str.push_str(&format!("@P{} ", i));
            param_str.push_str(param.column_type());
        }
        let params_meta = vec![
            RpcParamData {
                name: "handle",
                status_flags: rpc::fByRefValue,
                value: ColumnType::I32(0),
            },
            RpcParamData {
                name: "params",
                status_flags: 0,
                value: ColumnType::String(Cow::Owned(param_str))
            },
            RpcParamData {
                name: "stmt",
                status_flags: 0,
                value: ColumnType::String(Cow::Borrowed(self.sql)),
            }
        ];
        let rpc_req = RpcRequestData {
            proc_id: RpcProcIdValue::Id(RpcProcId::SpPrepare),
            flags: 0,
            params: params_meta,
        };
        let rpc_packet = Packet::RpcRequest(&rpc_req);
        let mut conn = self.conn.borrow_mut();
        try!(conn.send_packet(&rpc_packet));
        {
            let packet = try!(try!(conn.stream.read_packet()).into_stmt_token_stream(&mut *self.stmt.borrow_mut()));
            try!(packet.catch_error());
            match packet {
                Packet::TokenStream(ref tokens) => {
                    for token in tokens {
                        match *token {
                            TokenStream::ReturnValue(ref retval) if retval.name == "handle" => {
                                if let ColumnValue::Some(ColumnType::I32(ihandle)) = retval.data {
                                    self.stmt.borrow_mut().handle = Some(ihandle as u32);
                                } else {
                                    return Err(TdsError::Other(format!("prepare: invalid handle id {:?}", tokens)))
                                }
                            },
                            _ => ()
                        }
                    }
                },
                _ => return Err(TdsError::Other(format!("exec: Unexpected packet {:?}", packet)))
            }
            if self.stmt.borrow().handle.is_none() {
                return Err(TdsError::Other(format!("prepare: did not receive a handle id {:?}", packet)))
            }
        }
        Ok(())
    }

    /// Makes sure the statement is prepared, since we lazily prepare statements
    /// and then executes the statement, handling it as a query and therefore returning the results as rows
    pub fn query(&self, params: &[&ToColumnType]) -> TdsResult<()> {
        if self.stmt.borrow().handle.is_none() {
            try!(self.do_prepare(params));
        }
        Ok(())
    }
}
