use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;
use std::io::prelude::*;
use std::net::TcpStream;
use std::ops::Deref;

use protocol::*;
use stmt::{StatementInternal, QueryResult, PreparedStatement};
use ::{TdsResult};

#[derive(Debug, PartialEq)]
pub enum ClientState {
    Initial,
    PreloginPerformed,
    Ready
}

/// A connection to a MSSQL server

pub struct Connection<S: Write>(Rc<RefCell<InternalConnection<S>>>);

// manual impl since autoderef seemed to mess up when cloning
impl<S: Read + Write> Connection<S> {
    pub fn clone(&self) -> Connection<S> {
        Connection(self.0.clone())
    }
}

impl<S: Read + Write> Connection<S> {
    /// Execute the given query and return the resulting rows
    pub fn query<'a, L>(&'a self, sql: L) -> TdsResult<QueryResult> where L: Into<Cow<'a, str>> {
        let stmt = StatementInternal::new(self.clone(), sql.into());
        Ok(try!(stmt.execute_into_query()))
    }

    /// Execute a sql statement and return the number of affected rows
    pub fn exec<'a, L>(&self, sql: L) -> TdsResult<usize> where L: Into<Cow<'a, str>> {
        let mut stmt = StatementInternal::new(self.clone(), sql.into());
        Ok(try!(stmt.execute()))
    }

    pub fn prepare<'a, L>(&self, sql: L) -> TdsResult<PreparedStatement<'a, S>> where L: Into<Cow<'a, str>> {
        Ok(try!(PreparedStatement::new(self.clone(), sql.into())))
    }
}

impl<S: Read + Write> Deref for Connection<S> {
    type Target = Rc<RefCell<InternalConnection<S>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Connection<TcpStream> {
    pub fn connect_tcp(host: &str, port: u16) -> TdsResult<Connection<TcpStream>> {
        let mut conn = InternalConnection::new(try!(TcpStream::connect(&(host, port))));
        try!(conn.initialize());
        Ok(Connection(Rc::new(RefCell::new(conn))))
    }
}

/// Internal representation of a Internal Connection
#[doc(hidden)]
pub struct InternalConnection<S: Write> {
    pub stream: S,
    pub state: ClientState,
    last_packet_id: u8,
}

impl<S: Read + Write> InternalConnection<S> {
    fn new(str: S) -> InternalConnection<S> {
        InternalConnection {
            stream: str,
            state: ClientState::Initial,
            last_packet_id: 0
        }
    }

    #[inline]
    fn alloc_id(&mut self) -> u8 {
        let id = self.last_packet_id;
        self.last_packet_id = (id + 1) % 255;
        return id;
    }

    /// Send a prelogin packet with version number 9.0.0000 (>=TDS 7.2 ?), and US_SUBBUILD=0 (for MSSQL always 0)
    fn initialize(&mut self) -> TdsResult<()> {
        try!(self.send_packet(&Packet::PreLogin(vec![
            OptionTokenPair::Version(0x09000000, 0),
            OptionTokenPair::Encryption(EncryptionSetting::EncryptNotSupported),
            OptionTokenPair::Instance("".to_owned()),
            OptionTokenPair::ThreadId(0),
            OptionTokenPair::Mars(0)
        ])));
        {
            let response_packet = try!(self.read_packet());
            try!(response_packet.catch_error());
        }
        self.state = ClientState::PreloginPerformed;
        let login_packet = Login7::new(0x02000972);
        try!(self.send_packet(&Packet::Login(login_packet)));
        {
            let response_packet = try!(self.read_packet());
            try!(response_packet.catch_error());
        }
        // TODO verify and use response data
        self.state = ClientState::Ready;
        Ok(())
    }

    #[inline]
    pub fn internal_exec(&mut self, sql: &str) -> TdsResult<()> {
        assert_eq!(self.state, ClientState::Ready);
        try!(self.send_packet(&Packet::SqlBatch(sql)));
        Ok(())
    }

    /// read and parse "simple" packets
    fn read_packet<'a>(&mut self) -> TdsResult<Packet<'a>> {
        let packet = try!(self.stream.read_packet());
        Ok(match self.state {
            ClientState::Initial => {
                try!(packet.into_prelogin())
            },
            ClientState::PreloginPerformed => {
                try!(packet.into_general_token_stream())
            },
            ClientState::Ready => {
                panic!("read_packet: cannot be used in ready state");
            }
        })
    }

    /// Allocate an id and send a packet with the given data
    pub fn send_packet(&mut self, packet: &Packet) -> TdsResult<()> {
        let mut header = PacketHeader::new();
        header.id = self.alloc_id();
        try!(self.stream.write_packet(&mut header, packet));
        Ok(())
    }
}
