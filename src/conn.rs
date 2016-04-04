use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::io::prelude::*;
use std::net::{TcpStream, ToSocketAddrs};
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

pub trait TargetStream: Read + Write + fmt::Debug {}
impl<T: Read + Write + fmt::Debug> TargetStream for T {}

pub struct Connection<'a>(Rc<RefCell<InternalConnection<'a>>>);

#[derive(Debug)]
pub enum AuthenticationMethod<'a> {
    /// username, password
    InternalSqlServerAuth(Cow<'a, str>, Cow<'a, str>)
}

impl<'a> AuthenticationMethod<'a> {
    pub fn internal<U: Into<Cow<'a, str>>, P: Into<Cow<'a, str>>>(username: U, password: P) -> AuthenticationMethod<'a> {
        AuthenticationMethod::InternalSqlServerAuth(username.into(), password.into())
    }
}

pub struct ConnectionOptBuilder<'a> {
    auth: Option<AuthenticationMethod<'a>>,
    database: Option<Cow<'a, str>>,
}

impl<'a> ConnectionOptBuilder<'a> {
    pub fn new() -> ConnectionOptBuilder<'a> {
        ConnectionOptBuilder {
            auth: None,
            database: None,
        }
    }
    pub fn auth(mut self, method: AuthenticationMethod<'a>) -> ConnectionOptBuilder<'a> {
        self.auth = Some(method);
        self
    }

    pub fn db<D: Into<Cow<'a, str>>>(mut self, db: D) -> ConnectionOptBuilder<'a> {
        self.database = Some(db.into());
        self
    }

    pub fn build(self) -> ConnectionOptions<'a> {
        ConnectionOptions {
            auth: self.auth.unwrap(),
            database: self.database.unwrap(),
        }
    }
}

// TODO: allow connecting via URL, ... (easier usage)
#[derive(Debug)]
pub struct ConnectionOptions<'a> {
    pub auth: AuthenticationMethod<'a>,
    pub database: Cow<'a, str>,
}

pub trait IntoConnectOpts<'a> {
    fn into_connect_opts(self) -> TdsResult<ConnectionOptions<'a>>;
}

impl<'a> IntoConnectOpts<'a> for ConnectionOptions<'a> {
    fn into_connect_opts(self) -> TdsResult<ConnectionOptions<'a>> {
        Ok(self)
    }
}

// manual impl since autoderef seemed to mess up when cloning
impl<'a> Connection<'a> {
    pub fn clone(&'a self) -> Connection<'a> {
        Connection(self.0.clone())
    }
}

impl<'c> Connection<'c> {
    /// Execute the given query and return the resulting rows
    pub fn query<L>(&'c self, sql: L) -> TdsResult<QueryResult> where L: Into<Cow<'c, str>> {
        let stmt = StatementInternal::new(self.clone(), sql.into());
        Ok(try!(stmt.execute_into_query()))
    }

    /// Execute a sql statement and return the number of affected rows
    pub fn exec<L>(&'c self, sql: L) -> TdsResult<usize> where L: Into<Cow<'c, str>> {
        let mut stmt = StatementInternal::new(self.clone(), sql.into());
        Ok(try!(stmt.execute()))
    }

    pub fn prepare<L>(&'c self, sql: L) -> TdsResult<PreparedStatement<'c>> where L: Into<Cow<'c, str>> {
        Ok(try!(PreparedStatement::new(self.clone(), sql.into())))
    }
}

impl<'a> Deref for Connection<'a> {
    type Target = Rc<RefCell<InternalConnection<'a>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Connection<'a> {
    pub fn connect<T: IntoConnectOpts<'a>>(stream: Box<TargetStream>, opts: T) -> TdsResult<Connection<'a>> {
        let opts = try!(opts.into_connect_opts());
        let mut conn = InternalConnection::new(stream, opts);
        try!(conn.initialize());
        Ok(Connection(Rc::new(RefCell::new(conn))))
    }
}

pub struct TcpConnection;
impl<'a> TcpConnection {
    /// connect to the SQL server using the TCP protocol
    pub fn connect<A: ToSocketAddrs, T: IntoConnectOpts<'a>>(addrs: A, opts: T) -> TdsResult<Connection<'a>> {
        let stream = try!(TcpStream::connect(addrs));
        Ok(try!(Connection::connect(Box::new(stream), opts)))
    }
}

/// Internal representation of a Internal Connection
#[doc(hidden)]
pub struct InternalConnection<'a> {
    pub state: ClientState,
    last_packet_id: u8,
    pub stream: Box<TargetStream>,
    pub opts: ConnectionOptions<'a>,
}

impl<'c> InternalConnection<'c> {
    fn new(stream: Box<TargetStream>, opts: ConnectionOptions<'c>) -> InternalConnection<'c> {
        InternalConnection {
            stream: stream,
            state: ClientState::Initial,
            last_packet_id: 0,
            opts: opts,
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
        let mut login_packet = Login7::new(0x02000972);
        {
            login_packet.set_auth(&self.opts.auth);
            login_packet.set_db(self.opts.database.clone());
        }
        let packet = Packet::Login(login_packet);
        try!(self.send_packet(&packet));
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
    pub fn read_packet<'a>(&mut self) -> TdsResult<Packet<'a>> {
        let packet = try!(self.stream.read_message());
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
