use std::io::prelude::*;
use std::net::TcpStream;

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
pub struct Connection<S: Write>(InternalConnection<S>);

impl<S: Read + Write> Connection<S> {
    /// Execute the given query and return the resulting rows
    pub fn query<'a>(&'a mut self, sql: &'a str) -> TdsResult<QueryResult> {
        let stmt = StatementInternal::new(&mut self.0, sql);
        Ok(try!(stmt.execute_into_query()))
    }

    /// Execute a sql statement and return the number of affected rows
    pub fn exec(&mut self, sql: &str) -> TdsResult<usize> {
        let mut stmt = StatementInternal::new(&mut self.0, sql);
        Ok(try!(stmt.execute()))
    }

    pub fn prepare<'a>(&'a mut self, sql: &str) -> TdsResult<PreparedStatement<S>> {
        Ok(try!(PreparedStatement::new(&mut self.0, sql)))
    }
}

impl Connection<TcpStream> {
    pub fn connect_tcp(host: &str, port: u16) -> TdsResult<Connection<TcpStream>> {
        let mut conn = InternalConnection::new(try!(TcpStream::connect(&(host, port))));
        try!(conn.initialize());
        Ok(Connection(conn))
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
        try!(self.send_packet(PacketData::PreLogin(vec![
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
        try!(self.send_packet(PacketData::Login(login_packet)));
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
        try!(self.send_packet(PacketData::SqlBatch(sql)));
        Ok(())
    }

    /// read and parse "simple" packets
    fn read_packet(&mut self) -> TdsResult<Packet> {
        let mut packet = try!(self.stream.read_packet());
        match self.state {
            ClientState::Initial => {
                try!(packet.parse_as_prelogin());
            },
            ClientState::PreloginPerformed => {
                try!(packet.parse_as_general_token_stream());
            },
            ClientState::Ready => {
                panic!("read_packet: cannot be used in ready state");
            }
        }
        Ok(packet)
    }

    /// Allocate an id and send a packet with the given data
    pub fn send_packet(&mut self, data: PacketData) -> TdsResult<()> {
        let mut header = PacketHeader::new();
        header.id = self.alloc_id();
        let mut packet = Packet {
            header: header,
            data: data
        };
        try!(self.stream.write_packet(&mut packet));
        Ok(())
    }
}
