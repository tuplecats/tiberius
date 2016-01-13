use std::io::prelude::*;
use std::io;
use std::net::TcpStream;

use packets::*;
use ::{TdsResult, TdsError};

#[derive(Debug, PartialEq)]
enum ClientState {
    Initial,
    PreloginPerformed,
    Ready
}

pub struct Client<S: Write> {
/*dbg */pub stream: S,
    state: ClientState,
    last_packet_id: u8
}

impl Client<TcpStream> {
    pub fn connect_tcp(host: &str, port: u16) -> Result<Client<TcpStream>, io::Error> {
        let mut client = Client::new(try!(TcpStream::connect(&(host, port))));

        Ok(client)
    }
}

impl<S: Read + Write> Client<S> {
    pub /*dbg*/ fn new(str: S) -> Client<S> {
        Client {
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

    /// Send an prelogin packet with version number 9.0.0000 (>=TDS 7.2), and US_SUBBUILD=0 (for MSSQL always 0)
    pub fn initialize_connection(&mut self) -> TdsResult<()> {
        try!(self.send_packet(PacketData::PreLogin(vec![
            OptionTokenPair::Version(0x09000000, 0),
            OptionTokenPair::Encryption(EncryptionSetting::EncryptNotSupported),
            OptionTokenPair::Instance("".to_owned()),
            OptionTokenPair::ThreadId(0),
            OptionTokenPair::Mars(0)
        ])));
        {
            let mut response_packet = try!(self.read_packet());
            println!("{:?}", response_packet);
        }
        self.state = ClientState::PreloginPerformed;
        let login_packet = Login7::new();
        try!(self.send_packet(PacketData::Login(login_packet)));
        {
            let mut response_packet = try!(self.read_packet());
            println!("{:?}", response_packet);
            // TODO verify response
        }
        self.state = ClientState::Ready;
        Ok(())
    }

    /// Execute an SQL statement
    /// returns the amount of affected rows
    pub fn exec(&mut self, sql: &str) -> TdsResult<usize> {
        assert_eq!(self.state, ClientState::Ready);
        try!(self.send_packet(PacketData::SqlBatch(sql)));
        let p = try!(self.read_packet());
        match p.data {
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

        return Err(TdsError::Other(format!("exec: Unexpected packet {:?}", p)))
    }

    pub fn read_packet(&mut self) -> TdsResult<Packet> {
        let mut packet = try!(self.stream.read_packet());
        match self.state {
            ClientState::Initial => {
                try!(packet.parse_as_prelogin());
            },
            ClientState::PreloginPerformed => {
                try!(packet.parse_as_token_stream());
            },
            ClientState::Ready => {
                try!(packet.parse_as_token_stream());
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
