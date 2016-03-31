use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};
use super::DecodeTokenStream;
use protocol::util::ReadCharStream;
use ::{TdsResult, TdsProtocolError};

/// The environment change token stream "ENVCHANGE" as described by 2.2.7.8
#[derive(Debug)]
pub enum TokenStreamEnvChange {
    /// Change of database from old_value to new_value
    Database(String, Option<String>),
    PacketSize(String, Option<String>)
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum EnvChangeType {
    Database = 1,
    Language = 2,
    CharacterSet = 3,
    PacketSize = 4,
    /// Unicode data sorting local id
    UnicodeDataSortLID = 5,
    /// Unicode data sorting comparison flags
    UnicodeDataSortLCF = 6,
    SqlCollation = 7,
    BeginTransaction = 8,
    CommitTransaction = 9,
    RollbackTransaction = 10,
    EnlistDTCTransaction = 11,
    DefectTransaction = 12,
    /// Real Time Log Shipping
    Rtls = 13,
    PromoteTransaction = 15,
    TransactionManagerAddr= 16,
    TransactionEnded = 17,
    /// RESETCONNECTION/RESETCONNECTIONSKIPTRAN Completion Acknowledgement
    ResetConnectionAck= 18,
    /// Sends back name of user instance started per login request
    SessStartUserInst = 19,
    RoutingInformation = 20
}
impl_from_primitive!(EnvChangeType, Database, Language, CharacterSet, PacketSize, UnicodeDataSortLID, UnicodeDataSortLCF,
    SqlCollation, BeginTransaction, CommitTransaction, RollbackTransaction, EnlistDTCTransaction, DefectTransaction, Rtls,
    PromoteTransaction, TransactionManagerAddr, TransactionEnded, ResetConnectionAck, SessStartUserInst, RoutingInformation
);

impl DecodeTokenStream for TokenStreamEnvChange {
    fn decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamEnvChange> {
        let start_pos = cursor.position();
        let end_pos = start_pos + try!(cursor.read_u16::<LittleEndian>()) as u64;
        let token_type: EnvChangeType = read_packet_data!(None, cursor, read_u8, from_u8, "unknown envchange token type '0x{:x}'");
        Ok(match token_type {
            EnvChangeType::PacketSize => TokenStreamEnvChange::PacketSize(try!(cursor.read_b_varchar()), if cursor.position() < end_pos { Some(try!(cursor.read_b_varchar())) } else { None }),
            _ => panic!("unsupported envchange token: 0x{:x}", token_type as u8)
        })
    }
}
