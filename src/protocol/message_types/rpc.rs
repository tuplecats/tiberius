use std::io::prelude::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use protocol::TypeInfo;
use ::TdsResult;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum RpcProcId {
    SpPrepare = 11,
    SpExecute = 12,
    SpUnprepare = 15,
}

// only used for cipher stuff in TDS >= 7.4, which we dont support yet
// struct RpcParamCipher {
//     type_info: TypeInfo
// }

#[derive(Debug)]
pub struct RpcParamMetaData<'a> {
    pub name: &'a str,
    // fByRefValue[1b], fDefaultValue[1b], reserved[1b], fEncrypted[1b], reserved[4b]
    pub status_flags: u8,
    pub type_info: TypeInfo
}

#[derive(Debug)]
pub enum RpcProcIdValue {
    Name(String),
    Id(RpcProcId)
}

pub trait WriteRpcProcId {
    fn write_rpc_procid(&mut self, proc_id: &RpcProcIdValue) -> TdsResult<()>;
}

impl<W: Write> WriteRpcProcId for W {
    fn write_rpc_procid(&mut self, proc_id: &RpcProcIdValue) -> TdsResult<()> {
        match proc_id {
            //RpcProcIdValue::Name(ref name) => try!(self.write_b_varchar(name)),
            &RpcProcIdValue::Id(ref id) => {
                try!(self.write_u16::<LittleEndian>(0xFFFF));
                try!(self.write_u8((*id).clone() as u8))
            },
            _ => panic!("write_rpc_procid: not implemented for Name")
        }
        Ok(())
    }
}

/// 2.2.6.6
#[derive(Debug)]
pub struct RpcRequestData<'a> {
    // NameLenProcID: US_VARCHAR || (0xFFFF USHORT(ProcId))
    pub proc_id: RpcProcIdValue,
    // fWithRecomp[1b], fNoMetaData[1b], fReuseMetaData[1b], reserved[5b]
    pub flags: u8,
    // reserved[8b]
    pub params: Vec<RpcParamMetaData<'a>>
}
