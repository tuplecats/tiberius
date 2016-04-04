//TODO: make chrono optional
use std::borrow::Cow;
use std::io::prelude::*;
use std::io::Cursor;
use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use chrono::{Offset, Local};
use encoding::{Encoding, EncoderTrap};
use encoding::all::UTF_16LE;
use protocol::token_stream::WriteTokenStream;
use protocol::util::WriteUtf16;
use ::{LIB_NAME, TdsResult, AuthenticationMethod};

macro_rules! write_login_offset {
    ($cursor:expr, $pos:expr, $len:expr) => (write_login_offset!($cursor, $pos, $len, $len));
    ($cursor:expr, $pos:expr, $len:expr, $data_len:expr) => ({
        try!($cursor.write_u16::<LittleEndian>($pos));
        try!($cursor.write_u16::<LittleEndian>($len));
        $pos += $data_len;
    });
}

/// Login7 Packet as specified by 2.2.6.4
#[derive(Debug)]
pub struct Login7<'a>
{
    pub tds_version: u32,
    pub packet_size: u32,
    pub client_prog_ver: u32,
    pub client_pid: u32,
    pub conn_id: u32,
    /// consisting of: byteOrder[1-bit], charset[1b], float-type[2b], dump-load[1b], use-db[1b], succeed_database[1b], warn_lang_change[1b]
    pub flags1: u8,
    /// consisting of: succeed_lang[1b], is_odbc[1b], trans_boundary[1b], cacheconnect[1b], user_type[3b], integrated_security[1b]
    pub flags2: u8,
    /// consisting of: sql_type[4b], ole_db[1b], read_only_intent[1b], reserved[2b]
    pub type_flags: u8,
    /// consisting of: change_pwd[1b], send_yukon_binary_xml[1b], user_instance[1b], unknown_collation_handling[1b]
    pub flags3: u8,
    /// timezone offset to UTC [in minutes]
    pub timezone: i32,
    /// language code identifier
    pub lcid: u32,
    //OffsetLength
    pub hostname: Cow<'a, str>,
    pub username: Cow<'a, str>,
    pub password: Cow<'a, str>,
    pub app_name: Cow<'a, str>,
    pub server_name: Cow<'a, str>,
    pub library_name: Cow<'a, str>,
    /// initial lang
    pub language: Cow<'a, str>,
    /// initial db
    pub default_db: Cow<'a, str>,
    /// unique client identifier created by using the NIC-Address/MAC
    pub client_id: [u8; 6]
}

impl<'a> Login7<'a> {
    /// Create a new Login7 packet for TDS7.3
    pub fn new(tds_version: u32) -> Login7<'a> {
        Login7 {
            tds_version: tds_version,
            packet_size: 0x1000,
            client_prog_ver: 0,
            client_pid: 0,
            conn_id: 0,
            flags1: 0,
            flags2: 0,
            flags3: 0,
            type_flags: 0,
            timezone: Local::now().offset().local_minus_utc().num_minutes() as i32,
            lcid: 0x00000409,
            hostname: Cow::Borrowed(""),
            username: Cow::Borrowed(""),
            password: Cow::Borrowed(""),
            app_name: Cow::Borrowed(LIB_NAME),
            server_name: Cow::Borrowed(""),
            library_name: Cow::Borrowed(LIB_NAME),
            language: Cow::Borrowed(""),
            default_db: Cow::Borrowed(""),
            // todo make this unique?
            client_id: [1, 2, 3, 4, 5, 6],
        }
    }

    /// Apply the authentication method to the login packet by e.g. extracting username and password
    pub fn set_auth(&mut self, auth_method: &AuthenticationMethod<'a>) {
        match auth_method {
            &AuthenticationMethod::InternalSqlServerAuth(ref user, ref password) => {
                self.username = user.clone();
                self.password = password.clone();
            }
        }
    }

    /// Set the name of the default database
    pub fn set_db<'b, D: Into<Cow<'a, str>>>(&'b mut self, db: D) {
        self.default_db = db.into();
    }
}

impl<'a, W: Write> WriteTokenStream<&'a Login7<'a>> for W {
    fn write_token_stream(&mut self, login7: &'a Login7) -> TdsResult<()> {
        let buf = vec![];
        let mut cursor = Cursor::new(buf);
        let pos = cursor.position();
        // write the length at the end, skip 4 bytes for it (u32)
        cursor.set_position(pos + 4);
        try!(cursor.write_u32::<BigEndian>(login7.tds_version));
        try!(cursor.write_u32::<LittleEndian>(login7.packet_size));
        try!(cursor.write_u32::<LittleEndian>(login7.client_prog_ver));
        try!(cursor.write_u32::<LittleEndian>(login7.client_pid));
        try!(cursor.write_u32::<LittleEndian>(login7.conn_id));
        try!(cursor.write_u8(login7.flags1));
        try!(cursor.write_u8(login7.flags2));
        try!(cursor.write_u8(login7.type_flags));
        try!(cursor.write_u8(login7.flags3));
        try!(cursor.write_i32::<LittleEndian>(login7.timezone));
        try!(cursor.write_u32::<LittleEndian>(login7.lcid)); //LE? unused anyways
        let data_start: u16 = cursor.position() as u16 + (13 * 4) + 6;
        let mut data_pos = data_start;

        for (i, val) in [&login7.hostname, &login7.username, &login7.password, &login7.app_name, &login7.server_name,
            &login7.library_name, &login7.language, &login7.default_db].iter().enumerate() {
            let old_pos = cursor.position();
            cursor.set_position(data_pos as u64);
            //try!(cursor.write_cstr(val));
            let mut data_len = 0;
            if val.len() > 0 {
                // encode password
                if i == 2 {
                    let mut bytes = try!(UTF_16LE.encode(val, EncoderTrap::Strict));
                    for byte in bytes.iter_mut() {
                        *byte = (*byte >> 4) | ((*byte & 0x0f) << 4);
                        *byte ^= 0xa5;
                    }
                    try!(cursor.write_all(&bytes));
                    data_len = bytes.len() as u16;
                } else {
                    data_len = try!(cursor.write_as_utf16(val)) as u16;
                }
            }
            cursor.set_position(old_pos);
            write_login_offset!(cursor, data_pos, val.len() as u16, data_len);      //1,2,3,4,6,7,8,9

            if i == 4 {
                write_login_offset!(cursor, data_pos, 0);                           //5 [unused in TDSV7.3]
            }
        }
        try!(cursor.write(&login7.client_id));                                      //client unique ID
        write_login_offset!(cursor, data_pos, 0);                                   //10 [ibSSPI & cbSSPI]
        write_login_offset!(cursor, data_pos, 0);                                   //11 [ibAtchDBFile & cchAtchDBFile]
        write_login_offset!(cursor, data_pos, 0);                                   //12 [ibChangePassword & cchChangePassword]
        try!(cursor.write_u32::<LittleEndian>(0));                                  //13 [cbSSPILong]

        // write remaining data
        assert_eq!(cursor.position() as u16, data_start);
        // write length
        cursor.set_position(0);
        try!(cursor.write_u32::<LittleEndian>(data_pos as u32));
        try!(self.write_all(&cursor.into_inner()));
        Ok(())
    }
}