//TODO: make chrono optional
use chrono::{Offset, Local};
use ::LIB_NAME;

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
pub struct Login7
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
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub app_name: String,
    pub server_name: String,
    pub library_name: String,
    /// initial lang
    pub language: String,
    /// initial db
    pub default_db: String,
    /// unique client identifier created by using the NIC-Address/MAC
    pub client_id: [u8; 6]
}

impl Login7 {
    /// Create a new Login7 packet for TDS7.3
    pub fn new() -> Login7 {
        Login7 {
            tds_version: 0x03000B73,
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
            hostname: "localhost".to_owned(), //TODO
            username: "test".to_owned(),
            password: "test".to_owned(),
            app_name: LIB_NAME.to_owned(),
            server_name: "localhost".to_owned(), //TODO
            library_name: LIB_NAME.to_owned(),
            language: "".to_owned(),
            default_db: "tempdb".to_owned(),
            client_id: [1, 2, 3, 4, 5, 6]
        }
    }
}