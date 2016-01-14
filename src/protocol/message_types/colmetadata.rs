
struct ColumnData {
    user_type: u32,
    /// fNullable[1b], fCaseSen[1b], usUpdateable[2b], fIdentity[1b], fComputed[1b], usReservedODBC[2b]
    flags1: u8,
    /// fFixedLenCLRType[1b], usReserved[4b], fHidden[1b], fKey[1b], fNullableUnknown[1b]
    flags2: u8,
}

/// 2.2.7.4
struct TokenStreamColmetadata {
    token_type: u8,
    count: u16,
    /// NoMetaData / (1 *ColumnData)
    column_data: Option<ColumnData>,
}

struct TokenStreamColmetadata {
    impl decode<T: AsRef<[u8]>>(cursor: &mut Cursor<T>) -> TdsResult<TokenStreamColmetadata> {

    }
}
