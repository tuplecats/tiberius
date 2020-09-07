use std::collections::HashMap;
use std::str::FromStr;

// Return early with an error if a condition is not satisfied.
macro_rules! ensure {
    ($cond:expr, $msg:literal) => {
        if !$cond {
            return Err($crate::Error::Conversion($msg.into()));
        };
    };
}

// Return early with an error.
macro_rules! bail {
    ($msg:literal) => {
        return Err($crate::Error::Conversion($msg.into()));
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err($crate::Error::Conversion(format!($fmt, $($arg)*).into()));
    };
}

/// JDBC connection string parser for SqlServer
///
/// [Read more](https://docs.microsoft.com/en-us/sql/connect/jdbc/building-the-connection-url?view=sql-server-ver15)
///
/// # Format
///
/// ```
/// jdbc:sqlserver://[serverName[\instanceName][:portNumber]][;property=value[;property=value]]
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct JdbcConnectionString {
    sub_protocol: &'static str,
    server_name: Option<String>,
    instance_name: Option<String>,
    port: Option<u16>,
    properties: HashMap<String, String>,
}

impl JdbcConnectionString {
    /// Access the connection sub-protocol
    pub(crate) fn sub_protocol(&self) -> &'static str {
        &self.sub_protocol
    }

    /// Access the connection server name
    pub(crate) fn server_name(&self) -> Option<&str> {
        self.server_name.as_ref().map(|s| s.as_str())
    }

    /// Access the connection's instance name
    pub(crate) fn instance_name(&self) -> Option<&str> {
        self.instance_name.as_ref().map(|s| s.as_str())
    }

    /// Access the connection's port
    pub(crate) fn port(&self) -> Option<u16> {
        self.port
    }

    /// Access the connection's key-value pairs
    pub(crate) fn properties(&self) -> &HashMap<String, String> {
        &self.properties
    }
}

// NOTE(yosh): unfortunately we can't parse using `split(';')` because JDBC
// strings support escaping. This means that `{;}` is valid and we need to write
// an actual LR parser.
impl FromStr for JdbcConnectionString {
    type Err = crate::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // Tokenize
        let mut res = vec![];
        let mut iter = input.chars();
        while let Some(char) = iter.next() {
            let token = match char {
                c if c.is_ascii_whitespace() => continue,
                ':' => TokenKind::Colon,
                '=' => TokenKind::Eq,
                '\\' => TokenKind::BSlash,
                '/' => TokenKind::FSlash,
                ';' => TokenKind::Semi,
                '{' => {
                    let mut buf = String::new();
                    loop {
                        match iter.next() {
                            None => bail!("unclosed escape literal"),
                            Some('}') => break,
                            Some(c) if c.is_ascii() => buf.push(c),
                            _ => bail!("Invalid JDBC token"),
                        }
                    }
                    TokenKind::Escaped(buf)
                }
                c if c.is_ascii_alphanumeric() => TokenKind::Atom(c),
                c => bail!("Invalid JDBC token: '{}'", c),
            };
            res.push(token);
        }

        // ```
        // jdbc:sqlserver://[serverName[\instanceName][:portNumber]][;property=value[;property=value]]
        // ^^^^^^^^^^^^^^^^^
        // ```
        let mut slashes_read = 0;
        let proto = iter.by_ref().take_while(|c| {
            if *c == '/' {
                slashes_read += 1;
            }
            slashes_read != 2
        });
        dbg!(&proto);
        ensure!(
            proto.eq(dbg!("jdbc:sqlserver://".chars())),
            "Invalid JDBC sub-protocol"
        );

        Ok(Self {
            sub_protocol: "jdbc:sqlserver",
            server_name: None,
            instance_name: None,
            port: None,
            properties: HashMap::new(),
        })
    }
}

struct Lexer {
    tokens: Vec<TokenKind>,
}

impl Lexer {
    fn tokenize() -> Self {}
}

enum TokenKind {
    Colon,
    Eq,
    BSlash,
    FSlash,
    Semi,
    /// An ident that falls inside a `{}` pair.
    Escaped(String),
    /// An identifier in the connection string.
    Atom(char),
}

#[cfg(test)]
mod test {
    use super::JdbcConnectionString;

    #[test]
    fn parse_sub_protocol() -> crate::Result<()> {
        let conn: JdbcConnectionString = "jdbc:sqlserver://".parse()?;
        assert_eq!(conn.sub_protocol(), "jdbc:sqlserver");
        Ok(())
    }
}
