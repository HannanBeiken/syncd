pub struct AuthConf {
    pub key_id: String,
    pub authorized_keys: Vec<String>,
}

#[derive(Debug)]
pub enum ResultTypes {
    OK,
    DecryptionError,
    FprMismatch,
    IoError,
    KeyMismatch,
    KeyNoSigAttr,
    ParseErr,
    UnauthKey,
    UnregisteredKey,
    UnknownErr,
    SigContentMismatch,
    SigErr,
    SigInvalid,
    TlsErr,
    TomlErr,
}

impl std::fmt::Display for ResultTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ResultTypes::DecryptionError => write!(f, "DecryptionError"),
            ResultTypes::FprMismatch => write!(f, "FprMismatch"),
            ResultTypes::IoError => write!(f, "IoError"),
            ResultTypes::KeyMismatch => write!(f, "KeyMismatch"),
            ResultTypes::KeyNoSigAttr => write!(f, "KeyNoSigAttr"),
            ResultTypes::OK => write!(f, "OK"),
            ResultTypes::ParseErr => write!(f, "ParseErr"),
            ResultTypes::UnauthKey => write!(f, "UnauthKey"),
            ResultTypes::UnknownErr => write!(f, "UnknownErr"),
            ResultTypes::UnregisteredKey => write!(f, "UnregisteredKey"),
            ResultTypes::SigContentMismatch => write!(f, "SigContentMismatch"),
            ResultTypes::SigErr => write!(f, "SigErr"),
            ResultTypes::SigInvalid => write!(f, "SigInvalid"),
            ResultTypes::TlsErr => write!(f, "TlsErr"),
            ResultTypes::TomlErr => write!(f, "TomlErr"),
        }
    }
}

pub fn rt_from_bytes(buf: &Vec<u8>) -> Result<ResultTypes, ResultTypes> {
    let buf: Vec<u8> = buf.clone();
    let string = String::from_utf8(buf).expect("Still Problemo");
    match string.as_str() {
        "OK" => return Ok(ResultTypes::OK),
        "DecryptionErr" => return Ok(ResultTypes::DecryptionError),
        _ => return Ok(ResultTypes::UnknownErr),
    }
}

impl From<std::string::FromUtf8Error> for ResultTypes {
    fn from(_: std::string::FromUtf8Error) -> Self {
        ResultTypes::ParseErr
    }
}

impl From<std::option::Option<std::str::Utf8Error>> for ResultTypes {
    fn from(_: std::option::Option<std::str::Utf8Error>) -> Self {
        ResultTypes::ParseErr
    }
}

impl From<std::net::AddrParseError> for ResultTypes {
    fn from(_: std::net::AddrParseError) -> Self {
        ResultTypes::ParseErr
    }
}

impl From<tokio_native_tls::native_tls::Error> for ResultTypes {
    fn from(_: tokio_native_tls::native_tls::Error) -> Self {
        ResultTypes::TlsErr
    }
}

impl From<std::io::Error> for ResultTypes {
    fn from(_: std::io::Error) -> Self {
        ResultTypes::IoError
    }
}

impl From<toml::de::Error> for ResultTypes {
    fn from(_: toml::de::Error) -> Self {
        ResultTypes::TomlErr
    }
}
