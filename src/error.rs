/// Error type.
use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "io error: {:?}", _0)]
    IoError(std::io::Error),
    #[fail(display = "invalid archive")]
    InvalidArchive,
    #[fail(display = "incorrect magic header")]
    IncorrectMagicHeader,
    #[fail(
        display = "unsupported arhive version; WARC 1.7 (from nukitashi) is currently supported"
    )]
    UnsupportedVersion,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}
