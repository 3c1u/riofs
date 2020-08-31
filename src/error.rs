/// Error type.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("invalid archive")]
    InvalidArchive,
    #[error("incorrect magic header")]
    IncorrectMagicHeader,
    #[error(
        "unsupported arhive version; WARC 1.7 (from nukitashi) is currently supported"
    )]
    UnsupportedVersion,
}
