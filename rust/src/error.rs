use thiserror::Error;

/// Why a single dissector gave up on a single packet.
///
/// These are expected in ordinary captures — a snaplen-truncated frame or an unsupported
/// link type is not an error condition for the run as a whole. The packet is still emitted,
/// with whatever layers parsed before the failure, and the `malformed`/`truncated` columns
/// record what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DissectError {
    #[error("ran off the end of the buffer")]
    Truncated,
    #[error("field values are inconsistent or out of range")]
    Malformed,
    #[error("protocol recognised but not dissected")]
    Unsupported,
    #[error("tunnel nesting limit reached")]
    DepthExceeded,
}

pub type DResult<T> = std::result::Result<T, DissectError>;

/// Failures that abort the whole run, as opposed to one packet.
#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a pcap or pcapng file: {0}")]
    Format(String),
    #[error("arrow: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    #[error("parquet: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("{0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for pyo3::PyErr {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(io) => pyo3::exceptions::PyIOError::new_err(io.to_string()),
            Error::Format(m) => pyo3::exceptions::PyValueError::new_err(m),
            Error::Config(m) => pyo3::exceptions::PyValueError::new_err(m),
            other => pyo3::exceptions::PyRuntimeError::new_err(other.to_string()),
        }
    }
}
