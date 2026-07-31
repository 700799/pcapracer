use pyo3::exceptions::{PyIOError, PyRuntimeError, PyValueError};
use pyo3::PyErr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),

    #[error("arrow error: {0}")]
    Arrow(#[from] arrow_schema::ArrowError),

    #[error("operation interrupted")]
    Interrupted,

    #[error("{0}")]
    Other(String),
}

impl From<Error> for PyErr {
    fn from(e: Error) -> PyErr {
        match e {
            Error::Io(io) => PyIOError::new_err(io.to_string()),
            Error::Invalid(m) => PyValueError::new_err(m),
            Error::Unsupported(m) => PyValueError::new_err(m),
            Error::Interrupted => pyo3::exceptions::PyKeyboardInterrupt::new_err("interrupted"),
            other => PyRuntimeError::new_err(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
