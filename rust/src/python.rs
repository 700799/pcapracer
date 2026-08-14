//! PyO3 bindings.
//!
//! The boundary is deliberately thin: options come across as scalars, results go back as
//! Arrow via the C Data Interface (zero copy — no per-row Python objects anywhere), and the
//! run report travels as a JSON string that the Python layer turns into a dict. Everything
//! user-facing — argument validation, defaults, the ergonomic API — lives in Python, where
//! it is easier to read and to change.

use std::path::PathBuf;

use arrow::pyarrow::ToPyArrow;
use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::api::{self, OutputOptions};
use crate::pipeline::{Config, Mode};
use crate::writer::Codec;

/// Assemble a pipeline config from the scalars Python sends.
#[allow(clippy::too_many_arguments)]
fn make_config(
    mode: &str,
    reassemble: bool,
    threads: usize,
    batch_size: usize,
    max_flows: usize,
    max_streams: usize,
    max_stream_bytes: usize,
) -> PyResult<Config> {
    Ok(Config {
        mode: Mode::parse(mode)?,
        reassemble,
        threads,
        batch_size: batch_size.max(1),
        max_flows: max_flows.max(1),
        max_streams: max_streams.max(1),
        max_stream_bytes: max_stream_bytes.max(1),
        ..Default::default()
    })
}

fn make_output(
    compression: &str,
    compression_level: i32,
    row_group_rows: usize,
) -> PyResult<OutputOptions> {
    Ok(OutputOptions {
        codec: Codec::parse(compression)?,
        level: compression_level,
        row_group_rows: row_group_rows.max(1),
    })
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    input, out_dir, mode, reassemble, threads, batch_size, compression,
    compression_level, row_group_rows, max_flows, max_streams, max_stream_bytes
))]
fn extract_to_parquet(
    py: Python<'_>,
    input: PathBuf,
    out_dir: PathBuf,
    mode: &str,
    reassemble: bool,
    threads: usize,
    batch_size: usize,
    compression: &str,
    compression_level: i32,
    row_group_rows: usize,
    max_flows: usize,
    max_streams: usize,
    max_stream_bytes: usize,
) -> PyResult<String> {
    let cfg = make_config(
        mode,
        reassemble,
        threads,
        batch_size,
        max_flows,
        max_streams,
        max_stream_bytes,
    )?;
    let out = make_output(compression, compression_level, row_group_rows)?;

    // The whole extraction runs without the GIL, so other Python threads keep going and
    // several captures can be processed concurrently from a thread pool.
    let report = py.detach(|| api::to_parquet(&input, &out_dir, cfg, out))?;
    Ok(serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string()))
}

/// Extract into memory. Returns `(packet_batches, flow_batch, stats_json)`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    input, mode, reassemble, threads, batch_size, max_flows, max_streams, max_stream_bytes
))]
fn extract_to_batches<'py>(
    py: Python<'py>,
    input: PathBuf,
    mode: &str,
    reassemble: bool,
    threads: usize,
    batch_size: usize,
    max_flows: usize,
    max_streams: usize,
    max_stream_bytes: usize,
) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyAny>, String)> {
    let cfg = make_config(
        mode,
        reassemble,
        threads,
        batch_size,
        max_flows,
        max_streams,
        max_stream_bytes,
    )?;

    let (batches, flows, stats) = py.detach(|| api::to_batches(&input, cfg))?;

    let list = PyList::empty(py);
    for b in &batches {
        list.append(b.to_pyarrow(py)?)?;
    }
    let flows = flows.to_pyarrow(py)?;
    Ok((
        list,
        flows,
        serde_json::to_string(&stats).unwrap_or_default(),
    ))
}

/// Stream batches to a Python callable, one at a time.
///
/// Memory stays bounded by `batch_size` rather than by the capture's size, which is the point
/// of having this alongside `extract_to_batches`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    input, callback, mode, reassemble, threads, batch_size, max_flows, max_streams, max_stream_bytes
))]
fn stream_batches(
    input: PathBuf,
    callback: Py<PyAny>,
    mode: &str,
    reassemble: bool,
    threads: usize,
    batch_size: usize,
    max_flows: usize,
    max_streams: usize,
    max_stream_bytes: usize,
) -> PyResult<String> {
    let cfg = make_config(
        mode,
        reassemble,
        threads,
        batch_size,
        max_flows,
        max_streams,
        max_stream_bytes,
    )?;

    // An exception raised by the callback is parked rather than flattened into a string, so
    // the original traceback survives back to the caller.
    let mut py_err: Option<PyErr> = None;

    // The GIL is reacquired only to hand each finished batch over; dissection between calls
    // runs detached.
    let result = crate::pipeline::run(&input, cfg, |batch| {
        Python::attach(|py| {
            match batch
                .to_pyarrow(py)
                .and_then(|obj| callback.call1(py, (obj,)))
            {
                Ok(_) => Ok(()),
                Err(e) => {
                    py_err = Some(e);
                    // Any error stops the run; the real one is re-raised below.
                    Err(crate::error::Error::Config("callback raised".into()))
                }
            }
        })
    });

    if let Some(e) = py_err {
        return Err(e);
    }
    let (stats, _flows) = result?;
    Ok(serde_json::to_string(&stats).unwrap_or_default())
}

/// Every column in the wide schema, in order. Lets Python expose the schema without
/// duplicating the list.
#[pyfunction]
fn wide_field_names() -> Vec<String> {
    crate::schema::FIELD_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The per-protocol table names split mode can produce.
#[pyfunction]
fn protocol_table_names() -> Vec<String> {
    crate::schema::split::PROTO_TABLES
        .iter()
        .map(|t| t.name.to_string())
        .collect()
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn _pcapracer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_to_parquet, m)?)?;
    m.add_function(wrap_pyfunction!(extract_to_batches, m)?)?;
    m.add_function(wrap_pyfunction!(stream_batches, m)?)?;
    m.add_function(wrap_pyfunction!(wide_field_names, m)?)?;
    m.add_function(wrap_pyfunction!(protocol_table_names, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
