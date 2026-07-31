//! pcapracer: fast PCAP/pcapng feature extraction to Parquet.

mod app;
mod config;
mod decode;
mod error;
mod flow;
mod pipeline;
mod reader;
mod reader_ng;
mod schema;
mod sink;
mod summary;
mod util;

use config::{Compression, Config, TableSet};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::PathBuf;

const DEFAULT_TABLES: [&str; 5] = ["packets", "flows", "dns", "http", "tls"];

fn derive_stem(input: &std::path::Path) -> String {
    let mut name = input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capture".to_string());
    for suffix in [".gz", ".pcapng", ".pcap", ".cap"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            name = stripped.to_string();
        }
    }
    if name.is_empty() {
        "capture".to_string()
    } else {
        name
    }
}

/// Poll the Python interrupt flag from within a released-GIL section.
fn check_signals() -> bool {
    Python::attach(|py| py.check_signals().is_err())
}

/// Extract features from a single capture file into Parquet tables.
#[pyfunction]
#[pyo3(signature = (
    input,
    *,
    output_dir=None,
    tables=None,
    compression="snappy",
    zstd_level=3,
    idle_timeout=120.0,
    active_threshold=1.0,
    max_flows=1_000_000,
    app_buffer_bytes=8192,
    hex_prefix_len=0,
    threads=0,
    batch_size=8192,
))]
#[allow(clippy::too_many_arguments)]
fn extract_one(
    py: Python<'_>,
    input: PathBuf,
    output_dir: Option<PathBuf>,
    tables: Option<Vec<String>>,
    compression: &str,
    zstd_level: i32,
    idle_timeout: f64,
    active_threshold: f64,
    max_flows: usize,
    app_buffer_bytes: usize,
    hex_prefix_len: usize,
    threads: usize,
    batch_size: usize,
) -> PyResult<Py<PyDict>> {
    let table_names =
        tables.unwrap_or_else(|| DEFAULT_TABLES.iter().map(|s| s.to_string()).collect());
    let tables = TableSet::from_names(&table_names)?;
    let compression = Compression::parse(compression, zstd_level)?;
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let stem = derive_stem(&input);

    let cfg = Config {
        input,
        output_dir,
        stem,
        tables,
        compression,
        idle_timeout,
        active_threshold,
        max_flows: max_flows.max(1),
        app_buffer_bytes,
        app_buffer_budget: 64 << 20,
        hex_prefix_len,
        threads,
        batch_size: batch_size.clamp(1, 1 << 20),
    };

    let summary = py.detach(|| pipeline::run(cfg, check_signals))?;

    let d = PyDict::new(py);
    d.set_item("packets", summary.packets)?;
    d.set_item("decode_errors", summary.decode_errors)?;
    d.set_item("elapsed_s", summary.elapsed_s)?;
    d.set_item("pkts_per_s", summary.pkts_per_s())?;
    let rows = PyDict::new(py);
    for (k, v) in &summary.table_rows {
        rows.set_item(k, v)?;
    }
    d.set_item("rows", rows)?;
    let paths = PyDict::new(py);
    for (k, v) in &summary.table_paths {
        paths.set_item(k, v)?;
    }
    d.set_item("paths", paths)?;
    Ok(d.unbind())
}

#[pymodule]
fn _pcapracer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(extract_one, m)?)?;
    Ok(())
}
