use crate::error::{Error, Result};
use std::path::PathBuf;

/// Parquet compression codec selection.
#[derive(Clone, Copy, Debug)]
pub enum Compression {
    Uncompressed,
    Snappy,
    Zstd(i32),
}

impl Compression {
    pub fn parse(name: &str, zstd_level: i32) -> Result<Compression> {
        match name.to_ascii_lowercase().as_str() {
            "none" | "uncompressed" => Ok(Compression::Uncompressed),
            "snappy" | "snap" => Ok(Compression::Snappy),
            "zstd" => Ok(Compression::Zstd(zstd_level)),
            other => Err(Error::Invalid(format!(
                "unknown compression '{other}' (expected: none, snappy, zstd)"
            ))),
        }
    }

    pub fn to_parquet(self) -> parquet::basic::Compression {
        use parquet::basic::{Compression as PC, ZstdLevel};
        match self {
            Compression::Uncompressed => PC::UNCOMPRESSED,
            Compression::Snappy => PC::SNAPPY,
            Compression::Zstd(l) => {
                let lvl = ZstdLevel::try_new(l.clamp(1, 22))
                    .unwrap_or_else(|_| ZstdLevel::try_new(3).expect("zstd level 3 is valid"));
                PC::ZSTD(lvl)
            }
        }
    }
}

/// Which output tables to produce.
#[derive(Clone, Copy, Debug)]
pub struct TableSet {
    pub packets: bool,
    pub flows: bool,
    pub dns: bool,
    pub http: bool,
    pub tls: bool,
}

impl TableSet {
    pub fn from_names(names: &[String]) -> Result<TableSet> {
        let mut ts = TableSet {
            packets: false,
            flows: false,
            dns: false,
            http: false,
            tls: false,
        };
        for n in names {
            match n.to_ascii_lowercase().as_str() {
                "packets" => ts.packets = true,
                "flows" => ts.flows = true,
                "dns" => ts.dns = true,
                "http" => ts.http = true,
                "tls" => ts.tls = true,
                other => {
                    return Err(Error::Invalid(format!(
                        "unknown table '{other}' (expected: packets, flows, dns, http, tls)"
                    )))
                }
            }
        }
        if !(ts.packets || ts.flows || ts.dns || ts.http || ts.tls) {
            return Err(Error::Invalid("no output tables selected".into()));
        }
        Ok(ts)
    }

    /// Whether any application-layer parsing is needed at all.
    pub fn needs_app(&self) -> bool {
        self.dns || self.http || self.tls || self.flows
    }
}

/// Full extraction configuration for a single input file.
#[derive(Clone, Debug)]
pub struct Config {
    pub input: PathBuf,
    pub output_dir: PathBuf,
    pub stem: String,
    pub tables: TableSet,
    pub compression: Compression,
    pub idle_timeout: f64,
    pub active_threshold: f64,
    pub max_flows: usize,
    pub app_buffer_bytes: usize,
    pub hex_prefix_len: usize,
    pub threads: usize,
    pub batch_size: usize,
}

impl Config {
    pub fn output_path(&self, table: &str) -> PathBuf {
        self.output_dir
            .join(format!("{}.{}.parquet", self.stem, table))
    }
}
