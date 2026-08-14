//! Parquet output.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties};

use crate::error::Result;

/// Compression choice, exposed to Python so a user optimising for scan speed rather than
/// size can pick something cheaper than ZSTD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Zstd,
    Snappy,
    Lz4,
    Gzip,
    None,
}

impl Codec {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "zstd" => Codec::Zstd,
            "snappy" => Codec::Snappy,
            "lz4" => Codec::Lz4,
            "gzip" => Codec::Gzip,
            "none" | "uncompressed" => Codec::None,
            other => {
                return Err(crate::error::Error::Config(format!(
                    "unknown compression {other:?}; expected one of zstd, snappy, lz4, gzip, none"
                )))
            }
        })
    }

    fn to_parquet(self, level: i32) -> Result<Compression> {
        Ok(match self {
            Codec::Zstd => {
                Compression::ZSTD(ZstdLevel::try_new(level).map_err(crate::error::Error::Parquet)?)
            }
            Codec::Snappy => Compression::SNAPPY,
            Codec::Lz4 => Compression::LZ4_RAW,
            Codec::Gzip => Compression::GZIP(Default::default()),
            Codec::None => Compression::UNCOMPRESSED,
        })
    }
}

/// Row group size in rows.
///
/// Large row groups compress better and mean fewer footer entries, but a reader must
/// materialise a whole group's worth of a column to scan it. 128k is the usual sweet spot
/// for analytical scans and keeps a wide packet row group near a few hundred MB uncompressed.
pub const DEFAULT_ROW_GROUP_ROWS: usize = 128 * 1024;

pub fn writer_properties(
    codec: Codec,
    level: i32,
    row_group_rows: usize,
) -> Result<WriterProperties> {
    let mut b = WriterProperties::builder()
        .set_compression(codec.to_parquet(level)?)
        .set_max_row_group_row_count(Some(row_group_rows))
        // Page-level statistics let a reader skip pages on a predicate, which is what makes
        // `WHERE tls_sni = '...'` fast over a multi-GB output.
        .set_statistics_enabled(EnabledStatistics::Page)
        .set_dictionary_enabled(true);

    // Most of the wide schema's string columns are low cardinality — protocol names, flag
    // strings, rcode names — so dictionary encoding is close to free and a large win.
    b = b.set_encoding(Encoding::PLAIN);
    Ok(b.build())
}

/// A Parquet file being written incrementally.
pub struct ParquetSink {
    writer: ArrowWriter<File>,
    pub path: PathBuf,
    pub rows: u64,
}

impl ParquetSink {
    pub fn create(
        path: &Path,
        schema: Arc<Schema>,
        codec: Codec,
        level: i32,
        row_group_rows: usize,
    ) -> Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let file = File::create(path)?;
        let props = writer_properties(codec, level, row_group_rows)?;
        let writer = ArrowWriter::try_new(file, schema, Some(props))?;
        Ok(ParquetSink {
            writer,
            path: path.to_path_buf(),
            rows: 0,
        })
    }

    pub fn write(&mut self, batch: &RecordBatch) -> Result<()> {
        if batch.num_rows() == 0 {
            return Ok(());
        }
        self.writer.write(batch)?;
        self.rows += batch.num_rows() as u64;
        Ok(())
    }

    pub fn close(self) -> Result<u64> {
        let rows = self.rows;
        self.writer.close()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Packet, WideBuilder};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    fn temp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pcapracer-w-{}-{}", std::process::id(), name));
        p
    }

    #[test]
    fn round_trips_a_wide_batch() {
        let mut b = WideBuilder::new();
        for i in 0..1000u64 {
            let mut p = Packet {
                packet_id: Some(i),
                ip_src: Some("10.0.0.1".into()),
                dns_qname: Some(format!("host{i}.example.com")),
                ..Default::default()
            };
            b.append(&mut p);
        }
        let batch = b.finish().unwrap();

        let path = temp("roundtrip.parquet");
        let mut sink = ParquetSink::create(&path, batch.schema(), Codec::Zstd, 3, 256).unwrap();
        sink.write(&batch).unwrap();
        assert_eq!(sink.close().unwrap(), 1000);

        let file = File::open(&path).unwrap();
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)
            .unwrap()
            .build()
            .unwrap();
        let total: usize = reader.map(|b| b.unwrap().num_rows()).sum();
        assert_eq!(total, 1000);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn creates_missing_parent_directories() {
        let mut path = temp("nested");
        path.push("deeper");
        path.push("out.parquet");

        let schema = crate::schema::schema();
        let sink = ParquetSink::create(&path, schema, Codec::Snappy, 1, 64).unwrap();
        sink.close().unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(temp("nested")).ok();
    }

    #[test]
    fn codec_parsing_accepts_known_names_and_rejects_others() {
        assert_eq!(Codec::parse("zstd").unwrap(), Codec::Zstd);
        assert_eq!(Codec::parse("SNAPPY").unwrap(), Codec::Snappy);
        assert_eq!(Codec::parse("none").unwrap(), Codec::None);
        let err = Codec::parse("brotli-ish").unwrap_err();
        assert!(err.to_string().contains("unknown compression"));
    }

    #[test]
    fn empty_batches_are_skipped() {
        let mut b = WideBuilder::new();
        let batch = b.finish().unwrap();
        let path = temp("empty.parquet");
        let mut sink = ParquetSink::create(&path, batch.schema(), Codec::None, 1, 64).unwrap();
        sink.write(&batch).unwrap();
        assert_eq!(sink.close().unwrap(), 0);
        std::fs::remove_file(path).ok();
    }
}
