//! Parquet output sink wrapping an Arrow writer with tuned properties.

use crate::config::Compression;
use crate::error::Result;
use arrow_array::RecordBatch;
use arrow_schema::Schema;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct ParquetSink {
    writer: ArrowWriter<File>,
    path: PathBuf,
    rows: u64,
}

impl ParquetSink {
    pub fn create(
        path: &Path,
        schema: Arc<Schema>,
        compression: Compression,
        row_group_size: usize,
    ) -> Result<ParquetSink> {
        let props = WriterProperties::builder()
            .set_compression(compression.to_parquet())
            .set_dictionary_enabled(true)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .set_max_row_group_row_count(Some(row_group_size))
            .set_created_by(format!("pcapracer {}", env!("CARGO_PKG_VERSION")))
            .build();
        let file = File::create(path)?;
        let writer = ArrowWriter::try_new(file, schema, Some(props))?;
        Ok(ParquetSink {
            writer,
            path: path.to_path_buf(),
            rows: 0,
        })
    }

    pub fn write(&mut self, batch: RecordBatch) -> Result<()> {
        self.rows += batch.num_rows() as u64;
        self.writer.write(&batch)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush and close the writer, returning the total row count.
    pub fn close(self) -> Result<u64> {
        self.writer.close()?;
        Ok(self.rows)
    }
}
