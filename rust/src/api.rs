//! The extraction entry points: run a capture to Parquet on disk, or to Arrow in memory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use arrow::record_batch::RecordBatch;

use crate::error::Result;
use crate::pipeline::{run, Config, Mode, RunStats};
use crate::schema::split;
use crate::writer::{Codec, ParquetSink};

/// How the output is written.
#[derive(Debug, Clone)]
pub struct OutputOptions {
    pub codec: Codec,
    pub level: i32,
    pub row_group_rows: usize,
}

impl Default for OutputOptions {
    fn default() -> Self {
        OutputOptions {
            codec: Codec::Zstd,
            level: 3,
            row_group_rows: crate::writer::DEFAULT_ROW_GROUP_ROWS,
        }
    }
}

/// What a run produced.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunReport {
    pub stats: RunStats,
    /// Output file → row count, so a caller can see what was written without stat'ing files.
    pub files: BTreeMap<String, u64>,
}

/// Extract a capture to Parquet under `out_dir`.
///
/// Always writes `packets.parquet`, `flows.parquet` and `_meta.json`. In split mode
/// `packets.parquet` holds only the core columns, and each protocol present gets its own
/// file alongside. Protocols absent from the capture produce no file at all rather than an
/// empty one — an empty Parquet is a nuisance to glob over.
pub fn to_parquet(
    input: &Path,
    out_dir: &Path,
    cfg: Config,
    out: OutputOptions,
) -> Result<RunReport> {
    std::fs::create_dir_all(out_dir)?;
    let mode = cfg.mode;

    let mut packets: Option<ParquetSink> = None;
    let mut sidecars: BTreeMap<&'static str, ParquetSink> = BTreeMap::new();
    let mut files: BTreeMap<String, u64> = BTreeMap::new();

    let packets_path = out_dir.join("packets.parquet");

    let (stats, flows) = run(input, cfg, |batch| {
        let core = match mode {
            Mode::Wide => batch.clone(),
            Mode::Split => split::core_table(&batch)?,
        };

        // Sinks are created from the first batch so the schema comes from real data rather
        // than being asserted twice.
        let sink = match packets.as_mut() {
            Some(s) => s,
            None => {
                packets = Some(ParquetSink::create(
                    &packets_path,
                    core.schema(),
                    out.codec,
                    out.level,
                    out.row_group_rows,
                )?);
                packets.as_mut().expect("just created")
            }
        };
        sink.write(&core)?;

        if mode == Mode::Split {
            for (name, table) in split::all_proto_tables(&batch)? {
                let sink = match sidecars.get_mut(name) {
                    Some(s) => s,
                    None => {
                        let path = out_dir.join(format!("{name}.parquet"));
                        let s = ParquetSink::create(
                            &path,
                            table.schema(),
                            out.codec,
                            out.level,
                            out.row_group_rows,
                        )?;
                        sidecars.entry(name).or_insert(s)
                    }
                };
                sink.write(&table)?;
            }
        }
        Ok(())
    })?;

    // A capture with no packets still gets an (empty) packets file, so downstream globs and
    // schema reads do not have to special-case it.
    let sink = match packets {
        Some(s) => s,
        None => ParquetSink::create(
            &packets_path,
            match mode {
                Mode::Wide => crate::schema::schema(),
                Mode::Split => core_schema_only()?,
            },
            out.codec,
            out.level,
            out.row_group_rows,
        )?,
    };
    files.insert("packets.parquet".to_string(), sink.close()?);

    for (name, s) in sidecars {
        files.insert(format!("{name}.parquet"), s.close()?);
    }

    let flow_batch = flows.to_record_batch()?;
    let flows_path = out_dir.join("flows.parquet");
    let mut fs = ParquetSink::create(
        &flows_path,
        flow_batch.schema(),
        out.codec,
        out.level,
        out.row_group_rows,
    )?;
    fs.write(&flow_batch)?;
    files.insert("flows.parquet".to_string(), fs.close()?);

    let report = RunReport { stats, files };
    let meta_path = out_dir.join("_meta.json");
    std::fs::write(
        &meta_path,
        serde_json::to_vec_pretty(&report).unwrap_or_default(),
    )?;

    Ok(report)
}

/// The split-mode core schema, derived from the wide schema so the two cannot drift.
fn core_schema_only() -> Result<std::sync::Arc<arrow::datatypes::Schema>> {
    let empty = crate::schema::WideBuilder::new().schema();
    let idx: Vec<usize> = split::CORE_COLUMNS
        .iter()
        .filter_map(|n| empty.index_of(n).ok())
        .collect();
    Ok(std::sync::Arc::new(empty.project(&idx)?))
}

/// Extract to Arrow batches in memory, without writing anything.
pub fn to_batches(input: &Path, cfg: Config) -> Result<(Vec<RecordBatch>, RecordBatch, RunStats)> {
    let mut batches = Vec::new();
    let (stats, flows) = run(input, cfg, |b| {
        batches.push(b);
        Ok(())
    })?;
    let flow_batch = flows.to_record_batch()?;
    Ok((batches, flow_batch, stats))
}

/// Convenience: the paths `to_parquet` would write for a given mode.
pub fn output_paths(out_dir: &Path, mode: Mode) -> Vec<PathBuf> {
    let mut v = vec![
        out_dir.join("packets.parquet"),
        out_dir.join("flows.parquet"),
        out_dir.join("_meta.json"),
    ];
    if mode == Mode::Split {
        for t in split::PROTO_TABLES {
            v.push(out_dir.join(format!("{}.parquet", t.name)));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    fn fixture() -> PathBuf {
        // Reuse the pipeline's synthetic capture: HTTP request, HTTP response, DNS query.
        let bytes = crate::pipeline::tests::sample_capture_bytes();
        let mut p = std::env::temp_dir();
        p.push(format!("pcapracer-api-{}.pcap", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn out_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pcapracer-api-out-{}-{}", std::process::id(), name));
        std::fs::remove_dir_all(&p).ok();
        p
    }

    fn row_count(path: &Path) -> usize {
        let f = std::fs::File::open(path).unwrap();
        ParquetRecordBatchReaderBuilder::try_new(f)
            .unwrap()
            .build()
            .unwrap()
            .map(|b| b.unwrap().num_rows())
            .sum()
    }

    #[test]
    fn wide_mode_writes_packets_flows_and_meta() {
        let input = fixture();
        let dir = out_dir("wide");
        let report = to_parquet(&input, &dir, Config::default(), OutputOptions::default()).unwrap();

        assert_eq!(report.stats.packets, 3);
        assert_eq!(report.files["packets.parquet"], 3);
        assert_eq!(report.files["flows.parquet"], 2);

        assert_eq!(row_count(&dir.join("packets.parquet")), 3);
        assert!(dir.join("_meta.json").exists());

        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("_meta.json")).unwrap()).unwrap();
        assert_eq!(meta["stats"]["packets"], 3);
        assert!(meta["stats"]["pcapracer_version"].is_string());

        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_file(input).ok();
    }

    #[test]
    fn split_mode_writes_a_narrow_core_plus_protocol_sidecars() {
        let input = fixture();
        let dir = out_dir("split");
        let cfg = Config {
            mode: Mode::Split,
            ..Default::default()
        };
        let report = to_parquet(&input, &dir, cfg, OutputOptions::default()).unwrap();

        // Both L7 protocols in the fixture get a file.
        assert_eq!(report.files["http.parquet"], 2);
        assert_eq!(report.files["dns.parquet"], 1);
        // Protocols absent from the capture must not produce empty files.
        assert!(!dir.join("sip.parquet").exists());
        assert!(!dir.join("modbus.parquet").exists());

        // The core table is narrow; the wide table is not.
        let core = std::fs::File::open(dir.join("packets.parquet")).unwrap();
        let core_cols = ParquetRecordBatchReaderBuilder::try_new(core)
            .unwrap()
            .schema()
            .fields()
            .len();
        assert_eq!(core_cols, split::CORE_COLUMNS.len());
        assert!(core_cols < crate::schema::FIELD_NAMES.len() / 4);

        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_file(input).ok();
    }

    #[test]
    fn to_batches_matches_to_parquet_row_counts() {
        let input = fixture();
        let (batches, flows, stats) = to_batches(&input, Config::default()).unwrap();
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 3);
        assert_eq!(stats.packets, 3);
        assert_eq!(flows.num_rows(), 2);
        std::fs::remove_file(input).ok();
    }

    #[test]
    fn an_empty_capture_still_produces_readable_files() {
        let mut p = std::env::temp_dir();
        p.push(format!("pcapracer-empty-{}.pcap", std::process::id()));
        std::fs::write(&p, crate::reader::tests::build_pcap(1, false, &[])).unwrap();

        let dir = out_dir("empty");
        let report = to_parquet(&p, &dir, Config::default(), OutputOptions::default()).unwrap();
        assert_eq!(report.stats.packets, 0);
        assert_eq!(row_count(&dir.join("packets.parquet")), 0);
        assert_eq!(row_count(&dir.join("flows.parquet")), 0);

        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_file(p).ok();
    }
}
