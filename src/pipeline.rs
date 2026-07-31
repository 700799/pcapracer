//! Extraction pipeline.
//!
//! M1 runs a single-threaded pipeline through the same batch/sink structure
//! that the parallel version (M6) will build on.

use crate::config::Config;
use crate::decode::{decode_packet, PacketMeta};
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::schema::packets::{self, PacketsBuilder};
use crate::sink::ParquetSink;
use crate::summary::RunSummary;
use std::time::Instant;

const PACKETS_ROW_GROUP: usize = 131_072;
const SIGNAL_CHECK_EVERY: u64 = 256;

/// Run extraction for one input file. `should_abort` is polled periodically;
/// returning true aborts cleanly (writers are still finalized).
pub fn run(cfg: Config, should_abort: impl Fn() -> bool) -> Result<RunSummary> {
    let start = Instant::now();
    let mut summary = RunSummary::new(&cfg.tables);

    let reader = Reader::open(&cfg)?;

    let mut packets_sink = if cfg.tables.packets {
        Some(ParquetSink::create(
            &cfg.output_path("packets"),
            packets::schema(),
            cfg.compression,
            PACKETS_ROW_GROUP,
        )?)
    } else {
        None
    };
    let mut pbuilder = PacketsBuilder::new(cfg.batch_size);

    let mut meta = PacketMeta::default();
    let mut pkt_id: u64 = 0;
    let mut aborted = false;

    'outer: for batch in reader {
        if batch.idx % SIGNAL_CHECK_EVERY == 0 && should_abort() {
            aborted = true;
            break;
        }
        let bytes = batch.data.bytes();
        for rec in &batch.recs {
            let start = rec.off as usize;
            let end = start.saturating_add(rec.caplen as usize);
            if let Some(frame) = bytes.get(start..end) {
                decode_packet(frame, rec.linktype, &cfg, &mut meta);
            } else {
                meta.reset();
                summary.decode_errors += 1;
            }
            if let Some(sink) = packets_sink.as_mut() {
                pbuilder.append(pkt_id, rec, &meta);
                if pbuilder.len() >= cfg.batch_size {
                    sink.write(pbuilder.finish()?)?;
                }
            }
            pkt_id += 1;
            summary.packets += 1;
        }
        if aborted {
            break 'outer;
        }
    }

    if let Some(mut sink) = packets_sink.take() {
        if !pbuilder.is_empty() {
            sink.write(pbuilder.finish()?)?;
        }
        let path = sink.path().to_string_lossy().into_owned();
        let rows = sink.close()?;
        summary.table_rows.insert("packets", rows);
        summary.table_paths.insert("packets", path);
    }

    summary.elapsed_s = start.elapsed().as_secs_f64();

    if aborted {
        return Err(Error::Interrupted);
    }
    Ok(summary)
}
