//! Extraction pipeline.
//!
//! M1 runs a single-threaded pipeline through the same batch/sink structure
//! that the parallel version (M6) will build on.

use crate::config::Config;
use crate::decode::{decode_packet, PacketMeta};
use crate::error::{Error, Result};
use crate::flow::key::FlowEvent;
use crate::flow::FlowEngine;
use crate::reader::Reader;
use crate::schema::flows::{self, FlowsBuilder};
use crate::schema::packets::{self, PacketsBuilder};
use crate::sink::ParquetSink;
use crate::summary::RunSummary;
use std::time::Instant;

const PACKETS_ROW_GROUP: usize = 131_072;
const FLOWS_ROW_GROUP: usize = 524_288;
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

    let mut flows_sink = if cfg.tables.flows {
        Some(ParquetSink::create(
            &cfg.output_path("flows"),
            flows::schema(),
            cfg.compression,
            FLOWS_ROW_GROUP,
        )?)
    } else {
        None
    };
    let mut fbuilder = FlowsBuilder::new();
    let mut engine = FlowEngine::new(cfg.idle_timeout, cfg.active_threshold, cfg.max_flows);

    let mut meta = PacketMeta::default();
    let mut pkt_id: u64 = 0;
    let mut aborted = false;

    for batch in reader {
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
            if flows_sink.is_some() {
                if let Some(ev) = FlowEvent::from_packet(rec, &meta, rec.off) {
                    engine.on_event(&ev);
                }
            }
            pkt_id += 1;
            summary.packets += 1;
        }
        // Drain flows closed during this batch.
        if let Some(sink) = flows_sink.as_mut() {
            drain_flows(&mut engine, &mut fbuilder, sink, cfg.batch_size)?;
        }
    }

    // Finalize.
    if let Some(mut sink) = packets_sink.take() {
        if !pbuilder.is_empty() {
            sink.write(pbuilder.finish()?)?;
        }
        let path = sink.path().to_string_lossy().into_owned();
        let rows = sink.close()?;
        summary.table_rows.insert("packets", rows);
        summary.table_paths.insert("packets", path);
    }

    if let Some(mut sink) = flows_sink.take() {
        engine.finish();
        drain_flows(&mut engine, &mut fbuilder, &mut sink, 1)?;
        if !fbuilder.is_empty() {
            sink.write(fbuilder.finish()?)?;
        }
        let path = sink.path().to_string_lossy().into_owned();
        let rows = sink.close()?;
        summary.table_rows.insert("flows", rows);
        summary.table_paths.insert("flows", path);
    }

    summary.elapsed_s = start.elapsed().as_secs_f64();

    if aborted {
        return Err(Error::Interrupted);
    }
    Ok(summary)
}

/// Move closed flow rows from the engine into the builder, flushing full batches.
fn drain_flows(
    engine: &mut FlowEngine,
    builder: &mut FlowsBuilder,
    sink: &mut ParquetSink,
    batch_size: usize,
) -> Result<()> {
    if engine.closed.is_empty() {
        return Ok(());
    }
    let rows = std::mem::take(&mut engine.closed);
    for row in &rows {
        builder.append(row);
        if builder.len() >= batch_size {
            sink.write(builder.finish()?)?;
        }
    }
    Ok(())
}
