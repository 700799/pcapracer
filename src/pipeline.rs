//! Extraction pipeline.
//!
//! Stateless decoding (L2-L4, UDP apps, packet-row and flow-event building)
//! runs in parallel worker threads; a single ordered collector runs the flow
//! engine, TCP application parsing, and Parquet writing so capture order is
//! preserved. A single-threaded path is used when one thread is requested.

use crate::app;
use crate::config::Config;
use crate::decode::{decode_packet, PacketMeta, IP_TCP, IP_UDP};
use crate::error::{Error, Result};
use crate::flow::key::FlowEvent;
use crate::flow::{AppConfig, FlowEngine};
use crate::reader::{BatchData, RawBatch, Reader};
use crate::schema::dns::{self, DnsBuilder, DnsRow};
use crate::schema::flows::{self, FlowsBuilder};
use crate::schema::http::{self, HttpBuilder};
use crate::schema::packets::{self, PacketsBuilder};
use crate::schema::tls::{self, TlsBuilder};
use crate::sink::ParquetSink;
use crate::summary::RunSummary;
use arrow_array::RecordBatch;
use crossbeam_channel::bounded;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

const PACKETS_ROW_GROUP: usize = 131_072;
const NARROW_ROW_GROUP: usize = 524_288;
const SIGNAL_CHECK_EVERY: u64 = 256;
const MAX_THREADS: usize = 16;

/// Decoded output of one batch (stateless worker product).
struct Decoded {
    idx: u64,
    packets: Option<RecordBatch>,
    events: Vec<FlowEvent>,
    dns_rows: Vec<DnsRow>,
    data: Arc<BatchData>,
    pkt_count: u64,
    decode_errors: u64,
}

/// Reusable per-worker scratch state.
struct WorkerState {
    pbuilder: Option<PacketsBuilder>,
    meta: PacketMeta,
    want_app: bool,
    want_dns: bool,
    need_engine: bool,
}

impl WorkerState {
    fn new(cfg: &Config) -> WorkerState {
        WorkerState {
            pbuilder: if cfg.tables.packets {
                Some(PacketsBuilder::new(cfg.batch_size))
            } else {
                None
            },
            meta: PacketMeta::default(),
            want_app: cfg.tables.packets || cfg.tables.needs_app(),
            want_dns: cfg.tables.dns,
            need_engine: cfg.tables.flows || cfg.tables.tls || cfg.tables.http,
        }
    }
}

/// Decode one batch: fully stateless, safe to run on any worker thread.
fn decode_batch(cfg: &Config, batch: RawBatch, ws: &mut WorkerState) -> Result<Decoded> {
    let bytes = batch.data.bytes();
    let mut events = Vec::new();
    let mut dns_rows = Vec::new();
    let mut decode_errors = 0u64;
    let mut pkt_count = 0u64;

    for (i, rec) in batch.recs.iter().enumerate() {
        let pkt_id = batch.first_pkt_id + i as u64;
        let start = rec.off as usize;
        let end = start.saturating_add(rec.caplen as usize);
        if let Some(frame) = bytes.get(start..end) {
            decode_packet(frame, rec.linktype, cfg, &mut ws.meta);
            if ws.want_app && ws.meta.ip_proto == Some(IP_UDP) {
                if let Some((poff, plen)) = ws.meta.l4_payload {
                    if let Some(pl) = frame.get(poff..poff + plen) {
                        let out = app::parse_udp(pl, &mut ws.meta, rec.ts_ns, ws.want_dns);
                        if let Some(row) = out.dns {
                            dns_rows.push(row);
                        }
                    }
                }
            }
        } else {
            ws.meta.reset();
            decode_errors += 1;
        }
        if let Some(pb) = ws.pbuilder.as_mut() {
            pb.append(pkt_id, rec, &ws.meta);
        }
        if ws.need_engine {
            if let Some(ev) = FlowEvent::from_packet(rec, &ws.meta, rec.off) {
                events.push(ev);
            }
        }
        pkt_count += 1;
    }

    let packets = match ws.pbuilder.as_mut() {
        Some(b) => Some(b.finish()?),
        None => None,
    };

    Ok(Decoded {
        idx: batch.idx,
        packets,
        events,
        dns_rows,
        data: batch.data,
        pkt_count,
        decode_errors,
    })
}

/// Owns the order-sensitive stage: flow engine, TCP app parsing, and all sinks.
struct Collector {
    packets_sink: Option<ParquetSink>,
    dns_sink: Option<ParquetSink>,
    tls_sink: Option<ParquetSink>,
    http_sink: Option<ParquetSink>,
    flows_sink: Option<ParquetSink>,
    dbuilder: DnsBuilder,
    tbuilder: TlsBuilder,
    hbuilder: HttpBuilder,
    fbuilder: FlowsBuilder,
    engine: FlowEngine,
    summary: RunSummary,
    batch_size: usize,
}

impl Collector {
    fn new(cfg: &Config) -> Result<Collector> {
        let mk = |on: bool, name: &str, schema, rg| -> Result<Option<ParquetSink>> {
            if on {
                Ok(Some(ParquetSink::create(
                    &cfg.output_path(name),
                    schema,
                    cfg.compression,
                    rg,
                )?))
            } else {
                Ok(None)
            }
        };
        let appcfg = AppConfig {
            tls: cfg.tables.tls,
            http: cfg.tables.http,
            enrich: cfg.tables.flows,
            buffer_bytes: cfg.app_buffer_bytes,
        };
        Ok(Collector {
            packets_sink: mk(cfg.tables.packets, "packets", packets::schema(), PACKETS_ROW_GROUP)?,
            dns_sink: mk(cfg.tables.dns, "dns", dns::schema(), NARROW_ROW_GROUP)?,
            tls_sink: mk(cfg.tables.tls, "tls", tls::schema(), NARROW_ROW_GROUP)?,
            http_sink: mk(cfg.tables.http, "http", http::schema(), NARROW_ROW_GROUP)?,
            flows_sink: mk(cfg.tables.flows, "flows", flows::schema(), NARROW_ROW_GROUP)?,
            dbuilder: DnsBuilder::new(),
            tbuilder: TlsBuilder::new(),
            hbuilder: HttpBuilder::new(),
            fbuilder: FlowsBuilder::new(),
            engine: FlowEngine::new(cfg.idle_timeout, cfg.active_threshold, cfg.max_flows, appcfg),
            summary: RunSummary::new(&cfg.tables),
            batch_size: cfg.batch_size,
        })
    }

    fn consume(&mut self, d: Decoded) -> Result<()> {
        self.summary.packets += d.pkt_count;
        self.summary.decode_errors += d.decode_errors;

        if let (Some(sink), Some(batch)) = (self.packets_sink.as_mut(), d.packets) {
            sink.write(batch)?;
        }
        if let Some(sink) = self.dns_sink.as_mut() {
            for row in &d.dns_rows {
                self.dbuilder.append(row);
                if self.dbuilder.len() >= self.batch_size {
                    sink.write(self.dbuilder.finish()?)?;
                }
            }
        }
        let bytes = d.data.bytes();
        for ev in &d.events {
            let payload = if ev.proto == IP_TCP {
                ev.payload_ref
                    .and_then(|(off, len)| bytes.get(off as usize..off as usize + len as usize))
            } else {
                None
            };
            self.engine.on_event(ev, payload);
        }
        self.drain_rows()?;
        Ok(())
    }

    fn drain_rows(&mut self) -> Result<()> {
        if let Some(sink) = self.flows_sink.as_mut() {
            if !self.engine.closed.is_empty() {
                let rows = std::mem::take(&mut self.engine.closed);
                for row in &rows {
                    self.fbuilder.append(row);
                    if self.fbuilder.len() >= self.batch_size {
                        sink.write(self.fbuilder.finish()?)?;
                    }
                }
            }
        }
        if let Some(sink) = self.tls_sink.as_mut() {
            if !self.engine.tls_rows.is_empty() {
                let rows = std::mem::take(&mut self.engine.tls_rows);
                for row in &rows {
                    self.tbuilder.append(row);
                    if self.tbuilder.len() >= self.batch_size {
                        sink.write(self.tbuilder.finish()?)?;
                    }
                }
            }
        } else {
            self.engine.tls_rows.clear();
        }
        if let Some(sink) = self.http_sink.as_mut() {
            if !self.engine.http_rows.is_empty() {
                let rows = std::mem::take(&mut self.engine.http_rows);
                for row in &rows {
                    self.hbuilder.append(row);
                    if self.hbuilder.len() >= self.batch_size {
                        sink.write(self.hbuilder.finish()?)?;
                    }
                }
            }
        } else {
            self.engine.http_rows.clear();
        }
        Ok(())
    }

    fn finalize(mut self, elapsed_s: f64) -> Result<RunSummary> {
        // Close all flows and flush residual rows.
        self.engine.finish();
        self.drain_rows()?;

        if let Some(sink) = self.packets_sink.take() {
            let path = sink.path().to_string_lossy().into_owned();
            let rows = sink.close()?;
            self.summary.table_rows.insert("packets", rows);
            self.summary.table_paths.insert("packets", path);
        }
        macro_rules! finish_narrow {
            ($sink:ident, $builder:ident, $name:literal) => {
                if let Some(mut sink) = self.$sink.take() {
                    if !self.$builder.is_empty() {
                        sink.write(self.$builder.finish()?)?;
                    }
                    let path = sink.path().to_string_lossy().into_owned();
                    let rows = sink.close()?;
                    self.summary.table_rows.insert($name, rows);
                    self.summary.table_paths.insert($name, path);
                }
            };
        }
        finish_narrow!(dns_sink, dbuilder, "dns");
        finish_narrow!(tls_sink, tbuilder, "tls");
        finish_narrow!(http_sink, hbuilder, "http");
        finish_narrow!(flows_sink, fbuilder, "flows");

        self.summary.elapsed_s = elapsed_s;
        Ok(self.summary)
    }
}

fn resolve_threads(requested: usize) -> usize {
    if requested >= 1 {
        return requested.min(MAX_THREADS);
    }
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1).clamp(1, MAX_THREADS))
        .unwrap_or(1)
}

/// Run extraction for one input file.
pub fn run(cfg: Config, should_abort: impl Fn() -> bool) -> Result<RunSummary> {
    let threads = resolve_threads(cfg.threads);
    if threads <= 1 {
        run_serial(cfg, should_abort)
    } else {
        run_parallel(cfg, threads, should_abort)
    }
}

fn run_serial(cfg: Config, should_abort: impl Fn() -> bool) -> Result<RunSummary> {
    let start = Instant::now();
    let reader = Reader::open(&cfg)?;
    let mut collector = Collector::new(&cfg)?;
    let mut ws = WorkerState::new(&cfg);
    let mut aborted = false;

    for batch in reader {
        if batch.idx % SIGNAL_CHECK_EVERY == 0 && should_abort() {
            aborted = true;
            break;
        }
        let decoded = decode_batch(&cfg, batch, &mut ws)?;
        collector.consume(decoded)?;
    }

    let summary = collector.finalize(start.elapsed().as_secs_f64())?;
    if aborted {
        return Err(Error::Interrupted);
    }
    Ok(summary)
}

fn run_parallel(cfg: Config, threads: usize, should_abort: impl Fn() -> bool) -> Result<RunSummary> {
    let start = Instant::now();
    let reader = Reader::open(&cfg)?;
    let mut collector = Collector::new(&cfg)?;

    let cap = (threads * 2).max(4);
    let (work_tx, work_rx) = bounded::<RawBatch>(cap);
    let (out_tx, out_rx) = bounded::<Result<Decoded>>(cap);

    let cfg_ref = &cfg;
    let result = std::thread::scope(|scope| -> Result<bool> {
        // Reader thread.
        scope.spawn(move || {
            for batch in reader {
                if work_tx.send(batch).is_err() {
                    break;
                }
            }
        });

        // Worker threads.
        for _ in 0..threads {
            let wrx = work_rx.clone();
            let otx = out_tx.clone();
            scope.spawn(move || {
                let mut ws = WorkerState::new(cfg_ref);
                for batch in wrx.iter() {
                    let decoded = decode_batch(cfg_ref, batch, &mut ws);
                    let failed = decoded.is_err();
                    if otx.send(decoded).is_err() || failed {
                        break;
                    }
                }
            });
        }
        drop(work_rx);
        drop(out_tx);

        // Collector (this thread): reorder by batch idx and consume.
        let mut pending: BTreeMap<u64, Decoded> = BTreeMap::new();
        let mut next: u64 = 0;
        let mut received: u64 = 0;
        let mut aborted = false;

        for msg in out_rx.iter() {
            let decoded = msg?;
            pending.insert(decoded.idx, decoded);
            while let Some(d) = pending.remove(&next) {
                collector.consume(d)?;
                next += 1;
            }
            received += 1;
            if received % SIGNAL_CHECK_EVERY == 0 && should_abort() {
                aborted = true;
                break;
            }
        }
        // Drain any remaining in-order batches (e.g. on normal completion).
        while let Some(d) = pending.remove(&next) {
            collector.consume(d)?;
            next += 1;
        }
        Ok(aborted)
    });

    let aborted = result?;
    let summary = collector.finalize(start.elapsed().as_secs_f64())?;
    if aborted {
        return Err(Error::Interrupted);
    }
    Ok(summary)
}
