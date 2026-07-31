//! Extraction pipeline.
//!
//! M1 runs a single-threaded pipeline through the same batch/sink structure
//! that the parallel version (M6) will build on.

use crate::app;
use crate::config::Config;
use crate::decode::{decode_packet, PacketMeta, IP_TCP, IP_UDP};
use crate::error::{Error, Result};
use crate::flow::key::{FlowEvent, FlowKey};
use crate::flow::{AppConfig, FlowEngine};
use crate::reader::Reader;
use crate::schema::dns::{self, DnsBuilder};
use crate::schema::flows::{self, FlowsBuilder};
use crate::schema::http::{self, HttpBuilder};
use crate::schema::packets::{self, PacketsBuilder};
use crate::schema::tls::{self, TlsBuilder};
use crate::sink::ParquetSink;
use crate::summary::RunSummary;
use std::time::Instant;

const PACKETS_ROW_GROUP: usize = 131_072;
const FLOWS_ROW_GROUP: usize = 524_288;
const NARROW_ROW_GROUP: usize = 524_288;
const SIGNAL_CHECK_EVERY: u64 = 256;
const MAX_ENRICH_QNAMES: usize = 16;

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
    let appcfg = AppConfig {
        tls: cfg.tables.tls,
        http: cfg.tables.http,
        enrich: cfg.tables.flows,
        buffer_bytes: cfg.app_buffer_bytes,
    };
    let mut engine = FlowEngine::new(cfg.idle_timeout, cfg.active_threshold, cfg.max_flows, appcfg);
    let need_engine = cfg.tables.flows || cfg.tables.tls || cfg.tables.http;

    let mut tls_sink = if cfg.tables.tls {
        Some(ParquetSink::create(
            &cfg.output_path("tls"),
            tls::schema(),
            cfg.compression,
            NARROW_ROW_GROUP,
        )?)
    } else {
        None
    };
    let mut tbuilder = TlsBuilder::new();

    let mut http_sink = if cfg.tables.http {
        Some(ParquetSink::create(
            &cfg.output_path("http"),
            http::schema(),
            cfg.compression,
            NARROW_ROW_GROUP,
        )?)
    } else {
        None
    };
    let mut hbuilder = HttpBuilder::new();

    let mut dns_sink = if cfg.tables.dns {
        Some(ParquetSink::create(
            &cfg.output_path("dns"),
            dns::schema(),
            cfg.compression,
            NARROW_ROW_GROUP,
        )?)
    } else {
        None
    };
    let mut dbuilder = DnsBuilder::new();
    let want_app = cfg.tables.packets || cfg.tables.needs_app();

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

                // Stateless UDP application parsing (fills inline fields + dns rows).
                if want_app && meta.ip_proto == Some(IP_UDP) {
                    if let Some((poff, plen)) = meta.l4_payload {
                        if let Some(pl) = frame.get(poff..poff + plen) {
                            let out = app::parse_udp(pl, &mut meta, rec.ts_ns, cfg.tables.dns);
                            if let (Some(row), Some(sink)) = (out.dns, dns_sink.as_mut()) {
                                dbuilder.append(&row);
                                if dbuilder.len() >= cfg.batch_size {
                                    sink.write(dbuilder.finish()?)?;
                                }
                            }
                        }
                    }
                }
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
            if need_engine {
                if let Some(ev) = FlowEvent::from_packet(rec, &meta, rec.off) {
                    let key = ev.key;
                    // TCP payload slice for in-order application reassembly.
                    let payload = if meta.ip_proto == Some(IP_TCP) {
                        meta.l4_payload.and_then(|(o, l)| {
                            let base = start;
                            bytes.get(base + o..base + o + l)
                        })
                    } else {
                        None
                    };
                    engine.on_event(&ev, payload);
                    enrich_flow(&mut engine, &key, &meta);
                }
            }
            pkt_id += 1;
            summary.packets += 1;
        }
        // Drain rows produced during this batch.
        if let Some(sink) = flows_sink.as_mut() {
            drain_flows(&mut engine, &mut fbuilder, sink, cfg.batch_size)?;
        }
        drain_tls(&mut engine, &mut tbuilder, tls_sink.as_mut(), cfg.batch_size)?;
        drain_http(&mut engine, &mut hbuilder, http_sink.as_mut(), cfg.batch_size)?;
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

    if let Some(mut sink) = dns_sink.take() {
        if !dbuilder.is_empty() {
            sink.write(dbuilder.finish()?)?;
        }
        let path = sink.path().to_string_lossy().into_owned();
        let rows = sink.close()?;
        summary.table_rows.insert("dns", rows);
        summary.table_paths.insert("dns", path);
    }

    if let Some(mut sink) = tls_sink.take() {
        drain_tls(&mut engine, &mut tbuilder, Some(&mut sink), 1)?;
        if !tbuilder.is_empty() {
            sink.write(tbuilder.finish()?)?;
        }
        let path = sink.path().to_string_lossy().into_owned();
        let rows = sink.close()?;
        summary.table_rows.insert("tls", rows);
        summary.table_paths.insert("tls", path);
    }

    if let Some(mut sink) = http_sink.take() {
        drain_http(&mut engine, &mut hbuilder, Some(&mut sink), 1)?;
        if !hbuilder.is_empty() {
            sink.write(hbuilder.finish()?)?;
        }
        let path = sink.path().to_string_lossy().into_owned();
        let rows = sink.close()?;
        summary.table_rows.insert("http", rows);
        summary.table_paths.insert("http", path);
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

/// Add per-packet application enrichment to the current (open) flow.
fn enrich_flow(engine: &mut FlowEngine, key: &FlowKey, meta: &PacketMeta) {
    if meta.app_proto.is_none() && meta.dns_qname.is_none() {
        return;
    }
    if let Some(en) = engine.state_mut(key) {
        if let Some(ap) = meta.app_proto {
            en.app_protos.insert(ap);
        }
        if let Some(q) = &meta.dns_qname {
            if en.dns_qnames.len() < MAX_ENRICH_QNAMES && !en.dns_qnames.iter().any(|x| x == q) {
                en.dns_qnames.push(q.clone());
            }
        }
    }
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

/// Move produced TLS rows into the builder/sink (dropping them if no sink).
fn drain_tls(
    engine: &mut FlowEngine,
    builder: &mut TlsBuilder,
    sink: Option<&mut ParquetSink>,
    batch_size: usize,
) -> Result<()> {
    if engine.tls_rows.is_empty() {
        return Ok(());
    }
    let rows = std::mem::take(&mut engine.tls_rows);
    if let Some(sink) = sink {
        for row in &rows {
            builder.append(row);
            if builder.len() >= batch_size {
                sink.write(builder.finish()?)?;
            }
        }
    }
    Ok(())
}

/// Move produced HTTP rows into the builder/sink (dropping them if no sink).
fn drain_http(
    engine: &mut FlowEngine,
    builder: &mut HttpBuilder,
    sink: Option<&mut ParquetSink>,
    batch_size: usize,
) -> Result<()> {
    if engine.http_rows.is_empty() {
        return Ok(());
    }
    let rows = std::mem::take(&mut engine.http_rows);
    if let Some(sink) = sink {
        for row in &rows {
            builder.append(row);
            if builder.len() >= batch_size {
                sink.write(builder.finish()?)?;
            }
        }
    }
    Ok(())
}
