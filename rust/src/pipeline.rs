//! The extraction pipeline: read → dissect → aggregate → emit.
//!
//! # Parallelism and determinism
//!
//! Packets are read serially into a chunk, dissected in parallel with rayon, then folded
//! back into the flow and reassembly tables serially, in capture order. That split is
//! deliberate: dissecting one packet is pure and embarrassingly parallel, while flow
//! aggregation and TCP reassembly are inherently sequential — a stream's bytes only make
//! sense in order.
//!
//! The consequence worth knowing is that **output is byte-identical regardless of thread
//! count**. Flow ids, packet ids and row order all come from the serial phase. Threads only
//! change how fast you get there, never what you get.

use std::path::Path;

use rayon::prelude::*;

use crate::dissect::{app, dissect_frame, Ctx, Tuple};
use crate::error::{Error, Result};
use crate::flow::FlowTable;
use crate::reader::{CaptureReader, RawPacket};
use crate::reasm::{FragTable, StreamKey, StreamTable};
use crate::schema::{Packet, WideBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// One wide table with every column.
    Wide,
    /// A narrow core table plus one table per protocol.
    Split,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "wide" => Ok(Mode::Wide),
            "split" => Ok(Mode::Split),
            other => Err(Error::Config(format!(
                "unknown mode {other:?}; expected \"wide\" or \"split\""
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub reassemble: bool,
    /// 0 means "use every available core".
    pub threads: usize,
    pub batch_size: usize,
    pub max_flows: usize,
    pub max_streams: usize,
    pub max_stream_bytes: usize,
    pub max_frag_sets: usize,
    pub max_frag_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Wide,
            reassemble: true,
            threads: 0,
            batch_size: 65_536,
            max_flows: 1 << 20,
            max_streams: crate::reasm::DEFAULT_MAX_STREAMS,
            max_stream_bytes: crate::reasm::DEFAULT_MAX_STREAM_BYTES,
            max_frag_sets: crate::reasm::DEFAULT_MAX_FRAG_SETS,
            max_frag_bytes: 1 << 16,
        }
    }
}

/// What a run saw and what it had to give up on.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct RunStats {
    pub packets: u64,
    pub capture_bytes: u64,
    pub flows: u64,
    /// Packets whose dissection returned an error at some layer.
    pub malformed: u64,
    /// Packets cut short by the capture's snaplen.
    pub truncated: u64,
    /// Damaged blocks the reader could not parse.
    pub bad_blocks: u64,
    /// Flows not created because the flow table was at capacity.
    pub flows_evicted: u64,
    /// TCP streams that hit the per-stream byte cap.
    pub streams_truncated: u64,
    /// Segments dissected without reassembly because the stream table was full.
    pub streams_evicted: u64,
    pub fragments_reassembled: u64,
    pub fragments_dropped: u64,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub pcapracer_version: String,
}

/// A packet copied out of the reader's buffer so it can outlive the read call.
#[derive(Default, Clone)]
struct Owned {
    ts_ns: i64,
    cap_len: u32,
    orig_len: u32,
    iface_id: u32,
    linktype: u16,
    truncated: bool,
    data: Vec<u8>,
}

impl Owned {
    fn fill(&mut self, r: &RawPacket<'_>) {
        self.ts_ns = r.ts_ns;
        self.cap_len = r.cap_len;
        self.orig_len = r.orig_len;
        self.iface_id = r.iface_id;
        self.linktype = r.linktype;
        self.truncated = r.is_truncated();
        self.data.clear();
        self.data.extend_from_slice(r.data);
    }
}

/// Result of dissecting one packet, before flow state is applied.
struct Dissected {
    pkt: Packet,
    tuple: Option<Tuple>,
    /// Byte range of the TCP payload within the frame, when dispatch was deferred.
    tcp_payload: Option<(u16, u16)>,
    malformed: bool,
}

/// Dissect a single packet. Pure — no shared state, which is what lets this run in parallel.
fn dissect_one(o: &Owned, defer_tcp_app: bool) -> Dissected {
    // Frame-level columns come from the capture record; everything else the dissectors fill.
    let mut pkt = Packet {
        ts: Some(o.ts_ns),
        ts_epoch_ns: Some(o.ts_ns),
        frame_len: Some(o.orig_len),
        cap_len: Some(o.cap_len),
        iface_id: Some(o.iface_id),
        truncated: Some(o.truncated),
        ..Default::default()
    };

    let (tuple, malformed) = {
        let mut ctx = Ctx::new(&mut pkt);
        ctx.defer_tcp_app = defer_tcp_app;
        let r = dissect_frame(&o.data, o.linktype, &mut ctx);
        ctx.finish();
        (ctx.tuple, r.is_err())
    };
    pkt.malformed = Some(malformed);

    // Locate the TCP payload for the reassembly pass. Header lengths were recorded during
    // dissection, so this needs no second parse.
    let tcp_payload = if defer_tcp_app {
        tcp_payload_range(&pkt, o.data.len())
    } else {
        None
    };

    Dissected {
        pkt,
        tuple,
        tcp_payload,
        malformed,
    }
}

/// Where the TCP payload sits inside the frame, derived from the recorded header lengths.
fn tcp_payload_range(pkt: &Packet, frame_len: usize) -> Option<(u16, u16)> {
    let payload_len = pkt.tcp_payload_len? as usize;
    if payload_len == 0 {
        return None;
    }
    // The payload ends where the frame does, so its start is simply the frame length minus
    // the payload length. This holds even through tunnels, without re-walking the headers.
    let start = frame_len.checked_sub(payload_len)?;
    Some((
        start.min(u16::MAX as usize) as u16,
        payload_len.min(u16::MAX as usize) as u16,
    ))
}

/// Runs a capture through the pipeline, handing finished batches to a callback.
pub struct Engine {
    pub flows: FlowTable,
    streams: StreamTable,
    frags: FragTable,
    pub stats: RunStats,
    next_packet_id: u64,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        Engine {
            flows: FlowTable::new(cfg.max_flows),
            streams: StreamTable::new(cfg.max_streams, cfg.max_stream_bytes),
            frags: FragTable::new(cfg.max_frag_sets, cfg.max_frag_bytes),
            stats: RunStats {
                pcapracer_version: env!("CARGO_PKG_VERSION").to_string(),
                first_ts_ns: i64::MAX,
                last_ts_ns: i64::MIN,
                ..Default::default()
            },
            next_packet_id: 0,
        }
    }

    /// Fold a dissected chunk into the shared tables and append it to the builder.
    ///
    /// Serial by necessity: flow ids and reassembly both depend on capture order.
    fn absorb(&mut self, chunk: &[Owned], dissected: Vec<Dissected>, out: &mut WideBuilder) {
        for (o, d) in chunk.iter().zip(dissected) {
            let mut pkt = d.pkt;
            let id = self.next_packet_id;
            self.next_packet_id += 1;
            pkt.packet_id = Some(id);
            pkt.frame_number = Some(id + 1);

            if d.malformed {
                self.stats.malformed += 1;
            }
            if o.truncated {
                self.stats.truncated += 1;
            }
            if o.ts_ns != 0 {
                self.stats.first_ts_ns = self.stats.first_ts_ns.min(o.ts_ns);
                self.stats.last_ts_ns = self.stats.last_ts_ns.max(o.ts_ns);
            }

            if let Some(t) = d.tuple {
                self.reassemble_and_dispatch(&t, &mut pkt, o, d.tcp_payload);
                self.flows
                    .observe(&t, &mut pkt, o.ts_ns, id + 1, o.orig_len as u64);
            }

            out.append(&mut pkt);
            self.stats.packets += 1;
            self.stats.capture_bytes += o.cap_len as u64;
        }
    }

    /// Feed a TCP segment through reassembly, then dissect the reassembled stream prefix.
    fn reassemble_and_dispatch(
        &mut self,
        tuple: &Tuple,
        pkt: &mut Packet,
        o: &Owned,
        range: Option<(u16, u16)>,
    ) {
        let (start, len) = match range {
            Some(v) => v,
            None => return,
        };
        let (start, len) = (start as usize, len as usize);
        if start + len > o.data.len() {
            return;
        }
        let segment = &o.data[start..start + len];

        let (key_tuple, forward) = tuple.normalized();
        let key = StreamKey {
            flow: key_tuple,
            forward,
        };

        let (data, multi, partial): (&[u8], bool, bool) =
            match self.streams.push(key, pkt.tcp_seq.unwrap_or(0), segment) {
                Some(r) => (r.data, r.multi_segment, r.partial),
                // Stream table full: dissect the bare segment rather than dropping its L7
                // entirely. Worse fidelity, but not a blind spot.
                None => (segment, false, false),
            };

        pkt.reassembled = Some(multi);
        pkt.reassembly_partial = Some(partial);

        let sport = pkt.src_port.unwrap_or(0);
        let dport = pkt.dst_port.unwrap_or(0);

        // A fresh context so the L7 layers land on a clean stack, then splice the names onto
        // the stack the transport dissection already built.
        let base_stack = pkt.proto_stack.clone().unwrap_or_default();
        let mut scratch = Packet::default();
        std::mem::swap(pkt, &mut scratch);
        let extra = {
            let mut ctx = Ctx::new(&mut scratch);
            ctx.reassembled = multi;
            app::dispatch(data, sport, dport, true, &mut ctx);
            ctx.stack.join(":")
        };
        std::mem::swap(pkt, &mut scratch);

        if !extra.is_empty() {
            pkt.proto_stack = Some(if base_stack.is_empty() {
                extra.clone()
            } else {
                format!("{base_stack}:{extra}")
            });
            if let Some(last) = extra.rsplit(':').next() {
                pkt.highest_layer = Some(last.to_string());
            }
        }
    }

    fn finalize_stats(&mut self) {
        self.stats.flows = self.flows.len() as u64;
        self.stats.flows_evicted = self.flows.evicted;
        self.stats.streams_truncated = self.streams.truncated;
        self.stats.streams_evicted = self.streams.evicted;
        self.stats.fragments_reassembled = self.frags.completed;
        self.stats.fragments_dropped = self.frags.dropped;
        if self.stats.first_ts_ns == i64::MAX {
            self.stats.first_ts_ns = 0;
            self.stats.last_ts_ns = 0;
        }
    }
}

/// Run a capture end to end, invoking `on_batch` for each completed packet batch.
pub fn run<F>(path: &Path, cfg: Config, mut on_batch: F) -> Result<(RunStats, FlowTable)>
where
    F: FnMut(arrow::record_batch::RecordBatch) -> Result<()>,
{
    let pool = build_pool(cfg.threads)?;
    let mut engine = Engine::new(cfg.clone());
    let mut reader = CaptureReader::open(path)?;
    let mut builder = WideBuilder::new();

    // Buffers are reused across chunks so a long capture does not churn the allocator.
    let mut chunk: Vec<Owned> = Vec::with_capacity(cfg.batch_size);
    let mut filled = 0usize;
    // `for_each` cannot return a value, so a callback failure is parked here and re-raised
    // once reading stops. Batches are emitted as they complete rather than accumulated,
    // which is what keeps memory flat on a capture larger than RAM.
    let mut callback_err: Option<Error> = None;

    let defer = cfg.reassemble;
    let batch_size = cfg.batch_size.max(1);

    let read_stats = reader.for_each(|raw| {
        if callback_err.is_some() {
            return;
        }
        if filled == chunk.len() {
            chunk.push(Owned::default());
        }
        chunk[filled].fill(&raw);
        filled += 1;

        if filled >= batch_size {
            let slice = &chunk[..filled];
            let dissected = dissect_chunk(&pool, slice, defer);
            engine.absorb(slice, dissected, &mut builder);
            filled = 0;
            match builder.finish() {
                Ok(b) if b.num_rows() > 0 => {
                    if let Err(e) = on_batch(b) {
                        callback_err = Some(e);
                    }
                }
                Ok(_) => {}
                Err(e) => callback_err = Some(Error::Arrow(e)),
            }
        }
    })?;

    if let Some(e) = callback_err {
        return Err(e);
    }

    if filled > 0 {
        let slice = &chunk[..filled];
        let dissected = dissect_chunk(&pool, slice, defer);
        engine.absorb(slice, dissected, &mut builder);
    }
    let tail = builder.finish()?;

    engine.stats.bad_blocks = read_stats.bad_blocks;
    engine.finalize_stats();

    if tail.num_rows() > 0 {
        on_batch(tail)?;
    }
    Ok((engine.stats, engine.flows))
}

fn dissect_chunk(pool: &rayon::ThreadPool, chunk: &[Owned], defer: bool) -> Vec<Dissected> {
    // Below this, thread hand-off costs more than the work it distributes.
    const PARALLEL_THRESHOLD: usize = 256;
    if chunk.len() < PARALLEL_THRESHOLD || pool.current_num_threads() == 1 {
        return chunk.iter().map(|o| dissect_one(o, defer)).collect();
    }
    pool.install(|| chunk.par_iter().map(|o| dissect_one(o, defer)).collect())
}

fn build_pool(threads: usize) -> Result<rayon::ThreadPool> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| Error::Config(format!("could not start thread pool: {e}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use arrow::array::{Array, StringArray, UInt64Array};
    use std::io::Write;

    /// Shared with the api tests so both layers exercise the same fixture.
    pub(crate) fn sample_capture_bytes() -> Vec<u8> {
        sample_capture()
    }

    /// A capture holding an HTTP request, its response, and a DNS query.
    fn sample_capture() -> Vec<u8> {
        let mut records: Vec<(u32, u32, Vec<u8>)> = Vec::new();

        // Ethernet + IPv4 + TCP carrying an HTTP request.
        let http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        records.push((1, 0, eth_ip_tcp(50000, 80, 1000, http)));
        // The response, in the other direction.
        let resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        records.push((2, 0, eth_ip_tcp_rev(80, 50000, 5000, resp)));
        // A DNS query over UDP.
        records.push((3, 0, eth_ip_udp(40000, 53, &dns_query())));

        let refs: Vec<(u32, u32, &[u8])> = records
            .iter()
            .map(|(a, b, c)| (*a, *b, c.as_slice()))
            .collect();
        crate::reader::tests::build_pcap(1, false, &refs)
    }

    fn eth_hdr() -> Vec<u8> {
        let mut v = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        v.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        v.extend_from_slice(&[0x08, 0x00]);
        v
    }

    fn ip_hdr(proto: u8, payload_len: usize, swap: bool) -> Vec<u8> {
        let total = 20 + payload_len;
        let (a, b) = if swap {
            ([93u8, 184, 216, 34], [10u8, 0, 0, 5])
        } else {
            ([10u8, 0, 0, 5], [93u8, 184, 216, 34])
        };
        let mut v = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0x40,
            0,
            64,
            proto,
            0,
            0,
        ];
        v.extend_from_slice(&a);
        v.extend_from_slice(&b);
        v
    }

    fn tcp_hdr(sport: u16, dport: u16, seq: u32, payload_len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.push(0x50); // data offset 5
        v.push(if payload_len > 0 { 0x18 } else { 0x02 }); // PSH|ACK or SYN
        v.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        v
    }

    fn eth_ip_tcp(sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = eth_hdr();
        v.extend_from_slice(&ip_hdr(6, 20 + payload.len(), false));
        v.extend_from_slice(&tcp_hdr(sport, dport, seq, payload.len()));
        v.extend_from_slice(payload);
        v
    }

    fn eth_ip_tcp_rev(sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = eth_hdr();
        v.extend_from_slice(&ip_hdr(6, 20 + payload.len(), true));
        v.extend_from_slice(&tcp_hdr(sport, dport, seq, payload.len()));
        v.extend_from_slice(payload);
        v
    }

    fn eth_ip_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = eth_hdr();
        v.extend_from_slice(&ip_hdr(17, 8 + payload.len(), false));
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(payload);
        v
    }

    fn dns_query() -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&[7]);
        v.extend_from_slice(b"example");
        v.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        v.extend_from_slice(&[0, 1, 0, 1]);
        v
    }

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pcapracer-pipe-{}-{}", std::process::id(), name));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    fn collect(
        path: &Path,
        cfg: Config,
    ) -> (RunStats, FlowTable, Vec<arrow::record_batch::RecordBatch>) {
        let mut batches = Vec::new();
        let (stats, flows) = run(path, cfg, |b| {
            batches.push(b);
            Ok(())
        })
        .unwrap();
        (stats, flows, batches)
    }

    fn col_strings(b: &arrow::record_batch::RecordBatch, name: &str) -> Vec<Option<String>> {
        let i = b.schema().index_of(name).unwrap();
        let a = b.column(i).as_any().downcast_ref::<StringArray>().unwrap();
        (0..a.len())
            .map(|i| {
                if a.is_null(i) {
                    None
                } else {
                    Some(a.value(i).to_string())
                }
            })
            .collect()
    }

    #[test]
    fn end_to_end_extraction() {
        let path = write_temp("sample.pcap", &sample_capture());
        let (stats, flows, batches) = collect(&path, Config::default());

        assert_eq!(stats.packets, 3);
        assert_eq!(stats.bad_blocks, 0);
        // One TCP conversation (both directions) plus one UDP flow.
        assert_eq!(flows.len(), 2);
        assert_eq!(stats.flows, 2);

        let b = &batches[0];
        assert_eq!(b.num_rows(), 3);

        let hosts = col_strings(b, "http_host");
        assert_eq!(hosts[0].as_deref(), Some("example.com"));
        let servers = col_strings(b, "http_server");
        assert_eq!(servers[1].as_deref(), Some("nginx"));
        let qnames = col_strings(b, "dns_qname");
        assert_eq!(qnames[2].as_deref(), Some("example.com"));

        let stacks = col_strings(b, "proto_stack");
        assert_eq!(stacks[0].as_deref(), Some("eth:ip:tcp:http"));
        assert_eq!(stacks[2].as_deref(), Some("eth:ip:udp:dns"));

        // Both directions of the HTTP conversation share a flow and a community id.
        let cids = col_strings(b, "community_id");
        assert_eq!(cids[0], cids[1]);
        assert!(cids[0].as_ref().unwrap().starts_with("1:"));

        let dirs = col_strings(b, "direction");
        assert_eq!(dirs[0].as_deref(), Some("c2s"));
        assert_eq!(dirs[1].as_deref(), Some("s2c"));

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn packet_ids_are_dense_and_ordered() {
        let path = write_temp("ids.pcap", &sample_capture());
        let (_, _, batches) = collect(&path, Config::default());
        let b = &batches[0];
        let i = b.schema().index_of("packet_id").unwrap();
        let a = b.column(i).as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(a.values(), &[0, 1, 2]);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn thread_count_does_not_change_the_output() {
        // The property the parallel design is built around: threads change speed, not results.
        let path = write_temp("determinism.pcap", &sample_capture());

        let one = collect(
            &path,
            Config {
                threads: 1,
                ..Default::default()
            },
        );
        let many = collect(
            &path,
            Config {
                threads: 8,
                ..Default::default()
            },
        );

        assert_eq!(one.2.len(), many.2.len());
        for (a, b) in one.2.iter().zip(&many.2) {
            assert_eq!(a, b, "batch contents diverged between 1 and 8 threads");
        }
        let fa = one.1.to_record_batch().unwrap();
        let fb = many.1.to_record_batch().unwrap();
        assert_eq!(fa, fb, "flow table diverged between 1 and 8 threads");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn reassembly_off_still_finds_single_segment_protocols() {
        let path = write_temp("noreasm.pcap", &sample_capture());
        let (stats, _, batches) = collect(
            &path,
            Config {
                reassemble: false,
                ..Default::default()
            },
        );
        assert_eq!(stats.packets, 3);
        let hosts = col_strings(&batches[0], "http_host");
        assert_eq!(hosts[0].as_deref(), Some("example.com"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn split_across_segments_is_only_recovered_with_reassembly() {
        // An HTTP request whose Host header lands in the second segment.
        let part1 = b"GET / HTTP/1.1\r\nHo";
        let part2 = b"st: split.example\r\n\r\n";
        let records: Vec<(u32, u32, Vec<u8>)> = vec![
            (1, 0, eth_ip_tcp(50000, 80, 1000, part1)),
            (
                2,
                0,
                eth_ip_tcp(50000, 80, 1000 + part1.len() as u32, part2),
            ),
        ];
        let refs: Vec<(u32, u32, &[u8])> = records
            .iter()
            .map(|(a, b, c)| (*a, *b, c.as_slice()))
            .collect();
        let path = write_temp(
            "split.pcap",
            &crate::reader::tests::build_pcap(1, false, &refs),
        );

        let (_, _, with) = collect(&path, Config::default());
        let hosts = col_strings(&with[0], "http_host");
        // The second packet carries the completed header once the stream is reassembled.
        assert_eq!(hosts[1].as_deref(), Some("split.example"));

        let (_, _, without) = collect(
            &path,
            Config {
                reassemble: false,
                ..Default::default()
            },
        );
        let hosts = col_strings(&without[0], "http_host");
        assert_eq!(hosts[1], None, "a bare second segment has no Host header");

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn small_batch_size_produces_multiple_batches() {
        let path = write_temp("batched.pcap", &sample_capture());
        let (stats, _, batches) = collect(
            &path,
            Config {
                batch_size: 1,
                ..Default::default()
            },
        );
        assert_eq!(stats.packets, 3);
        assert_eq!(batches.len(), 3);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn mode_and_codec_parsing_reject_typos() {
        assert_eq!(Mode::parse("split").unwrap(), Mode::Split);
        assert!(Mode::parse("wode").is_err());
    }
}
