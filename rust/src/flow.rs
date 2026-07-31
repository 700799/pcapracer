//! Bidirectional flow aggregation.
//!
//! Packets are the raw material; flows are what analysts actually pivot on. Each
//! conversation is keyed by its normalised 5-tuple so both directions land in one row, with
//! per-direction counters, a coarse TCP state, and the identifying details (SNI, HTTP host,
//! JA3) lifted from whichever packet carried them.

use std::sync::Arc;

use ahash::AHashMap;
use arrow::array::{
    ArrayRef, Float64Builder, StringBuilder, TimestampNanosecondBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;

use crate::dissect::l4::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::dissect::Tuple;
use crate::fingerprint::community_id;
use crate::schema::Packet;

/// Coarse connection state, derived from the flags seen in each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Data seen but no handshake — typically a capture that started mid-connection.
    Partial,
    /// SYN sent, nothing back yet. A flow left here is an unanswered connection attempt,
    /// which in bulk is what a port scan looks like.
    SynSent,
    /// SYN and SYN-ACK seen.
    Established,
    /// At least one side has sent FIN.
    Closing,
    /// Both sides sent FIN.
    Closed,
    /// Connection was reset.
    Reset,
}

impl TcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Partial => "partial",
            TcpState::SynSent => "syn-sent",
            TcpState::Established => "established",
            TcpState::Closing => "closing",
            TcpState::Closed => "closed",
            TcpState::Reset => "reset",
        }
    }
}

#[derive(Debug)]
pub struct Flow {
    pub id: u64,
    pub key: Tuple,
    pub community_id: String,
    pub first_ts: i64,
    pub last_ts: i64,
    pub first_frame: u64,
    pub last_frame: u64,
    pub packets_c2s: u64,
    pub packets_s2c: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub tcp_flags_c2s: u16,
    pub tcp_flags_s2c: u16,
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    fin_c2s: bool,
    fin_s2c: bool,
    syn_c2s: bool,
    synack_s2c: bool,
    saw_reset: bool,
    pub service: Option<String>,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub dns_qname: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja4: Option<String>,
}

impl Flow {
    pub fn state(&self) -> TcpState {
        if self.key.proto != 6 {
            return TcpState::Partial;
        }
        if self.saw_reset {
            return TcpState::Reset;
        }
        if self.fin_c2s && self.fin_s2c {
            return TcpState::Closed;
        }
        if self.fin_c2s || self.fin_s2c {
            return TcpState::Closing;
        }
        if self.syn_c2s && self.synack_s2c {
            return TcpState::Established;
        }
        if self.syn_c2s {
            return TcpState::SynSent;
        }
        TcpState::Partial
    }

    pub fn duration_secs(&self) -> f64 {
        (self.last_ts - self.first_ts) as f64 / 1e9
    }
}

/// The seed used for Community ID. Zero is the convention every tool defaults to.
pub const COMMUNITY_ID_SEED: u16 = 0;

#[derive(Default)]
pub struct FlowTable {
    flows: AHashMap<Tuple, Flow>,
    next_id: u64,
    /// Flows dropped because the table hit its cap. Reported in the run metadata so a
    /// truncated flow table is never mistaken for a complete one.
    pub evicted: u64,
    max_flows: usize,
}

impl FlowTable {
    pub fn new(max_flows: usize) -> Self {
        FlowTable {
            flows: AHashMap::new(),
            next_id: 1,
            evicted: 0,
            max_flows,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Fold a packet into its flow, returning the flow id and direction.
    ///
    /// The packet's `flow_id`, `community_id` and `direction` columns are filled in here.
    pub fn observe(&mut self, tuple: &Tuple, pkt: &mut Packet, ts: i64, frame: u64, len: u64) {
        let (key, forward) = tuple.normalized();

        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            // At capacity: the packet still gets counted in the packet table, it simply does
            // not open a new flow. Dropping silently would misreport the flow count, so this
            // is tallied.
            self.evicted += 1;
            return;
        }

        let id = self.next_id;
        let entry = self.flows.entry(key).or_insert_with(|| {
            let cid = community_id(
                &key.src_ip,
                &key.dst_ip,
                key.src_port,
                key.dst_port,
                key.proto,
                COMMUNITY_ID_SEED,
            );
            Flow {
                id,
                key,
                community_id: cid,
                first_ts: ts,
                last_ts: ts,
                first_frame: frame,
                last_frame: frame,
                packets_c2s: 0,
                packets_s2c: 0,
                bytes_c2s: 0,
                bytes_s2c: 0,
                tcp_flags_c2s: 0,
                tcp_flags_s2c: 0,
                syn_count: 0,
                fin_count: 0,
                rst_count: 0,
                fin_c2s: false,
                fin_s2c: false,
                syn_c2s: false,
                synack_s2c: false,
                saw_reset: false,
                service: None,
                sni: None,
                http_host: None,
                dns_qname: None,
                ja3: None,
                ja3s: None,
                ja4: None,
            }
        });
        if entry.id == id {
            self.next_id += 1;
        }

        // Timestamps can move backwards across a chunk boundary or a reordered capture, so
        // widen the interval rather than assuming monotonic arrival.
        entry.first_ts = entry.first_ts.min(ts);
        entry.last_ts = entry.last_ts.max(ts);
        entry.first_frame = entry.first_frame.min(frame);
        entry.last_frame = entry.last_frame.max(frame);

        if forward {
            entry.packets_c2s += 1;
            entry.bytes_c2s += len;
        } else {
            entry.packets_s2c += 1;
            entry.bytes_s2c += len;
        }

        if let Some(flags) = pkt.tcp_flags {
            if forward {
                entry.tcp_flags_c2s |= flags;
            } else {
                entry.tcp_flags_s2c |= flags;
            }
            let syn = flags & TCP_SYN != 0;
            let ack = flags & TCP_ACK != 0;
            if syn {
                entry.syn_count += 1;
                if forward && !ack {
                    entry.syn_c2s = true;
                }
                if !forward && ack {
                    entry.synack_s2c = true;
                }
            }
            if flags & TCP_FIN != 0 {
                entry.fin_count += 1;
                if forward {
                    entry.fin_c2s = true;
                } else {
                    entry.fin_s2c = true;
                }
            }
            if flags & TCP_RST != 0 {
                entry.rst_count += 1;
                entry.saw_reset = true;
            }
        }

        // Identifying details are recorded once, from the first packet that carried them.
        take_first(&mut entry.sni, &pkt.tls_sni);
        take_first(&mut entry.http_host, &pkt.http_host);
        take_first(&mut entry.dns_qname, &pkt.dns_qname);
        take_first(&mut entry.ja3, &pkt.ja3);
        take_first(&mut entry.ja3s, &pkt.ja3s);
        take_first(&mut entry.ja4, &pkt.ja4);
        if let Some(h) = &pkt.highest_layer {
            // Prefer the most specific layer seen anywhere in the flow: a TLS handshake
            // packet says more about the conversation than the ACKs around it.
            if entry.service.is_none()
                || matches!(entry.service.as_deref(), Some("tcp") | Some("udp"))
            {
                entry.service = Some(h.clone());
            }
        }

        pkt.flow_id = Some(entry.id);
        pkt.community_id = Some(entry.community_id.clone());
        pkt.direction = Some(if forward { "c2s" } else { "s2c" }.to_string());
    }

    /// Merge another table into this one, used to stitch flows across parallel chunks.
    ///
    /// Flow ids from the other table are discarded: only this table's numbering survives, so
    /// callers must remap packet `flow_id`s themselves if they need them to line up.
    pub fn merge(&mut self, other: FlowTable) {
        self.evicted += other.evicted;
        for (key, f) in other.flows {
            match self.flows.get_mut(&key) {
                Some(existing) => {
                    existing.first_ts = existing.first_ts.min(f.first_ts);
                    existing.last_ts = existing.last_ts.max(f.last_ts);
                    existing.first_frame = existing.first_frame.min(f.first_frame);
                    existing.last_frame = existing.last_frame.max(f.last_frame);
                    existing.packets_c2s += f.packets_c2s;
                    existing.packets_s2c += f.packets_s2c;
                    existing.bytes_c2s += f.bytes_c2s;
                    existing.bytes_s2c += f.bytes_s2c;
                    existing.tcp_flags_c2s |= f.tcp_flags_c2s;
                    existing.tcp_flags_s2c |= f.tcp_flags_s2c;
                    existing.syn_count += f.syn_count;
                    existing.fin_count += f.fin_count;
                    existing.rst_count += f.rst_count;
                    existing.fin_c2s |= f.fin_c2s;
                    existing.fin_s2c |= f.fin_s2c;
                    existing.syn_c2s |= f.syn_c2s;
                    existing.synack_s2c |= f.synack_s2c;
                    existing.saw_reset |= f.saw_reset;
                    take_owned(&mut existing.sni, f.sni);
                    take_owned(&mut existing.http_host, f.http_host);
                    take_owned(&mut existing.dns_qname, f.dns_qname);
                    take_owned(&mut existing.ja3, f.ja3);
                    take_owned(&mut existing.ja3s, f.ja3s);
                    take_owned(&mut existing.ja4, f.ja4);
                    take_owned(&mut existing.service, f.service);
                }
                None => {
                    let id = self.next_id;
                    self.next_id += 1;
                    self.flows.insert(key, Flow { id, ..f });
                }
            }
        }
    }

    /// Flows in ascending first-seen order, so the output is deterministic regardless of
    /// hash iteration order.
    pub fn sorted(&self) -> Vec<&Flow> {
        let mut v: Vec<&Flow> = self.flows.values().collect();
        v.sort_by_key(|f| (f.first_frame, f.id));
        v
    }

    pub fn to_record_batch(&self) -> Result<RecordBatch, ArrowError> {
        let mut b = FlowBuilder::new();
        for f in self.sorted() {
            b.append(f);
        }
        b.finish()
    }
}

fn take_first(slot: &mut Option<String>, v: &Option<String>) {
    if slot.is_none() {
        if let Some(x) = v {
            *slot = Some(x.clone());
        }
    }
}

fn take_owned(slot: &mut Option<String>, v: Option<String>) {
    if slot.is_none() {
        *slot = v;
    }
}

pub fn flow_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("flow_id", DataType::UInt64, true),
        Field::new("community_id", DataType::Utf8, true),
        Field::new("src_ip", DataType::Utf8, true),
        Field::new("dst_ip", DataType::Utf8, true),
        Field::new("src_port", DataType::UInt16, true),
        Field::new("dst_port", DataType::UInt16, true),
        Field::new("proto", DataType::UInt8, true),
        Field::new("proto_name", DataType::Utf8, true),
        Field::new("service", DataType::Utf8, true),
        Field::new(
            "first_ts",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            true,
        ),
        Field::new(
            "last_ts",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            true,
        ),
        Field::new("duration_sec", DataType::Float64, true),
        Field::new("first_frame", DataType::UInt64, true),
        Field::new("last_frame", DataType::UInt64, true),
        Field::new("packets_c2s", DataType::UInt64, true),
        Field::new("packets_s2c", DataType::UInt64, true),
        Field::new("packets_total", DataType::UInt64, true),
        Field::new("bytes_c2s", DataType::UInt64, true),
        Field::new("bytes_s2c", DataType::UInt64, true),
        Field::new("bytes_total", DataType::UInt64, true),
        Field::new("tcp_flags_c2s", DataType::UInt16, true),
        Field::new("tcp_flags_s2c", DataType::UInt16, true),
        Field::new("tcp_state", DataType::Utf8, true),
        Field::new("syn_count", DataType::UInt32, true),
        Field::new("fin_count", DataType::UInt32, true),
        Field::new("rst_count", DataType::UInt32, true),
        Field::new("tls_sni", DataType::Utf8, true),
        Field::new("http_host", DataType::Utf8, true),
        Field::new("dns_qname", DataType::Utf8, true),
        Field::new("ja3", DataType::Utf8, true),
        Field::new("ja3s", DataType::Utf8, true),
        Field::new("ja4", DataType::Utf8, true),
    ]))
}

struct FlowBuilder {
    flow_id: UInt64Builder,
    community_id: StringBuilder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    proto: UInt8Builder,
    proto_name: StringBuilder,
    service: StringBuilder,
    first_ts: TimestampNanosecondBuilder,
    last_ts: TimestampNanosecondBuilder,
    duration_sec: Float64Builder,
    first_frame: UInt64Builder,
    last_frame: UInt64Builder,
    packets_c2s: UInt64Builder,
    packets_s2c: UInt64Builder,
    packets_total: UInt64Builder,
    bytes_c2s: UInt64Builder,
    bytes_s2c: UInt64Builder,
    bytes_total: UInt64Builder,
    tcp_flags_c2s: UInt16Builder,
    tcp_flags_s2c: UInt16Builder,
    tcp_state: StringBuilder,
    syn_count: UInt32Builder,
    fin_count: UInt32Builder,
    rst_count: UInt32Builder,
    tls_sni: StringBuilder,
    http_host: StringBuilder,
    dns_qname: StringBuilder,
    ja3: StringBuilder,
    ja3s: StringBuilder,
    ja4: StringBuilder,
}

impl FlowBuilder {
    fn new() -> Self {
        FlowBuilder {
            flow_id: UInt64Builder::new(),
            community_id: StringBuilder::new(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: UInt16Builder::new(),
            dst_port: UInt16Builder::new(),
            proto: UInt8Builder::new(),
            proto_name: StringBuilder::new(),
            service: StringBuilder::new(),
            first_ts: TimestampNanosecondBuilder::new(),
            last_ts: TimestampNanosecondBuilder::new(),
            duration_sec: Float64Builder::new(),
            first_frame: UInt64Builder::new(),
            last_frame: UInt64Builder::new(),
            packets_c2s: UInt64Builder::new(),
            packets_s2c: UInt64Builder::new(),
            packets_total: UInt64Builder::new(),
            bytes_c2s: UInt64Builder::new(),
            bytes_s2c: UInt64Builder::new(),
            bytes_total: UInt64Builder::new(),
            tcp_flags_c2s: UInt16Builder::new(),
            tcp_flags_s2c: UInt16Builder::new(),
            tcp_state: StringBuilder::new(),
            syn_count: UInt32Builder::new(),
            fin_count: UInt32Builder::new(),
            rst_count: UInt32Builder::new(),
            tls_sni: StringBuilder::new(),
            http_host: StringBuilder::new(),
            dns_qname: StringBuilder::new(),
            ja3: StringBuilder::new(),
            ja3s: StringBuilder::new(),
            ja4: StringBuilder::new(),
        }
    }

    fn append(&mut self, f: &Flow) {
        self.flow_id.append_value(f.id);
        self.community_id.append_value(&f.community_id);
        self.src_ip.append_value(f.key.src_ip.to_string());
        self.dst_ip.append_value(f.key.dst_ip.to_string());
        self.src_port.append_value(f.key.src_port);
        self.dst_port.append_value(f.key.dst_port);
        self.proto.append_value(f.key.proto);
        self.proto_name
            .append_value(crate::dissect::l3::proto_name(f.key.proto));
        self.service.append_option(f.service.as_deref());
        self.first_ts.append_value(f.first_ts);
        self.last_ts.append_value(f.last_ts);
        self.duration_sec.append_value(f.duration_secs());
        self.first_frame.append_value(f.first_frame);
        self.last_frame.append_value(f.last_frame);
        self.packets_c2s.append_value(f.packets_c2s);
        self.packets_s2c.append_value(f.packets_s2c);
        self.packets_total
            .append_value(f.packets_c2s + f.packets_s2c);
        self.bytes_c2s.append_value(f.bytes_c2s);
        self.bytes_s2c.append_value(f.bytes_s2c);
        self.bytes_total.append_value(f.bytes_c2s + f.bytes_s2c);
        self.tcp_flags_c2s.append_value(f.tcp_flags_c2s);
        self.tcp_flags_s2c.append_value(f.tcp_flags_s2c);
        self.tcp_state.append_value(f.state().as_str());
        self.syn_count.append_value(f.syn_count);
        self.fin_count.append_value(f.fin_count);
        self.rst_count.append_value(f.rst_count);
        self.tls_sni.append_option(f.sni.as_deref());
        self.http_host.append_option(f.http_host.as_deref());
        self.dns_qname.append_option(f.dns_qname.as_deref());
        self.ja3.append_option(f.ja3.as_deref());
        self.ja3s.append_option(f.ja3s.as_deref());
        self.ja4.append_option(f.ja4.as_deref());
    }

    fn finish(&mut self) -> Result<RecordBatch, ArrowError> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.flow_id.finish()),
            Arc::new(self.community_id.finish()),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.proto.finish()),
            Arc::new(self.proto_name.finish()),
            Arc::new(self.service.finish()),
            Arc::new(self.first_ts.finish()),
            Arc::new(self.last_ts.finish()),
            Arc::new(self.duration_sec.finish()),
            Arc::new(self.first_frame.finish()),
            Arc::new(self.last_frame.finish()),
            Arc::new(self.packets_c2s.finish()),
            Arc::new(self.packets_s2c.finish()),
            Arc::new(self.packets_total.finish()),
            Arc::new(self.bytes_c2s.finish()),
            Arc::new(self.bytes_s2c.finish()),
            Arc::new(self.bytes_total.finish()),
            Arc::new(self.tcp_flags_c2s.finish()),
            Arc::new(self.tcp_flags_s2c.finish()),
            Arc::new(self.tcp_state.finish()),
            Arc::new(self.syn_count.finish()),
            Arc::new(self.fin_count.finish()),
            Arc::new(self.rst_count.finish()),
            Arc::new(self.tls_sni.finish()),
            Arc::new(self.http_host.finish()),
            Arc::new(self.dns_qname.finish()),
            Arc::new(self.ja3.finish()),
            Arc::new(self.ja3s.finish()),
            Arc::new(self.ja4.finish()),
        ];
        RecordBatch::try_new(flow_schema(), columns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn tuple(sp: u16, dp: u16) -> Tuple {
        Tuple {
            src_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_ip: "10.0.0.2".parse::<IpAddr>().unwrap(),
            src_port: sp,
            dst_port: dp,
            proto: 6,
        }
    }

    fn reverse(t: &Tuple) -> Tuple {
        Tuple {
            src_ip: t.dst_ip,
            dst_ip: t.src_ip,
            src_port: t.dst_port,
            dst_port: t.src_port,
            proto: t.proto,
        }
    }

    fn observe(
        table: &mut FlowTable,
        t: &Tuple,
        flags: u16,
        ts: i64,
        frame: u64,
        len: u64,
    ) -> Packet {
        let mut p = Packet {
            tcp_flags: Some(flags),
            ..Default::default()
        };
        table.observe(t, &mut p, ts, frame, len);
        p
    }

    #[test]
    fn both_directions_land_in_one_flow() {
        let mut t = FlowTable::new(1000);
        let fwd = tuple(50000, 443);
        let rev = reverse(&fwd);

        let a = observe(&mut t, &fwd, TCP_SYN, 1_000, 1, 74);
        let b = observe(&mut t, &rev, TCP_SYN | TCP_ACK, 2_000, 2, 74);

        assert_eq!(t.len(), 1);
        assert_eq!(a.flow_id, b.flow_id);
        assert_eq!(a.direction.as_deref(), Some("c2s"));
        assert_eq!(b.direction.as_deref(), Some("s2c"));
        // Both directions must agree on the community id.
        assert_eq!(a.community_id, b.community_id);

        let f = t.sorted()[0];
        assert_eq!(f.state(), TcpState::Established);
        assert_eq!(f.packets_c2s, 1);
        assert_eq!(f.packets_s2c, 1);
        assert_eq!(f.bytes_c2s + f.bytes_s2c, 148);
    }

    #[test]
    fn tcp_state_progression() {
        let mut t = FlowTable::new(1000);
        let fwd = tuple(40000, 80);
        let rev = reverse(&fwd);

        observe(&mut t, &fwd, TCP_SYN, 1, 1, 60);
        assert_eq!(t.sorted()[0].state(), TcpState::SynSent);

        observe(&mut t, &rev, TCP_SYN | TCP_ACK, 2, 2, 60);
        assert_eq!(t.sorted()[0].state(), TcpState::Established);

        observe(&mut t, &fwd, TCP_FIN | TCP_ACK, 3, 3, 60);
        assert_eq!(t.sorted()[0].state(), TcpState::Closing);

        observe(&mut t, &rev, TCP_FIN | TCP_ACK, 4, 4, 60);
        assert_eq!(t.sorted()[0].state(), TcpState::Closed);
    }

    #[test]
    fn reset_wins_over_other_states() {
        let mut t = FlowTable::new(1000);
        let fwd = tuple(40000, 80);
        observe(&mut t, &fwd, TCP_SYN, 1, 1, 60);
        observe(&mut t, &reverse(&fwd), TCP_RST | TCP_ACK, 2, 2, 60);
        assert_eq!(t.sorted()[0].state(), TcpState::Reset);
    }

    #[test]
    fn capacity_is_enforced_and_counted() {
        let mut t = FlowTable::new(2);
        observe(&mut t, &tuple(1, 80), TCP_SYN, 1, 1, 60);
        observe(&mut t, &tuple(2, 80), TCP_SYN, 2, 2, 60);
        let p = observe(&mut t, &tuple(3, 80), TCP_SYN, 3, 3, 60);

        assert_eq!(t.len(), 2);
        assert_eq!(t.evicted, 1);
        // The over-cap packet gets no flow id rather than a wrong one.
        assert!(p.flow_id.is_none());
    }

    #[test]
    fn merge_combines_counters_across_chunks() {
        let fwd = tuple(50000, 443);
        let mut a = FlowTable::new(1000);
        observe(&mut a, &fwd, TCP_SYN, 1, 1, 100);

        let mut b = FlowTable::new(1000);
        observe(&mut b, &reverse(&fwd), TCP_SYN | TCP_ACK, 2, 2, 200);
        observe(&mut b, &tuple(60000, 53), 0, 3, 3, 50);

        a.merge(b);
        assert_eq!(a.len(), 2);
        let stitched = a
            .sorted()
            .into_iter()
            .find(|f| f.key.proto == 6 && f.packets_c2s > 0)
            .unwrap();
        assert_eq!(stitched.packets_c2s + stitched.packets_s2c, 2);
        assert_eq!(stitched.bytes_c2s + stitched.bytes_s2c, 300);
        assert_eq!(stitched.state(), TcpState::Established);
    }

    #[test]
    fn record_batch_matches_the_schema() {
        let mut t = FlowTable::new(1000);
        observe(&mut t, &tuple(50000, 443), TCP_SYN, 1, 1, 74);
        let batch = t.to_record_batch().unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), flow_schema().fields().len());
    }
}
