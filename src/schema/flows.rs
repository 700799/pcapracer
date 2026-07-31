//! `flows` table: one row per bidirectional flow with CIC-style features.

use super::push_ip;
use crate::flow::FlowRow;
use arrow_array::builder::{
    BooleanBuilder, Float64Builder, StringBuilder, TimestampNanosecondBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

macro_rules! fields {
    ($($name:literal : $dt:expr, $null:literal);* $(;)?) => {
        vec![ $( Field::new($name, $dt, $null) ),* ]
    };
}

pub fn schema() -> Arc<Schema> {
    use DataType::*;
    let ts = || Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
    let f = fields![
        "flow_id": UInt64, false;
        "src_ip": Utf8, false;
        "dst_ip": Utf8, false;
        "src_port": UInt16, false;
        "dst_port": UInt16, false;
        "proto": UInt8, false;
        "proto_name": Utf8, false;
        "vlan_id": UInt16, true;
        "tunneled": Boolean, false;
        "first_ts": ts(), false;
        "last_ts": ts(), false;
        "duration_s": Float64, false;
        "end_reason": Utf8, false;
        "fwd_pkts": UInt64, false;
        "bwd_pkts": UInt64, false;
        "fwd_bytes": UInt64, false;
        "bwd_bytes": UInt64, false;
        "fwd_payload_bytes": UInt64, false;
        "bwd_payload_bytes": UInt64, false;
        "fwd_header_bytes": UInt64, false;
        "bwd_header_bytes": UInt64, false;
        "fwd_pkts_with_payload": UInt64, false;
        "bwd_pkts_with_payload": UInt64, false;
        "pkt_len_min": UInt32, true;
        "pkt_len_max": UInt32, true;
        "pkt_len_mean": Float64, true;
        "pkt_len_std": Float64, true;
        "fwd_pkt_len_min": UInt32, true;
        "fwd_pkt_len_max": UInt32, true;
        "fwd_pkt_len_mean": Float64, true;
        "fwd_pkt_len_std": Float64, true;
        "bwd_pkt_len_min": UInt32, true;
        "bwd_pkt_len_max": UInt32, true;
        "bwd_pkt_len_mean": Float64, true;
        "bwd_pkt_len_std": Float64, true;
        "fwd_seg_size_min": UInt32, true;
        "fwd_seg_size_avg": Float64, true;
        "bwd_seg_size_avg": Float64, true;
        "flow_iat_min": Float64, true;
        "flow_iat_max": Float64, true;
        "flow_iat_mean": Float64, true;
        "flow_iat_std": Float64, true;
        "fwd_iat_total": Float64, false;
        "fwd_iat_min": Float64, true;
        "fwd_iat_max": Float64, true;
        "fwd_iat_mean": Float64, true;
        "fwd_iat_std": Float64, true;
        "bwd_iat_total": Float64, false;
        "bwd_iat_min": Float64, true;
        "bwd_iat_max": Float64, true;
        "bwd_iat_mean": Float64, true;
        "bwd_iat_std": Float64, true;
        "syn_count": UInt32, false;
        "fin_count": UInt32, false;
        "rst_count": UInt32, false;
        "psh_count": UInt32, false;
        "ack_count": UInt32, false;
        "urg_count": UInt32, false;
        "ece_count": UInt32, false;
        "cwr_count": UInt32, false;
        "fwd_psh_count": UInt32, false;
        "bwd_psh_count": UInt32, false;
        "fwd_urg_count": UInt32, false;
        "bwd_urg_count": UInt32, false;
        "flow_pkts_per_s": Float64, false;
        "flow_bytes_per_s": Float64, false;
        "fwd_pkts_per_s": Float64, false;
        "bwd_pkts_per_s": Float64, false;
        "down_up_ratio": Float64, false;
        "init_win_fwd": UInt32, true;
        "init_win_bwd": UInt32, true;
        "tcp_handshake_complete": Boolean, false;
        "syn_synack_rtt_s": Float64, true;
        "active_min": Float64, true;
        "active_max": Float64, true;
        "active_mean": Float64, true;
        "active_std": Float64, true;
        "idle_min": Float64, true;
        "idle_max": Float64, true;
        "idle_mean": Float64, true;
        "idle_std": Float64, true;
        "active_count": UInt32, false;
        "app_protos": Utf8, true;
        "dns_qnames": Utf8, true;
        "dns_qname_count": UInt32, false;
        "tls_sni": Utf8, true;
        "tls_version": UInt16, true;
        "ja3": Utf8, true;
        "ja3s": Utf8, true;
        "ja4": Utf8, true;
        "http_hosts": Utf8, true;
        "http_user_agent": Utf8, true;
        "http_methods": Utf8, true;
        "client_banner": Utf8, true;
        "server_banner": Utf8, true;
    ];
    Arc::new(Schema::new(f))
}

pub struct FlowsBuilder {
    schema: Arc<Schema>,
    scratch: String,
    n: usize,
    flow_id: UInt64Builder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    proto: UInt8Builder,
    proto_name: StringBuilder,
    vlan_id: UInt16Builder,
    tunneled: BooleanBuilder,
    first_ts: TimestampNanosecondBuilder,
    last_ts: TimestampNanosecondBuilder,
    duration_s: Float64Builder,
    end_reason: StringBuilder,
    fwd_pkts: UInt64Builder,
    bwd_pkts: UInt64Builder,
    fwd_bytes: UInt64Builder,
    bwd_bytes: UInt64Builder,
    fwd_payload_bytes: UInt64Builder,
    bwd_payload_bytes: UInt64Builder,
    fwd_header_bytes: UInt64Builder,
    bwd_header_bytes: UInt64Builder,
    fwd_pkts_with_payload: UInt64Builder,
    bwd_pkts_with_payload: UInt64Builder,
    pkt_len_min: UInt32Builder,
    pkt_len_max: UInt32Builder,
    pkt_len_mean: Float64Builder,
    pkt_len_std: Float64Builder,
    fwd_pkt_len_min: UInt32Builder,
    fwd_pkt_len_max: UInt32Builder,
    fwd_pkt_len_mean: Float64Builder,
    fwd_pkt_len_std: Float64Builder,
    bwd_pkt_len_min: UInt32Builder,
    bwd_pkt_len_max: UInt32Builder,
    bwd_pkt_len_mean: Float64Builder,
    bwd_pkt_len_std: Float64Builder,
    fwd_seg_size_min: UInt32Builder,
    fwd_seg_size_avg: Float64Builder,
    bwd_seg_size_avg: Float64Builder,
    flow_iat_min: Float64Builder,
    flow_iat_max: Float64Builder,
    flow_iat_mean: Float64Builder,
    flow_iat_std: Float64Builder,
    fwd_iat_total: Float64Builder,
    fwd_iat_min: Float64Builder,
    fwd_iat_max: Float64Builder,
    fwd_iat_mean: Float64Builder,
    fwd_iat_std: Float64Builder,
    bwd_iat_total: Float64Builder,
    bwd_iat_min: Float64Builder,
    bwd_iat_max: Float64Builder,
    bwd_iat_mean: Float64Builder,
    bwd_iat_std: Float64Builder,
    syn_count: UInt32Builder,
    fin_count: UInt32Builder,
    rst_count: UInt32Builder,
    psh_count: UInt32Builder,
    ack_count: UInt32Builder,
    urg_count: UInt32Builder,
    ece_count: UInt32Builder,
    cwr_count: UInt32Builder,
    fwd_psh_count: UInt32Builder,
    bwd_psh_count: UInt32Builder,
    fwd_urg_count: UInt32Builder,
    bwd_urg_count: UInt32Builder,
    flow_pkts_per_s: Float64Builder,
    flow_bytes_per_s: Float64Builder,
    fwd_pkts_per_s: Float64Builder,
    bwd_pkts_per_s: Float64Builder,
    down_up_ratio: Float64Builder,
    init_win_fwd: UInt32Builder,
    init_win_bwd: UInt32Builder,
    tcp_handshake_complete: BooleanBuilder,
    syn_synack_rtt_s: Float64Builder,
    active_min: Float64Builder,
    active_max: Float64Builder,
    active_mean: Float64Builder,
    active_std: Float64Builder,
    idle_min: Float64Builder,
    idle_max: Float64Builder,
    idle_mean: Float64Builder,
    idle_std: Float64Builder,
    active_count: UInt32Builder,
    app_protos: StringBuilder,
    dns_qnames: StringBuilder,
    dns_qname_count: UInt32Builder,
    tls_sni: StringBuilder,
    tls_version: UInt16Builder,
    ja3: StringBuilder,
    ja3s: StringBuilder,
    ja4: StringBuilder,
    http_hosts: StringBuilder,
    http_user_agent: StringBuilder,
    http_methods: StringBuilder,
    client_banner: StringBuilder,
    server_banner: StringBuilder,
}

impl FlowsBuilder {
    pub fn new() -> FlowsBuilder {
        FlowsBuilder {
            schema: schema(),
            scratch: String::with_capacity(48),
            n: 0,
            flow_id: Default::default(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: Default::default(),
            dst_port: Default::default(),
            proto: Default::default(),
            proto_name: StringBuilder::new(),
            vlan_id: Default::default(),
            tunneled: Default::default(),
            first_ts: Default::default(),
            last_ts: Default::default(),
            duration_s: Default::default(),
            end_reason: StringBuilder::new(),
            fwd_pkts: Default::default(),
            bwd_pkts: Default::default(),
            fwd_bytes: Default::default(),
            bwd_bytes: Default::default(),
            fwd_payload_bytes: Default::default(),
            bwd_payload_bytes: Default::default(),
            fwd_header_bytes: Default::default(),
            bwd_header_bytes: Default::default(),
            fwd_pkts_with_payload: Default::default(),
            bwd_pkts_with_payload: Default::default(),
            pkt_len_min: Default::default(),
            pkt_len_max: Default::default(),
            pkt_len_mean: Default::default(),
            pkt_len_std: Default::default(),
            fwd_pkt_len_min: Default::default(),
            fwd_pkt_len_max: Default::default(),
            fwd_pkt_len_mean: Default::default(),
            fwd_pkt_len_std: Default::default(),
            bwd_pkt_len_min: Default::default(),
            bwd_pkt_len_max: Default::default(),
            bwd_pkt_len_mean: Default::default(),
            bwd_pkt_len_std: Default::default(),
            fwd_seg_size_min: Default::default(),
            fwd_seg_size_avg: Default::default(),
            bwd_seg_size_avg: Default::default(),
            flow_iat_min: Default::default(),
            flow_iat_max: Default::default(),
            flow_iat_mean: Default::default(),
            flow_iat_std: Default::default(),
            fwd_iat_total: Default::default(),
            fwd_iat_min: Default::default(),
            fwd_iat_max: Default::default(),
            fwd_iat_mean: Default::default(),
            fwd_iat_std: Default::default(),
            bwd_iat_total: Default::default(),
            bwd_iat_min: Default::default(),
            bwd_iat_max: Default::default(),
            bwd_iat_mean: Default::default(),
            bwd_iat_std: Default::default(),
            syn_count: Default::default(),
            fin_count: Default::default(),
            rst_count: Default::default(),
            psh_count: Default::default(),
            ack_count: Default::default(),
            urg_count: Default::default(),
            ece_count: Default::default(),
            cwr_count: Default::default(),
            fwd_psh_count: Default::default(),
            bwd_psh_count: Default::default(),
            fwd_urg_count: Default::default(),
            bwd_urg_count: Default::default(),
            flow_pkts_per_s: Default::default(),
            flow_bytes_per_s: Default::default(),
            fwd_pkts_per_s: Default::default(),
            bwd_pkts_per_s: Default::default(),
            down_up_ratio: Default::default(),
            init_win_fwd: Default::default(),
            init_win_bwd: Default::default(),
            tcp_handshake_complete: Default::default(),
            syn_synack_rtt_s: Default::default(),
            active_min: Default::default(),
            active_max: Default::default(),
            active_mean: Default::default(),
            active_std: Default::default(),
            idle_min: Default::default(),
            idle_max: Default::default(),
            idle_mean: Default::default(),
            idle_std: Default::default(),
            active_count: Default::default(),
            app_protos: StringBuilder::new(),
            dns_qnames: StringBuilder::new(),
            dns_qname_count: Default::default(),
            tls_sni: StringBuilder::new(),
            tls_version: Default::default(),
            ja3: StringBuilder::new(),
            ja3s: StringBuilder::new(),
            ja4: StringBuilder::new(),
            http_hosts: StringBuilder::new(),
            http_user_agent: StringBuilder::new(),
            http_methods: StringBuilder::new(),
            client_banner: StringBuilder::new(),
            server_banner: StringBuilder::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn append(&mut self, r: &FlowRow) {
        self.n += 1;
        self.flow_id.append_value(r.flow_id);
        push_ip(&mut self.src_ip, &mut self.scratch, Some(r.src_ip));
        push_ip(&mut self.dst_ip, &mut self.scratch, Some(r.dst_ip));
        self.src_port.append_value(r.src_port);
        self.dst_port.append_value(r.dst_port);
        self.proto.append_value(r.proto);
        self.proto_name.append_value(r.proto_name);
        self.vlan_id.append_option(r.vlan_id);
        self.tunneled.append_value(r.tunneled);
        self.first_ts.append_value(r.first_ts);
        self.last_ts.append_value(r.last_ts);
        self.duration_s.append_value(r.duration_s);
        self.end_reason.append_value(r.end_reason);

        self.fwd_pkts.append_value(r.fwd_pkts);
        self.bwd_pkts.append_value(r.bwd_pkts);
        self.fwd_bytes.append_value(r.fwd_bytes);
        self.bwd_bytes.append_value(r.bwd_bytes);
        self.fwd_payload_bytes.append_value(r.fwd_payload_bytes);
        self.bwd_payload_bytes.append_value(r.bwd_payload_bytes);
        self.fwd_header_bytes.append_value(r.fwd_header_bytes);
        self.bwd_header_bytes.append_value(r.bwd_header_bytes);
        self.fwd_pkts_with_payload
            .append_value(r.fwd_pkts_with_payload);
        self.bwd_pkts_with_payload
            .append_value(r.bwd_pkts_with_payload);

        self.pkt_len_min.append_option(r.pkt_len_min);
        self.pkt_len_max.append_option(r.pkt_len_max);
        self.pkt_len_mean.append_option(r.pkt_len_mean);
        self.pkt_len_std.append_option(r.pkt_len_std);
        self.fwd_pkt_len_min.append_option(r.fwd_pkt_len_min);
        self.fwd_pkt_len_max.append_option(r.fwd_pkt_len_max);
        self.fwd_pkt_len_mean.append_option(r.fwd_pkt_len_mean);
        self.fwd_pkt_len_std.append_option(r.fwd_pkt_len_std);
        self.bwd_pkt_len_min.append_option(r.bwd_pkt_len_min);
        self.bwd_pkt_len_max.append_option(r.bwd_pkt_len_max);
        self.bwd_pkt_len_mean.append_option(r.bwd_pkt_len_mean);
        self.bwd_pkt_len_std.append_option(r.bwd_pkt_len_std);
        self.fwd_seg_size_min.append_option(r.fwd_seg_size_min);
        self.fwd_seg_size_avg.append_option(r.fwd_seg_size_avg);
        self.bwd_seg_size_avg.append_option(r.bwd_seg_size_avg);

        self.flow_iat_min.append_option(r.flow_iat_min);
        self.flow_iat_max.append_option(r.flow_iat_max);
        self.flow_iat_mean.append_option(r.flow_iat_mean);
        self.flow_iat_std.append_option(r.flow_iat_std);
        self.fwd_iat_total.append_value(r.fwd_iat_total);
        self.fwd_iat_min.append_option(r.fwd_iat_min);
        self.fwd_iat_max.append_option(r.fwd_iat_max);
        self.fwd_iat_mean.append_option(r.fwd_iat_mean);
        self.fwd_iat_std.append_option(r.fwd_iat_std);
        self.bwd_iat_total.append_value(r.bwd_iat_total);
        self.bwd_iat_min.append_option(r.bwd_iat_min);
        self.bwd_iat_max.append_option(r.bwd_iat_max);
        self.bwd_iat_mean.append_option(r.bwd_iat_mean);
        self.bwd_iat_std.append_option(r.bwd_iat_std);

        self.syn_count.append_value(r.syn_count);
        self.fin_count.append_value(r.fin_count);
        self.rst_count.append_value(r.rst_count);
        self.psh_count.append_value(r.psh_count);
        self.ack_count.append_value(r.ack_count);
        self.urg_count.append_value(r.urg_count);
        self.ece_count.append_value(r.ece_count);
        self.cwr_count.append_value(r.cwr_count);
        self.fwd_psh_count.append_value(r.fwd_psh_count);
        self.bwd_psh_count.append_value(r.bwd_psh_count);
        self.fwd_urg_count.append_value(r.fwd_urg_count);
        self.bwd_urg_count.append_value(r.bwd_urg_count);

        self.flow_pkts_per_s.append_value(r.flow_pkts_per_s);
        self.flow_bytes_per_s.append_value(r.flow_bytes_per_s);
        self.fwd_pkts_per_s.append_value(r.fwd_pkts_per_s);
        self.bwd_pkts_per_s.append_value(r.bwd_pkts_per_s);
        self.down_up_ratio.append_value(r.down_up_ratio);

        self.init_win_fwd.append_option(r.init_win_fwd);
        self.init_win_bwd.append_option(r.init_win_bwd);
        self.tcp_handshake_complete
            .append_value(r.tcp_handshake_complete);
        self.syn_synack_rtt_s.append_option(r.syn_synack_rtt_s);

        self.active_min.append_option(r.active_min);
        self.active_max.append_option(r.active_max);
        self.active_mean.append_option(r.active_mean);
        self.active_std.append_option(r.active_std);
        self.idle_min.append_option(r.idle_min);
        self.idle_max.append_option(r.idle_max);
        self.idle_mean.append_option(r.idle_mean);
        self.idle_std.append_option(r.idle_std);
        self.active_count.append_value(r.active_count);

        self.app_protos.append_option(r.app_protos.as_deref());
        self.dns_qnames.append_option(r.dns_qnames.as_deref());
        self.dns_qname_count.append_value(r.dns_qname_count);
        self.tls_sni.append_option(r.tls_sni.as_deref());
        self.tls_version.append_option(r.tls_version);
        self.ja3.append_option(r.ja3.as_deref());
        self.ja3s.append_option(r.ja3s.as_deref());
        self.ja4.append_option(r.ja4.as_deref());
        self.http_hosts.append_option(r.http_hosts.as_deref());
        self.http_user_agent
            .append_option(r.http_user_agent.as_deref());
        self.http_methods.append_option(r.http_methods.as_deref());
        self.client_banner.append_option(r.client_banner.as_deref());
        self.server_banner.append_option(r.server_banner.as_deref());
    }

    pub fn finish(&mut self) -> Result<RecordBatch, arrow_schema::ArrowError> {
        let first_ts = self.first_ts.finish().with_timezone("UTC");
        let last_ts = self.last_ts.finish().with_timezone("UTC");
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(self.flow_id.finish()),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.proto.finish()),
            Arc::new(self.proto_name.finish()),
            Arc::new(self.vlan_id.finish()),
            Arc::new(self.tunneled.finish()),
            Arc::new(first_ts),
            Arc::new(last_ts),
            Arc::new(self.duration_s.finish()),
            Arc::new(self.end_reason.finish()),
            Arc::new(self.fwd_pkts.finish()),
            Arc::new(self.bwd_pkts.finish()),
            Arc::new(self.fwd_bytes.finish()),
            Arc::new(self.bwd_bytes.finish()),
            Arc::new(self.fwd_payload_bytes.finish()),
            Arc::new(self.bwd_payload_bytes.finish()),
            Arc::new(self.fwd_header_bytes.finish()),
            Arc::new(self.bwd_header_bytes.finish()),
            Arc::new(self.fwd_pkts_with_payload.finish()),
            Arc::new(self.bwd_pkts_with_payload.finish()),
            Arc::new(self.pkt_len_min.finish()),
            Arc::new(self.pkt_len_max.finish()),
            Arc::new(self.pkt_len_mean.finish()),
            Arc::new(self.pkt_len_std.finish()),
            Arc::new(self.fwd_pkt_len_min.finish()),
            Arc::new(self.fwd_pkt_len_max.finish()),
            Arc::new(self.fwd_pkt_len_mean.finish()),
            Arc::new(self.fwd_pkt_len_std.finish()),
            Arc::new(self.bwd_pkt_len_min.finish()),
            Arc::new(self.bwd_pkt_len_max.finish()),
            Arc::new(self.bwd_pkt_len_mean.finish()),
            Arc::new(self.bwd_pkt_len_std.finish()),
            Arc::new(self.fwd_seg_size_min.finish()),
            Arc::new(self.fwd_seg_size_avg.finish()),
            Arc::new(self.bwd_seg_size_avg.finish()),
            Arc::new(self.flow_iat_min.finish()),
            Arc::new(self.flow_iat_max.finish()),
            Arc::new(self.flow_iat_mean.finish()),
            Arc::new(self.flow_iat_std.finish()),
            Arc::new(self.fwd_iat_total.finish()),
            Arc::new(self.fwd_iat_min.finish()),
            Arc::new(self.fwd_iat_max.finish()),
            Arc::new(self.fwd_iat_mean.finish()),
            Arc::new(self.fwd_iat_std.finish()),
            Arc::new(self.bwd_iat_total.finish()),
            Arc::new(self.bwd_iat_min.finish()),
            Arc::new(self.bwd_iat_max.finish()),
            Arc::new(self.bwd_iat_mean.finish()),
            Arc::new(self.bwd_iat_std.finish()),
            Arc::new(self.syn_count.finish()),
            Arc::new(self.fin_count.finish()),
            Arc::new(self.rst_count.finish()),
            Arc::new(self.psh_count.finish()),
            Arc::new(self.ack_count.finish()),
            Arc::new(self.urg_count.finish()),
            Arc::new(self.ece_count.finish()),
            Arc::new(self.cwr_count.finish()),
            Arc::new(self.fwd_psh_count.finish()),
            Arc::new(self.bwd_psh_count.finish()),
            Arc::new(self.fwd_urg_count.finish()),
            Arc::new(self.bwd_urg_count.finish()),
            Arc::new(self.flow_pkts_per_s.finish()),
            Arc::new(self.flow_bytes_per_s.finish()),
            Arc::new(self.fwd_pkts_per_s.finish()),
            Arc::new(self.bwd_pkts_per_s.finish()),
            Arc::new(self.down_up_ratio.finish()),
            Arc::new(self.init_win_fwd.finish()),
            Arc::new(self.init_win_bwd.finish()),
            Arc::new(self.tcp_handshake_complete.finish()),
            Arc::new(self.syn_synack_rtt_s.finish()),
            Arc::new(self.active_min.finish()),
            Arc::new(self.active_max.finish()),
            Arc::new(self.active_mean.finish()),
            Arc::new(self.active_std.finish()),
            Arc::new(self.idle_min.finish()),
            Arc::new(self.idle_max.finish()),
            Arc::new(self.idle_mean.finish()),
            Arc::new(self.idle_std.finish()),
            Arc::new(self.active_count.finish()),
            Arc::new(self.app_protos.finish()),
            Arc::new(self.dns_qnames.finish()),
            Arc::new(self.dns_qname_count.finish()),
            Arc::new(self.tls_sni.finish()),
            Arc::new(self.tls_version.finish()),
            Arc::new(self.ja3.finish()),
            Arc::new(self.ja3s.finish()),
            Arc::new(self.ja4.finish()),
            Arc::new(self.http_hosts.finish()),
            Arc::new(self.http_user_agent.finish()),
            Arc::new(self.http_methods.finish()),
            Arc::new(self.client_banner.finish()),
            Arc::new(self.server_banner.finish()),
        ];
        self.n = 0;
        RecordBatch::try_new(Arc::clone(&self.schema), arrays)
    }
}

impl Default for FlowsBuilder {
    fn default() -> Self {
        Self::new()
    }
}
