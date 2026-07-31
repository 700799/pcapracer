//! Bidirectional flow tracking and CIC-style feature computation.

pub mod key;
pub mod stats;

use crate::util::IpRepr;
use key::{proto_name, FlowEvent, FlowKey};
use stats::{ActiveIdle, Welford};
use std::collections::{BTreeSet, HashMap};

const SWEEP_INTERVAL_NS: i64 = 4_000_000_000; // sweep at most every 4s of capture time
const TCP: u8 = 6;

#[derive(Clone, Copy, Debug)]
pub enum EndReason {
    Idle,
    Fin,
    Rst,
    Eof,
}

impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            EndReason::Idle => "idle",
            EndReason::Fin => "fin",
            EndReason::Rst => "rst",
            EndReason::Eof => "eof",
        }
    }
}

/// Application-layer enrichment collected per flow (populated in M4/M5).
#[derive(Default, Debug)]
pub struct FlowEnrich {
    pub app_protos: BTreeSet<&'static str>,
    pub dns_qnames: Vec<String>,
    pub tls_sni: Option<String>,
    pub tls_version: Option<u16>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja4: Option<String>,
    pub http_hosts: Vec<String>,
    pub http_user_agent: Option<String>,
    pub http_methods: BTreeSet<String>,
    pub client_banner: Option<String>,
    pub server_banner: Option<String>,
}

struct FlowState {
    orig_src: IpRepr,
    orig_dst: IpRepr,
    orig_sport: u16,
    orig_dport: u16,
    proto: u8,
    initiator_is_a: bool,
    vlan_id: Option<u16>,
    tunneled: bool,
    first_ts: i64,
    last_ts: i64,
    started: bool,

    fwd_pkts: u64,
    bwd_pkts: u64,
    fwd_bytes: u64,
    bwd_bytes: u64,
    fwd_payload: u64,
    bwd_payload: u64,
    fwd_header: u64,
    bwd_header: u64,
    fwd_pwp: u64,
    bwd_pwp: u64,

    len_all: Welford,
    len_fwd: Welford,
    len_bwd: Welford,
    fwd_seg_min: Option<u32>,

    iat_flow: Welford,
    iat_fwd: Welford,
    iat_bwd: Welford,
    fwd_iat_total: f64,
    bwd_iat_total: f64,
    last_ts_fwd: Option<i64>,
    last_ts_bwd: Option<i64>,

    syn: u32,
    fin: u32,
    rst: u32,
    psh: u32,
    ack: u32,
    urg: u32,
    ece: u32,
    cwr: u32,
    fwd_psh: u32,
    bwd_psh: u32,
    fwd_urg: u32,
    bwd_urg: u32,

    init_win_fwd: Option<u32>,
    init_win_bwd: Option<u32>,
    saw_syn: bool,
    saw_synack: bool,
    saw_init_ack: bool,
    syn_ts: Option<i64>,
    synack_ts: Option<i64>,
    fin_fwd: bool,
    fin_bwd: bool,
    rst_seen: bool,

    ai: ActiveIdle,
    pub enrich: FlowEnrich,
}

impl FlowState {
    fn new(ev: &FlowEvent, active_threshold: f64) -> FlowState {
        FlowState {
            orig_src: ev.src_ip,
            orig_dst: ev.dst_ip,
            orig_sport: ev.src_port,
            orig_dport: ev.dst_port,
            proto: ev.proto,
            initiator_is_a: ev.src_is_a,
            vlan_id: ev.vlan_id,
            tunneled: ev.tunneled,
            first_ts: ev.ts_ns,
            last_ts: ev.ts_ns,
            started: false,
            fwd_pkts: 0,
            bwd_pkts: 0,
            fwd_bytes: 0,
            bwd_bytes: 0,
            fwd_payload: 0,
            bwd_payload: 0,
            fwd_header: 0,
            bwd_header: 0,
            fwd_pwp: 0,
            bwd_pwp: 0,
            len_all: Welford::default(),
            len_fwd: Welford::default(),
            len_bwd: Welford::default(),
            fwd_seg_min: None,
            iat_flow: Welford::default(),
            iat_fwd: Welford::default(),
            iat_bwd: Welford::default(),
            fwd_iat_total: 0.0,
            bwd_iat_total: 0.0,
            last_ts_fwd: None,
            last_ts_bwd: None,
            syn: 0,
            fin: 0,
            rst: 0,
            psh: 0,
            ack: 0,
            urg: 0,
            ece: 0,
            cwr: 0,
            fwd_psh: 0,
            bwd_psh: 0,
            fwd_urg: 0,
            bwd_urg: 0,
            init_win_fwd: None,
            init_win_bwd: None,
            saw_syn: false,
            saw_synack: false,
            saw_init_ack: false,
            syn_ts: None,
            synack_ts: None,
            fin_fwd: false,
            fin_bwd: false,
            rst_seen: false,
            ai: ActiveIdle::new(active_threshold),
            enrich: FlowEnrich::default(),
        }
    }

    fn account(&mut self, ev: &FlowEvent) {
        let ts = ev.ts_ns;
        if self.started {
            self.iat_flow.push((ts - self.last_ts) as f64 / 1e9);
        }
        self.started = true;
        self.last_ts = ts;
        self.ai.observe(ts);
        let wire = ev.wire_len as f64;
        self.len_all.push(wire);

        let fwd = ev.src_is_a == self.initiator_is_a;
        if fwd {
            self.fwd_pkts += 1;
            self.fwd_bytes += ev.wire_len as u64;
            self.fwd_payload += ev.payload_len as u64;
            self.fwd_header += ev.header_len as u64;
            if ev.payload_len > 0 {
                self.fwd_pwp += 1;
            }
            self.len_fwd.push(wire);
            self.fwd_seg_min = Some(self.fwd_seg_min.map_or(ev.payload_len, |m| m.min(ev.payload_len)));
            if let Some(lt) = self.last_ts_fwd {
                let d = (ts - lt) as f64 / 1e9;
                self.iat_fwd.push(d);
                self.fwd_iat_total += d;
            }
            self.last_ts_fwd = Some(ts);
            if self.init_win_fwd.is_none() {
                self.init_win_fwd = ev.tcp_window.map(|w| w as u32);
            }
        } else {
            self.bwd_pkts += 1;
            self.bwd_bytes += ev.wire_len as u64;
            self.bwd_payload += ev.payload_len as u64;
            self.bwd_header += ev.header_len as u64;
            if ev.payload_len > 0 {
                self.bwd_pwp += 1;
            }
            self.len_bwd.push(wire);
            if let Some(lt) = self.last_ts_bwd {
                let d = (ts - lt) as f64 / 1e9;
                self.iat_bwd.push(d);
                self.bwd_iat_total += d;
            }
            self.last_ts_bwd = Some(ts);
            if self.init_win_bwd.is_none() {
                self.init_win_bwd = ev.tcp_window.map(|w| w as u32);
            }
        }

        if let Some(fl) = ev.tcp_flags {
            let f = fl as u8;
            if f & 0x01 != 0 {
                self.fin += 1;
                if fwd {
                    self.fin_fwd = true;
                } else {
                    self.fin_bwd = true;
                }
            }
            if f & 0x02 != 0 {
                self.syn += 1;
            }
            if f & 0x04 != 0 {
                self.rst += 1;
                self.rst_seen = true;
            }
            if f & 0x08 != 0 {
                self.psh += 1;
                if fwd {
                    self.fwd_psh += 1;
                } else {
                    self.bwd_psh += 1;
                }
            }
            if f & 0x10 != 0 {
                self.ack += 1;
            }
            if f & 0x20 != 0 {
                self.urg += 1;
                if fwd {
                    self.fwd_urg += 1;
                } else {
                    self.bwd_urg += 1;
                }
            }
            if f & 0x40 != 0 {
                self.ece += 1;
            }
            if f & 0x80 != 0 {
                self.cwr += 1;
            }

            let is_syn = f & 0x02 != 0;
            let is_ack = f & 0x10 != 0;
            if is_syn && !is_ack {
                self.saw_syn = true;
                if self.syn_ts.is_none() {
                    self.syn_ts = Some(ts);
                }
            } else if is_syn && is_ack {
                self.saw_synack = true;
                if self.synack_ts.is_none() {
                    self.synack_ts = Some(ts);
                }
            } else if is_ack && fwd && self.saw_synack {
                self.saw_init_ack = true;
            }
        }
    }

    fn terminal(&self) -> bool {
        self.proto == TCP && (self.rst_seen || (self.fin_fwd && self.fin_bwd))
    }

    fn finalize(mut self, flow_id: u64, key: &FlowKey, reason: EndReason) -> FlowRow {
        self.ai.finish();
        let total_pkts = self.fwd_pkts + self.bwd_pkts;
        let total_bytes = self.fwd_bytes + self.bwd_bytes;
        let duration_s = (self.last_ts - self.first_ts) as f64 / 1e9;
        let rate = |x: f64| if duration_s > 0.0 { x / duration_s } else { 0.0 };

        let reason = if self.rst_seen {
            EndReason::Rst
        } else if self.fin_fwd && self.fin_bwd {
            EndReason::Fin
        } else {
            reason
        };

        let handshake_complete = self.saw_syn && self.saw_synack && self.saw_init_ack;
        let syn_synack_rtt = match (self.syn_ts, self.synack_ts) {
            (Some(s), Some(sa)) if sa >= s => Some((sa - s) as f64 / 1e9),
            _ => None,
        };

        let e = &self.enrich;
        let join_set = |s: &BTreeSet<&'static str>| {
            if s.is_empty() {
                None
            } else {
                Some(s.iter().cloned().collect::<Vec<_>>().join(","))
            }
        };
        let join_methods = |s: &BTreeSet<String>| {
            if s.is_empty() {
                None
            } else {
                Some(s.iter().cloned().collect::<Vec<_>>().join(","))
            }
        };
        let dns_qnames = if e.dns_qnames.is_empty() {
            None
        } else {
            Some(e.dns_qnames.iter().take(10).cloned().collect::<Vec<_>>().join(";"))
        };
        let http_hosts = if e.http_hosts.is_empty() {
            None
        } else {
            Some(e.http_hosts.iter().take(5).cloned().collect::<Vec<_>>().join(";"))
        };

        FlowRow {
            flow_id,
            src_ip: self.orig_src,
            dst_ip: self.orig_dst,
            src_port: self.orig_sport,
            dst_port: self.orig_dport,
            proto: key.proto,
            proto_name: proto_name(key.proto),
            vlan_id: self.vlan_id,
            tunneled: self.tunneled,
            first_ts: self.first_ts,
            last_ts: self.last_ts,
            duration_s,
            end_reason: reason.as_str(),

            fwd_pkts: self.fwd_pkts,
            bwd_pkts: self.bwd_pkts,
            fwd_bytes: self.fwd_bytes,
            bwd_bytes: self.bwd_bytes,
            fwd_payload_bytes: self.fwd_payload,
            bwd_payload_bytes: self.bwd_payload,
            fwd_header_bytes: self.fwd_header,
            bwd_header_bytes: self.bwd_header,
            fwd_pkts_with_payload: self.fwd_pwp,
            bwd_pkts_with_payload: self.bwd_pwp,

            pkt_len_min: self.len_all.min_opt().map(|v| v as u32),
            pkt_len_max: self.len_all.max_opt().map(|v| v as u32),
            pkt_len_mean: self.len_all.mean_opt(),
            pkt_len_std: self.len_all.std_opt(),
            fwd_pkt_len_min: self.len_fwd.min_opt().map(|v| v as u32),
            fwd_pkt_len_max: self.len_fwd.max_opt().map(|v| v as u32),
            fwd_pkt_len_mean: self.len_fwd.mean_opt(),
            fwd_pkt_len_std: self.len_fwd.std_opt(),
            bwd_pkt_len_min: self.len_bwd.min_opt().map(|v| v as u32),
            bwd_pkt_len_max: self.len_bwd.max_opt().map(|v| v as u32),
            bwd_pkt_len_mean: self.len_bwd.mean_opt(),
            bwd_pkt_len_std: self.len_bwd.std_opt(),
            fwd_seg_size_min: self.fwd_seg_min,
            fwd_seg_size_avg: if self.fwd_pkts > 0 {
                Some(self.fwd_payload as f64 / self.fwd_pkts as f64)
            } else {
                None
            },
            bwd_seg_size_avg: if self.bwd_pkts > 0 {
                Some(self.bwd_payload as f64 / self.bwd_pkts as f64)
            } else {
                None
            },

            flow_iat_min: self.iat_flow.min_opt(),
            flow_iat_max: self.iat_flow.max_opt(),
            flow_iat_mean: self.iat_flow.mean_opt(),
            flow_iat_std: self.iat_flow.std_opt(),
            fwd_iat_total: self.fwd_iat_total,
            fwd_iat_min: self.iat_fwd.min_opt(),
            fwd_iat_max: self.iat_fwd.max_opt(),
            fwd_iat_mean: self.iat_fwd.mean_opt(),
            fwd_iat_std: self.iat_fwd.std_opt(),
            bwd_iat_total: self.bwd_iat_total,
            bwd_iat_min: self.iat_bwd.min_opt(),
            bwd_iat_max: self.iat_bwd.max_opt(),
            bwd_iat_mean: self.iat_bwd.mean_opt(),
            bwd_iat_std: self.iat_bwd.std_opt(),

            syn_count: self.syn,
            fin_count: self.fin,
            rst_count: self.rst,
            psh_count: self.psh,
            ack_count: self.ack,
            urg_count: self.urg,
            ece_count: self.ece,
            cwr_count: self.cwr,
            fwd_psh_count: self.fwd_psh,
            bwd_psh_count: self.bwd_psh,
            fwd_urg_count: self.fwd_urg,
            bwd_urg_count: self.bwd_urg,

            flow_pkts_per_s: rate(total_pkts as f64),
            flow_bytes_per_s: rate(total_bytes as f64),
            fwd_pkts_per_s: rate(self.fwd_pkts as f64),
            bwd_pkts_per_s: rate(self.bwd_pkts as f64),
            down_up_ratio: if self.fwd_bytes > 0 {
                self.bwd_bytes as f64 / self.fwd_bytes as f64
            } else {
                0.0
            },

            init_win_fwd: self.init_win_fwd,
            init_win_bwd: self.init_win_bwd,
            tcp_handshake_complete: handshake_complete,
            syn_synack_rtt_s: syn_synack_rtt,

            active_min: self.ai.active.min_opt(),
            active_max: self.ai.active.max_opt(),
            active_mean: self.ai.active.mean_opt(),
            active_std: self.ai.active.std_opt(),
            idle_min: self.ai.idle.min_opt(),
            idle_max: self.ai.idle.max_opt(),
            idle_mean: self.ai.idle.mean_opt(),
            idle_std: self.ai.idle.std_opt(),
            active_count: self.ai.active_count(),

            app_protos: join_set(&e.app_protos),
            dns_qnames,
            dns_qname_count: e.dns_qnames.len() as u32,
            tls_sni: e.tls_sni.clone(),
            tls_version: e.tls_version,
            ja3: e.ja3.clone(),
            ja3s: e.ja3s.clone(),
            ja4: e.ja4.clone(),
            http_hosts,
            http_user_agent: e.http_user_agent.clone(),
            http_methods: join_methods(&e.http_methods),
            client_banner: e.client_banner.clone(),
            server_banner: e.server_banner.clone(),
        }
    }
}

/// The flow engine: consumes ordered flow events and emits closed flow rows.
pub struct FlowEngine {
    flows: HashMap<FlowKey, FlowState>,
    active_threshold: f64,
    idle_timeout_ns: i64,
    max_flows: usize,
    max_seen_ts: i64,
    last_sweep_ts: i64,
    next_id: u64,
    pub closed: Vec<FlowRow>,
}

impl FlowEngine {
    pub fn new(idle_timeout: f64, active_threshold: f64, max_flows: usize) -> FlowEngine {
        FlowEngine {
            flows: HashMap::new(),
            active_threshold,
            idle_timeout_ns: (idle_timeout * 1e9) as i64,
            max_flows: max_flows.max(1),
            max_seen_ts: i64::MIN,
            last_sweep_ts: i64::MIN,
            next_id: 0,
            closed: Vec::new(),
        }
    }

    pub fn on_event(&mut self, ev: &FlowEvent) {
        if ev.ts_ns > self.max_seen_ts {
            self.max_seen_ts = ev.ts_ns;
        }

        // If the existing flow for this key is already terminated or has been
        // idle past the timeout, close it first so this packet begins a new flow.
        let split = matches!(
            self.flows.get(&ev.key),
            Some(st) if st.terminal() || (ev.ts_ns - st.last_ts) > self.idle_timeout_ns
        );
        if split {
            if let Some(st) = self.flows.remove(&ev.key) {
                let id = self.next_id;
                self.next_id += 1;
                self.closed.push(st.finalize(id, &ev.key, EndReason::Idle));
            }
        }

        let st = self
            .flows
            .entry(ev.key)
            .or_insert_with(|| FlowState::new(ev, self.active_threshold));
        st.account(ev);

        if self.max_seen_ts - self.last_sweep_ts >= SWEEP_INTERVAL_NS {
            self.sweep();
        }
        if self.flows.len() > self.max_flows {
            self.evict_oldest();
        }
    }

    fn sweep(&mut self) {
        self.last_sweep_ts = self.max_seen_ts;
        let idle = self.idle_timeout_ns;
        let now = self.max_seen_ts;
        let to_close: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, st)| st.terminal() || (now - st.last_ts) > idle)
            .map(|(k, _)| *k)
            .collect();
        for k in to_close {
            if let Some(st) = self.flows.remove(&k) {
                let reason = if st.terminal() {
                    EndReason::Fin
                } else {
                    EndReason::Idle
                };
                let id = self.next_id;
                self.next_id += 1;
                self.closed.push(st.finalize(id, &k, reason));
            }
        }
    }

    fn evict_oldest(&mut self) {
        // Force-evict the flow with the smallest last_ts to bound memory.
        if let Some((&k, _)) = self.flows.iter().min_by_key(|(_, st)| st.last_ts) {
            if let Some(st) = self.flows.remove(&k) {
                let id = self.next_id;
                self.next_id += 1;
                self.closed.push(st.finalize(id, &k, EndReason::Idle));
            }
        }
    }

    /// Access the state of an in-progress flow (used by app enrichment in M5).
    pub fn state_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEnrich> {
        self.flows.get_mut(key).map(|s| &mut s.enrich)
    }

    pub fn finish(&mut self) {
        let keys: Vec<FlowKey> = self.flows.keys().copied().collect();
        for k in keys {
            if let Some(st) = self.flows.remove(&k) {
                let id = self.next_id;
                self.next_id += 1;
                self.closed.push(st.finalize(id, &k, EndReason::Eof));
            }
        }
    }
}

/// A finalized flow record ready for the `flows` table.
pub struct FlowRow {
    pub flow_id: u64,
    pub src_ip: IpRepr,
    pub dst_ip: IpRepr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub proto_name: &'static str,
    pub vlan_id: Option<u16>,
    pub tunneled: bool,
    pub first_ts: i64,
    pub last_ts: i64,
    pub duration_s: f64,
    pub end_reason: &'static str,

    pub fwd_pkts: u64,
    pub bwd_pkts: u64,
    pub fwd_bytes: u64,
    pub bwd_bytes: u64,
    pub fwd_payload_bytes: u64,
    pub bwd_payload_bytes: u64,
    pub fwd_header_bytes: u64,
    pub bwd_header_bytes: u64,
    pub fwd_pkts_with_payload: u64,
    pub bwd_pkts_with_payload: u64,

    pub pkt_len_min: Option<u32>,
    pub pkt_len_max: Option<u32>,
    pub pkt_len_mean: Option<f64>,
    pub pkt_len_std: Option<f64>,
    pub fwd_pkt_len_min: Option<u32>,
    pub fwd_pkt_len_max: Option<u32>,
    pub fwd_pkt_len_mean: Option<f64>,
    pub fwd_pkt_len_std: Option<f64>,
    pub bwd_pkt_len_min: Option<u32>,
    pub bwd_pkt_len_max: Option<u32>,
    pub bwd_pkt_len_mean: Option<f64>,
    pub bwd_pkt_len_std: Option<f64>,
    pub fwd_seg_size_min: Option<u32>,
    pub fwd_seg_size_avg: Option<f64>,
    pub bwd_seg_size_avg: Option<f64>,

    pub flow_iat_min: Option<f64>,
    pub flow_iat_max: Option<f64>,
    pub flow_iat_mean: Option<f64>,
    pub flow_iat_std: Option<f64>,
    pub fwd_iat_total: f64,
    pub fwd_iat_min: Option<f64>,
    pub fwd_iat_max: Option<f64>,
    pub fwd_iat_mean: Option<f64>,
    pub fwd_iat_std: Option<f64>,
    pub bwd_iat_total: f64,
    pub bwd_iat_min: Option<f64>,
    pub bwd_iat_max: Option<f64>,
    pub bwd_iat_mean: Option<f64>,
    pub bwd_iat_std: Option<f64>,

    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub psh_count: u32,
    pub ack_count: u32,
    pub urg_count: u32,
    pub ece_count: u32,
    pub cwr_count: u32,
    pub fwd_psh_count: u32,
    pub bwd_psh_count: u32,
    pub fwd_urg_count: u32,
    pub bwd_urg_count: u32,

    pub flow_pkts_per_s: f64,
    pub flow_bytes_per_s: f64,
    pub fwd_pkts_per_s: f64,
    pub bwd_pkts_per_s: f64,
    pub down_up_ratio: f64,

    pub init_win_fwd: Option<u32>,
    pub init_win_bwd: Option<u32>,
    pub tcp_handshake_complete: bool,
    pub syn_synack_rtt_s: Option<f64>,

    pub active_min: Option<f64>,
    pub active_max: Option<f64>,
    pub active_mean: Option<f64>,
    pub active_std: Option<f64>,
    pub idle_min: Option<f64>,
    pub idle_max: Option<f64>,
    pub idle_mean: Option<f64>,
    pub idle_std: Option<f64>,
    pub active_count: u32,

    pub app_protos: Option<String>,
    pub dns_qnames: Option<String>,
    pub dns_qname_count: u32,
    pub tls_sni: Option<String>,
    pub tls_version: Option<u16>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub ja4: Option<String>,
    pub http_hosts: Option<String>,
    pub http_user_agent: Option<String>,
    pub http_methods: Option<String>,
    pub client_banner: Option<String>,
    pub server_banner: Option<String>,
}
