//! Flow key canonicalization and per-packet flow events.

use crate::decode::{PacketMeta, IP_ICMP, IP_ICMPV6, IP_TCP, IP_UDP};
use crate::reader::RecMeta;
use crate::util::IpRepr;

/// Canonical bidirectional flow key. Endpoint `a` is the lexicographically
/// smaller `(ip, port)`; direction is recovered per packet via `src_is_a`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub a: [u8; 16],
    pub b: [u8; 16],
    pub a_port: u16,
    pub b_port: u16,
    pub proto: u8,
    pub v6: bool,
}

fn ip_bytes(ip: IpRepr) -> ([u8; 16], bool) {
    match ip {
        IpRepr::V4(o) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&o);
            (b, false)
        }
        IpRepr::V6(o) => (o, true),
    }
}

/// A single packet's contribution to its flow, in capture order.
#[derive(Clone, Debug)]
pub struct FlowEvent {
    pub ts_ns: i64,
    pub key: FlowKey,
    pub src_is_a: bool,
    pub src_ip: IpRepr,
    pub dst_ip: IpRepr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub wire_len: u32,
    pub header_len: u32,
    pub payload_len: u32,
    pub tcp_flags: Option<u16>,
    pub tcp_window: Option<u16>,
    pub tcp_seq: Option<u32>,
    pub vlan_id: Option<u16>,
    pub tunneled: bool,
    /// Application payload region within the batch frame, for TCP reassembly (M5).
    pub payload_ref: Option<(u64, u32)>,
}

impl FlowEvent {
    /// Build a flow event from a decoded packet, or None if it has no IP 5-tuple.
    pub fn from_packet(rec: &RecMeta, m: &PacketMeta, frame_off: u64) -> Option<FlowEvent> {
        let (src_ip, dst_ip) = match (m.src_ip, m.dst_ip) {
            (Some(s), Some(d)) => (s, d),
            _ => return None,
        };
        let proto = m.ip_proto?;

        // Effective ports: real ports for TCP/UDP; ICMP echo id pairs req/reply.
        let (sport, dport) = match proto {
            IP_TCP | IP_UDP => (m.src_port.unwrap_or(0), m.dst_port.unwrap_or(0)),
            IP_ICMP | IP_ICMPV6 => {
                let id = m.icmp_echo_id.unwrap_or(0);
                (id, id)
            }
            _ => (0, 0),
        };

        let (sb, v6a) = ip_bytes(src_ip);
        let (db, _v6b) = ip_bytes(dst_ip);

        // Canonical ordering by (ip, port).
        let src_is_a = (sb, sport) <= (db, dport);
        let (a, a_port, b, b_port) = if src_is_a {
            (sb, sport, db, dport)
        } else {
            (db, dport, sb, sport)
        };
        let key = FlowKey {
            a,
            b,
            a_port,
            b_port,
            proto,
            v6: v6a,
        };

        let wire_len = if rec.wirelen > 0 {
            rec.wirelen
        } else {
            rec.caplen
        };

        let l3 = match m.ip_version {
            Some(4) => m.ipv4_ihl.map(|i| i as u32 * 4).unwrap_or(20),
            Some(6) => 40,
            _ => 0,
        };
        let l4 = match proto {
            IP_TCP => m.tcp_header_len.map(|h| h as u32).unwrap_or(20),
            IP_UDP => 8,
            _ => 0,
        };
        let header_len = l3 + l4;
        let payload_len = m.payload_len.unwrap_or(0);

        let payload_ref = m.l4_payload.and_then(|(off, len)| {
            if len > 0 {
                Some((frame_off + off as u64, len as u32))
            } else {
                None
            }
        });

        Some(FlowEvent {
            ts_ns: rec.ts_ns,
            key,
            src_is_a,
            src_ip,
            dst_ip,
            src_port: sport,
            dst_port: dport,
            proto,
            wire_len,
            header_len,
            payload_len,
            tcp_flags: m.tcp_flags,
            tcp_window: m.tcp_window,
            tcp_seq: m.tcp_seq,
            vlan_id: m.vlan1_id,
            tunneled: m.tunnel_depth > 0,
            payload_ref,
        })
    }
}

/// Human-readable protocol name for the `proto_name` column.
pub fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        2 => "igmp",
        6 => "tcp",
        17 => "udp",
        41 => "ipv6",
        47 => "gre",
        50 => "esp",
        58 => "icmpv6",
        89 => "ospf",
        132 => "sctp",
        _ => "other",
    }
}
