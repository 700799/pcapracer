//! Application-layer parsing.
//!
//! UDP application parsing is stateless and runs in the packet path. TCP
//! application parsing (M5) is driven by the flow engine over reassembled
//! payloads.

pub mod banner;
pub mod dhcp;
pub mod dns;
pub mod fingerprint;
pub mod http;
pub mod ntp;
pub mod quic;
pub mod tls;

use crate::decode::PacketMeta;
use crate::schema::dns::DnsRow;
use crate::util::IpRepr;

/// Per-message context for building application-table rows (the sender's
/// endpoint is `src`).
#[derive(Clone, Copy, Debug)]
pub struct AppCtx {
    pub ts_ns: i64,
    pub src_ip: IpRepr,
    pub dst_ip: IpRepr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Output of UDP application parsing for one datagram.
#[derive(Default)]
pub struct UdpAppOut {
    pub dns: Option<DnsRow>,
}

/// Detect and parse the application protocol of a UDP datagram, filling inline
/// `meta` fields and returning any per-table rows.
pub fn parse_udp(payload: &[u8], meta: &mut PacketMeta, ts_ns: i64, want_dns: bool) -> UdpAppOut {
    let mut out = UdpAppOut::default();
    if payload.is_empty() {
        return out;
    }
    let sport = meta.src_port.unwrap_or(0);
    let dport = meta.dst_port.unwrap_or(0);

    if let Some(service) = dns_service(sport, dport) {
        if let Some(row) = dns::parse(payload, service, meta, ts_ns) {
            if want_dns {
                out.dns = Some(row);
            }
            return out;
        }
    }

    let has = |port| sport == port || dport == port;
    if has(67) || has(68) {
        dhcp::detect(payload, meta);
    } else if has(123) {
        ntp::detect(payload, meta);
    } else if has(443) || has(80) {
        quic::detect(payload, meta);
    }
    out
}

fn dns_service(sport: u16, dport: u16) -> Option<&'static str> {
    let has = |port| sport == port || dport == port;
    if has(53) {
        Some("dns")
    } else if has(5353) {
        Some("mdns")
    } else if has(5355) {
        Some("llmnr")
    } else if has(137) {
        Some("nbns")
    } else {
        None
    }
}
