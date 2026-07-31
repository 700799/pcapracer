//! Layered packet decoder. Produces a [`PacketMeta`] from a raw frame.
//!
//! All parsing uses checked slicing (`get`) and never panics on malformed
//! input; unparsable layers simply leave their fields unset.

pub mod l2;
pub mod l3;
pub mod l4;
pub mod tunnel;

use crate::config::Config;
use crate::util::{shannon_entropy, write_hex, IpRepr};

// EtherTypes
pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_IPV6: u16 = 0x86DD;
pub const ETH_ARP: u16 = 0x0806;
pub const ETH_VLAN: u16 = 0x8100;
pub const ETH_QINQ: u16 = 0x88A8;
pub const ETH_QINQ_LEGACY: u16 = 0x9100;
pub const ETH_MPLS_UCAST: u16 = 0x8847;
pub const ETH_MPLS_MCAST: u16 = 0x8848;

// IP protocol numbers
pub const IP_ICMP: u8 = 1;
pub const IP_IGMP: u8 = 2;
pub const IP_IPIP: u8 = 4;
pub const IP_TCP: u8 = 6;
pub const IP_UDP: u8 = 17;
pub const IP_IPV6: u8 = 41;
pub const IP_GRE: u8 = 47;
pub const IP_ESP: u8 = 50;
pub const IP_ICMPV6: u8 = 58;
pub const IP_SCTP: u8 = 132;

// Link-layer types (libpcap LINKTYPE_*)
pub const LT_NULL: u16 = 0;
pub const LT_ETHERNET: u16 = 1;
pub const LT_RAW: u16 = 101;
pub const LT_LINUX_SLL: u16 = 113;
pub const LT_LINUX_SLL2: u16 = 276;
pub const LT_IPV4: u16 = 228;
pub const LT_IPV6: u16 = 229;
pub const LT_LOOP: u16 = 108;

pub const MAX_TUNNEL_DEPTH: u8 = 4;

/// Flat, reusable per-packet decode result mirroring the `packets` schema.
///
/// All application-layer fields are left `None` by the core decoder and filled
/// in later (workers for UDP apps, the flow engine for TCP apps).
#[derive(Default, Debug)]
pub struct PacketMeta {
    // L2
    pub eth_src: Option<[u8; 6]>,
    pub eth_dst: Option<[u8; 6]>,
    pub eth_type: Option<u16>,
    pub vlan1_id: Option<u16>,
    pub vlan1_pcp: Option<u8>,
    pub vlan2_id: Option<u16>,
    pub mpls_top_label: Option<u32>,
    pub mpls_depth: Option<u8>,

    // ARP
    pub arp_op: Option<u16>,
    pub arp_hw_type: Option<u16>,
    pub arp_sender_mac: Option<[u8; 6]>,
    pub arp_sender_ip: Option<[u8; 4]>,
    pub arp_target_mac: Option<[u8; 6]>,
    pub arp_target_ip: Option<[u8; 4]>,

    // Tunnel
    pub tunnel_depth: u8,
    pub tunnel_stack: Option<String>,
    pub vxlan_vni: Option<u32>,
    pub gre_protocol: Option<u16>,
    pub outer_src_ip: Option<IpRepr>,
    pub outer_dst_ip: Option<IpRepr>,

    // L3 (innermost)
    pub ip_version: Option<u8>,
    pub src_ip: Option<IpRepr>,
    pub dst_ip: Option<IpRepr>,
    pub ip_proto: Option<u8>,
    pub ip_ttl: Option<u8>,
    pub ip_dscp: Option<u8>,
    pub ip_ecn: Option<u8>,
    pub ip_len: Option<u32>,
    pub is_fragment: Option<bool>,
    pub ipv4_ihl: Option<u8>,
    pub ipv4_id: Option<u16>,
    pub ipv4_df: Option<bool>,
    pub ipv4_mf: Option<bool>,
    pub ipv4_frag_offset: Option<u16>,
    pub ipv4_checksum: Option<u16>,
    pub ipv4_options_len: Option<u8>,
    pub ipv6_flow_label: Option<u32>,
    pub ipv6_next_header: Option<u8>,
    pub ipv6_ext_headers: Option<String>,

    // ICMP
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmp_echo_id: Option<u16>,
    pub icmp_echo_seq: Option<u16>,
    pub icmp_mtu: Option<u16>,

    // L4
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,

    // TCP
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_header_len: Option<u8>,
    pub tcp_flags: Option<u16>,
    pub tcp_window: Option<u16>,
    pub tcp_checksum: Option<u16>,
    pub tcp_urgent_ptr: Option<u16>,
    pub tcp_mss: Option<u16>,
    pub tcp_wscale: Option<u8>,
    pub tcp_sack_permitted: Option<bool>,
    pub tcp_sack_count: Option<u8>,
    pub tcp_ts_val: Option<u32>,
    pub tcp_ts_ecr: Option<u32>,
    pub tcp_payload_len: Option<u32>,

    // UDP
    pub udp_len: Option<u16>,
    pub udp_checksum: Option<u16>,

    // Payload
    pub payload_len: Option<u32>,
    pub payload_entropy: Option<f32>,
    pub payload_printable_ratio: Option<f32>,
    pub payload_hex_prefix: Option<String>,
    /// (offset, len) of the transport payload within the frame slice.
    pub l4_payload: Option<(usize, usize)>,

    // Application (best-effort inline; authoritative data lives in per-app tables)
    pub app_proto: Option<&'static str>,
    pub dns_qname: Option<String>,
    pub dns_qtype: Option<u16>,
    pub dns_is_response: Option<bool>,
    pub tls_sni: Option<String>,
    pub tls_version: Option<u16>,
    pub tls_ja3: Option<String>,
    pub tls_ja4: Option<String>,
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_uri: Option<String>,
    pub http_status: Option<u16>,
    pub http_user_agent: Option<String>,
    pub quic_version: Option<u32>,
    pub quic_dcid: Option<String>,
    pub banner: Option<String>,
}

impl PacketMeta {
    #[inline]
    pub fn reset(&mut self) {
        *self = PacketMeta::default();
    }

    /// True if a routable L3 endpoint pair was decoded.
    pub fn has_ip(&self) -> bool {
        self.src_ip.is_some() && self.dst_ip.is_some()
    }
}

/// Decode a single frame into `meta`. Never panics.
pub fn decode_packet(frame: &[u8], linktype: u16, cfg: &Config, meta: &mut PacketMeta) {
    meta.reset();
    l2::decode(frame, linktype, cfg, meta);
}

/// Compute payload statistics for the transport payload region.
pub(crate) fn payload_stats(frame: &[u8], off: usize, len: usize, cfg: &Config, meta: &mut PacketMeta) {
    meta.l4_payload = Some((off, len));
    meta.payload_len = Some(len as u32);
    if let Some(p) = frame.get(off..off + len) {
        if !p.is_empty() {
            meta.payload_entropy = Some(shannon_entropy(p));
            meta.payload_printable_ratio = Some(crate::util::printable_ratio(p));
            if cfg.hex_prefix_len > 0 {
                let n = cfg.hex_prefix_len.min(p.len());
                let mut s = String::with_capacity(n * 2);
                write_hex(&mut s, &p[..n]);
                meta.payload_hex_prefix = Some(s);
            }
        }
    }
}
