//! Link-layer decoding and dispatch to L3.

use super::*;
use crate::config::Config;
use crate::util::be_u16;

/// Entry point: dispatch by libpcap linktype.
pub fn decode(frame: &[u8], linktype: u16, cfg: &Config, meta: &mut PacketMeta) {
    match linktype {
        LT_ETHERNET => decode_ethernet(frame, 0, cfg, meta),
        LT_LINUX_SLL => decode_sll(frame, cfg, meta),
        LT_LINUX_SLL2 => decode_sll2(frame, cfg, meta),
        LT_RAW | LT_IPV4 | LT_IPV6 => decode_raw_ip(frame, cfg, meta),
        LT_NULL | LT_LOOP => decode_null(frame, linktype, cfg, meta),
        _ => {}
    }
}

/// Ethernet II with optional 802.1Q / QinQ VLAN tags and MPLS, starting at
/// absolute offset `base` within `frame` (base is non-zero for VXLAN inner frames).
pub(crate) fn decode_ethernet(frame: &[u8], base: usize, cfg: &Config, meta: &mut PacketMeta) {
    let hdr = match frame.get(base..base + 14) {
        Some(h) => h,
        None => return,
    };
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&hdr[0..6]);
    src.copy_from_slice(&hdr[6..12]);
    meta.eth_dst = Some(dst);
    meta.eth_src = Some(src);

    let mut ethertype = be_u16(frame, base + 12).unwrap_or(0);
    let mut off = base + 14;

    // VLAN tags (802.1Q / QinQ), up to two.
    let mut tag = 0u8;
    while matches!(ethertype, ETH_VLAN | ETH_QINQ | ETH_QINQ_LEGACY) && tag < 2 {
        let tci = match be_u16(frame, off) {
            Some(v) => v,
            None => return,
        };
        let vid = tci & 0x0fff;
        let pcp = (tci >> 13) as u8 & 0x07;
        if tag == 0 {
            meta.vlan1_id = Some(vid);
            meta.vlan1_pcp = Some(pcp);
        } else {
            meta.vlan2_id = Some(vid);
        }
        ethertype = match be_u16(frame, off + 2) {
            Some(v) => v,
            None => return,
        };
        off += 4;
        tag += 1;
    }

    meta.eth_type = Some(ethertype);
    dispatch_ethertype(frame, off, ethertype, cfg, meta);
}

/// Dispatch on an EtherType at `off` within `frame`.
pub(crate) fn dispatch_ethertype(
    frame: &[u8],
    off: usize,
    ethertype: u16,
    cfg: &Config,
    meta: &mut PacketMeta,
) {
    let rest = match frame.get(off..) {
        Some(r) => r,
        None => return,
    };
    match ethertype {
        ETH_IPV4 => l3::decode_ipv4(frame, off, cfg, meta),
        ETH_IPV6 => l3::decode_ipv6(frame, off, cfg, meta),
        ETH_ARP => decode_arp(rest, meta),
        ETH_MPLS_UCAST | ETH_MPLS_MCAST => decode_mpls(frame, off, cfg, meta),
        _ => {}
    }
}

/// MPLS label stack; unwrap to guess the payload (IPv4/IPv6).
fn decode_mpls(frame: &[u8], mut off: usize, cfg: &Config, meta: &mut PacketMeta) {
    let mut depth = 0u8;
    loop {
        let w = match crate::util::be_u32(frame, off) {
            Some(v) => v,
            None => return,
        };
        let label = w >> 12;
        let bottom = (w >> 8) & 0x1 == 1;
        if depth == 0 {
            meta.mpls_top_label = Some(label);
        }
        depth += 1;
        off += 4;
        if bottom || depth >= 8 {
            break;
        }
    }
    meta.mpls_depth = Some(depth);
    // After the label stack, guess IP version from the first nibble.
    match frame.get(off).map(|b| b >> 4) {
        Some(4) => l3::decode_ipv4(frame, off, cfg, meta),
        Some(6) => l3::decode_ipv6(frame, off, cfg, meta),
        _ => {}
    }
}

/// ARP (over Ethernet/IPv4 shapes).
fn decode_arp(p: &[u8], meta: &mut PacketMeta) {
    if p.len() < 28 {
        return;
    }
    let hw_type = u16::from_be_bytes([p[0], p[1]]);
    let hlen = p[4];
    let plen = p[5];
    let op = u16::from_be_bytes([p[6], p[7]]);
    meta.arp_hw_type = Some(hw_type);
    meta.arp_op = Some(op);
    // Only decode the common Ethernet/IPv4 address shape.
    if hlen == 6 && plen == 4 {
        let mut smac = [0u8; 6];
        let mut sip = [0u8; 4];
        let mut tmac = [0u8; 6];
        let mut tip = [0u8; 4];
        smac.copy_from_slice(&p[8..14]);
        sip.copy_from_slice(&p[14..18]);
        tmac.copy_from_slice(&p[18..24]);
        tip.copy_from_slice(&p[24..28]);
        meta.arp_sender_mac = Some(smac);
        meta.arp_sender_ip = Some(sip);
        meta.arp_target_mac = Some(tmac);
        meta.arp_target_ip = Some(tip);
    }
}

/// Linux "cooked" capture v1 (SLL).
fn decode_sll(frame: &[u8], cfg: &Config, meta: &mut PacketMeta) {
    if frame.len() < 16 {
        return;
    }
    // SLL: [pkttype:2][arphrd:2][lladdrlen:2][lladdr:8][protocol:2]
    let proto = be_u16(frame, 14).unwrap_or(0);
    dispatch_ethertype(frame, 16, proto, cfg, meta);
}

/// Linux "cooked" capture v2 (SLL2).
fn decode_sll2(frame: &[u8], cfg: &Config, meta: &mut PacketMeta) {
    if frame.len() < 20 {
        return;
    }
    // SLL2: [protocol:2][reserved:2][ifindex:4][arphrd:2][pkttype:1][lladdrlen:1][lladdr:8]
    let proto = be_u16(frame, 0).unwrap_or(0);
    dispatch_ethertype(frame, 20, proto, cfg, meta);
}

/// Raw IP linktypes (no link layer).
fn decode_raw_ip(frame: &[u8], cfg: &Config, meta: &mut PacketMeta) {
    match frame.first().map(|b| b >> 4) {
        Some(4) => l3::decode_ipv4(frame, 0, cfg, meta),
        Some(6) => l3::decode_ipv6(frame, 0, cfg, meta),
        _ => {}
    }
}

/// BSD loopback / DLT_NULL: 4-byte address-family header.
fn decode_null(frame: &[u8], linktype: u16, cfg: &Config, meta: &mut PacketMeta) {
    if frame.len() < 4 {
        return;
    }
    // Family is host-endian in the file; accept both byte orders.
    let le = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let fam = if le <= 30 { le } else { be };
    let _ = linktype;
    match fam {
        2 => l3::decode_ipv4(frame, 4, cfg, meta),
        24 | 28 | 30 => l3::decode_ipv6(frame, 4, cfg, meta),
        _ => match frame.get(4).map(|b| b >> 4) {
            Some(4) => l3::decode_ipv4(frame, 4, cfg, meta),
            Some(6) => l3::decode_ipv6(frame, 4, cfg, meta),
            _ => {}
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Compression, Config, TableSet};
    use std::path::PathBuf;

    fn cfg() -> Config {
        Config {
            input: PathBuf::new(),
            output_dir: PathBuf::new(),
            stem: String::new(),
            tables: TableSet {
                packets: true,
                flows: false,
                dns: false,
                http: false,
                tls: false,
            },
            compression: Compression::Snappy,
            idle_timeout: 120.0,
            active_threshold: 1.0,
            max_flows: 1000,
            app_buffer_bytes: 8192,
            hex_prefix_len: 0,
            threads: 1,
            batch_size: 128,
        }
    }

    #[test]
    fn eth_ipv4_udp() {
        // eth + ipv4 + udp
        let mut f = vec![
            0, 1, 2, 3, 4, 5, // dst mac
            6, 7, 8, 9, 10, 11, // src mac
            0x08, 0x00, // ipv4
        ];
        // ipv4 header (20 bytes), proto udp(17)
        let ip = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 17, 0x00, 0x00, 192, 168, 0, 1,
            192, 168, 0, 2,
        ];
        f.extend_from_slice(&ip);
        // udp header 8 bytes: sport 1234 dport 53 len 8 csum 0
        f.extend_from_slice(&[0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
        let mut m = PacketMeta::default();
        decode(&f, LT_ETHERNET, &cfg(), &mut m);
        assert_eq!(m.eth_type, Some(ETH_IPV4));
        assert_eq!(m.ip_proto, Some(IP_UDP));
        assert_eq!(m.src_port, Some(1234));
        assert_eq!(m.dst_port, Some(53));
    }

    #[test]
    fn vlan_tagged() {
        let mut f = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        f.extend_from_slice(&[0x81, 0x00]); // vlan
        f.extend_from_slice(&[0x00, 0x64]); // vid 100
        f.extend_from_slice(&[0x08, 0x00]); // ipv4
        let ip = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, IP_TCP, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        f.extend_from_slice(&ip);
        let mut m = PacketMeta::default();
        decode(&f, LT_ETHERNET, &cfg(), &mut m);
        assert_eq!(m.vlan1_id, Some(100));
        assert_eq!(m.eth_type, Some(ETH_IPV4));
        assert_eq!(m.ip_proto, Some(IP_TCP));
    }

    #[test]
    fn arp_request() {
        let mut f = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 6, 7, 8, 9, 10, 11, 0x08, 0x06,
        ];
        let arp = [
            0x00, 0x01, 0x08, 0x00, 6, 4, 0x00,
            0x01, // htype eth, ptype ipv4, hlen plen, op req
            6, 7, 8, 9, 10, 11, 192, 168, 0, 1, // sender
            0, 0, 0, 0, 0, 0, 192, 168, 0, 2, // target
        ];
        f.extend_from_slice(&arp);
        let mut m = PacketMeta::default();
        decode(&f, LT_ETHERNET, &cfg(), &mut m);
        assert_eq!(m.arp_op, Some(1));
        assert_eq!(m.arp_sender_ip, Some([192, 168, 0, 1]));
        assert_eq!(m.arp_target_ip, Some([192, 168, 0, 2]));
    }

    #[test]
    fn truncated_never_panics() {
        let cfg = cfg();
        for n in 0..40 {
            let f = vec![0x11u8; n];
            let mut m = PacketMeta::default();
            decode(&f, LT_ETHERNET, &cfg, &mut m);
        }
    }
}
