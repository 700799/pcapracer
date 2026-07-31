//! Tunnel decapsulation: IP-in-IP / 6in4, GRE, VXLAN.
//!
//! The innermost IP layer wins the 5-tuple; the outermost IP pair is preserved
//! in `outer_src_ip` / `outer_dst_ip`. Recursion is capped by [`MAX_TUNNEL_DEPTH`].

use super::*;
use crate::config::Config;

/// Record entry into a tunnel layer. Returns false if the depth cap is hit.
fn enter(meta: &mut PacketMeta, label: &str) -> bool {
    if meta.tunnel_depth >= MAX_TUNNEL_DEPTH {
        return false;
    }
    if meta.tunnel_depth == 0 {
        meta.outer_src_ip = meta.src_ip;
        meta.outer_dst_ip = meta.dst_ip;
        meta.tunnel_stack = Some(String::new());
    }
    if let Some(s) = meta.tunnel_stack.as_mut() {
        if !s.is_empty() {
            s.push('>');
        }
        s.push_str(label);
    }
    meta.tunnel_depth += 1;
    true
}

/// IP-in-IP (proto 4) or 6in4 (proto 41). `inner_ver` is 4 or 6.
pub fn decode_ipip(frame: &[u8], start: usize, cfg: &Config, meta: &mut PacketMeta, inner_ver: u8) {
    let label = if inner_ver == 6 { "6in4" } else { "ipip" };
    if !enter(meta, label) {
        return;
    }
    if inner_ver == 6 {
        l3::decode_ipv6(frame, start, cfg, meta);
    } else {
        l3::decode_ipv4(frame, start, cfg, meta);
    }
}

/// GRE (proto 47): base header + optional checksum/key/sequence fields.
pub fn decode_gre(frame: &[u8], start: usize, end: usize, cfg: &Config, meta: &mut PacketMeta) {
    let g = match frame.get(start..end) {
        Some(s) if s.len() >= 4 => s,
        _ => return,
    };
    let flags = g[0];
    let has_csum = flags & 0x80 != 0;
    let has_key = flags & 0x20 != 0;
    let has_seq = flags & 0x10 != 0;
    let proto = u16::from_be_bytes([g[2], g[3]]);
    meta.gre_protocol = Some(proto);

    let mut hdr = 4usize;
    if has_csum {
        hdr += 4;
    }
    if has_key {
        hdr += 4;
    }
    if has_seq {
        hdr += 4;
    }
    let inner = start + hdr;
    if inner > end {
        return;
    }
    if !enter(meta, "gre") {
        return;
    }
    match proto {
        ETH_IPV4 => l3::decode_ipv4(frame, inner, cfg, meta),
        ETH_IPV6 => l3::decode_ipv6(frame, inner, cfg, meta),
        0x6558 => l2::decode_ethernet(frame, inner, cfg, meta), // transparent ethernet bridging
        _ => {}
    }
}

/// VXLAN (UDP/4789): 8-byte header then an inner Ethernet frame.
pub fn decode_vxlan(frame: &[u8], start: usize, end: usize, cfg: &Config, meta: &mut PacketMeta) {
    let h = match frame.get(start..end) {
        Some(s) if s.len() >= 8 => s,
        _ => return,
    };
    // flags byte0, VNI in bytes 4..7 (24 bits)
    let vni = ((h[4] as u32) << 16) | ((h[5] as u32) << 8) | h[6] as u32;
    if !enter(meta, "vxlan") {
        return;
    }
    meta.vxlan_vni = Some(vni);
    l2::decode_ethernet(frame, start + 8, cfg, meta);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Compression, Config, TableSet};
    use crate::decode::decode_packet;
    use crate::util::IpRepr;
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
            app_buffer_budget: 1 << 26,
            hex_prefix_len: 0,
            threads: 1,
            batch_size: 128,
        }
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut v = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            proto,
            0,
            0,
        ];
        v.extend_from_slice(&src);
        v.extend_from_slice(&dst);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn ipip_inner_wins() {
        // outer ipv4 (proto 4) carrying inner ipv4 udp
        let udp = [0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0];
        let inner = ipv4([10, 0, 0, 1], [10, 0, 0, 2], IP_UDP, &udp);
        let outer = ipv4([1, 1, 1, 1], [2, 2, 2, 2], IP_IPIP, &inner);
        // wrap in ethernet
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend_from_slice(&outer);
        let mut m = PacketMeta::default();
        decode_packet(&frame, LT_ETHERNET, &cfg(), &mut m);
        assert_eq!(m.src_ip, Some(IpRepr::V4([10, 0, 0, 1])));
        assert_eq!(m.outer_src_ip, Some(IpRepr::V4([1, 1, 1, 1])));
        assert_eq!(m.tunnel_depth, 1);
        assert_eq!(m.dst_port, Some(53));
    }
}
