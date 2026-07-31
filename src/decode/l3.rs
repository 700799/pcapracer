//! IPv4 / IPv6 decoding (innermost layer wins for the flow 5-tuple).

use super::*;
use crate::config::Config;
use crate::util::{be_u16, IpRepr};
use std::fmt::Write as _;

/// Decode an IPv4 header at `off`; then dispatch L4 or tunnel.
pub fn decode_ipv4(frame: &[u8], off: usize, cfg: &Config, meta: &mut PacketMeta) {
    let p = match frame.get(off..) {
        Some(p) if p.len() >= 20 => p,
        _ => return,
    };
    let ihl = (p[0] & 0x0f) as usize;
    let hdr_len = ihl * 4;
    if ihl < 5 || p.len() < hdr_len {
        return;
    }
    let total_len = u16::from_be_bytes([p[2], p[3]]);
    let flags_frag = u16::from_be_bytes([p[6], p[7]]);
    let df = flags_frag & 0x4000 != 0;
    let mf = flags_frag & 0x2000 != 0;
    let frag_off = flags_frag & 0x1fff;

    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&p[12..16]);
    dst.copy_from_slice(&p[16..20]);

    meta.ip_version = Some(4);
    meta.src_ip = Some(IpRepr::V4(src));
    meta.dst_ip = Some(IpRepr::V4(dst));
    let proto = p[9];
    meta.ip_proto = Some(proto);
    meta.ip_ttl = Some(p[8]);
    meta.ip_dscp = Some(p[1] >> 2);
    meta.ip_ecn = Some(p[1] & 0x03);
    meta.ip_len = Some(total_len as u32);
    meta.is_fragment = Some(mf || frag_off > 0);
    meta.ipv4_ihl = Some(ihl as u8);
    meta.ipv4_id = Some(u16::from_be_bytes([p[4], p[5]]));
    meta.ipv4_df = Some(df);
    meta.ipv4_mf = Some(mf);
    meta.ipv4_frag_offset = Some(frag_off);
    meta.ipv4_checksum = Some(u16::from_be_bytes([p[10], p[11]]));
    meta.ipv4_options_len = Some((hdr_len - 20) as u8);

    // Compute the L4 region bounded by total_length, but never beyond capture.
    let payload_start = off + hdr_len;
    let l4_end = {
        let by_total = off + total_len as usize;
        by_total.min(frame.len()).max(payload_start)
    };

    // Only descend into L4 for the first (or only) fragment.
    if frag_off == 0 {
        l4::dispatch(frame, payload_start, l4_end, proto, cfg, meta);
    }
}

/// Decode an IPv6 header (and extension chain) at `off`; then dispatch.
pub fn decode_ipv6(frame: &[u8], off: usize, cfg: &Config, meta: &mut PacketMeta) {
    let p = match frame.get(off..) {
        Some(p) if p.len() >= 40 => p,
        _ => return,
    };
    let b0 = p[0];
    let b1 = p[1];
    let traffic_class = ((b0 & 0x0f) << 4) | (b1 >> 4);
    let flow_label = ((b1 as u32 & 0x0f) << 16) | ((p[2] as u32) << 8) | p[3] as u32;
    let payload_len = u16::from_be_bytes([p[4], p[5]]);
    let mut next_header = p[6];

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&p[8..24]);
    dst.copy_from_slice(&p[24..40]);

    meta.ip_version = Some(6);
    meta.src_ip = Some(IpRepr::V6(src));
    meta.dst_ip = Some(IpRepr::V6(dst));
    meta.ip_ttl = Some(p[7]);
    meta.ip_dscp = Some(traffic_class >> 2);
    meta.ip_ecn = Some(traffic_class & 0x03);
    meta.ip_len = Some(payload_len as u32 + 40);
    meta.ipv6_flow_label = Some(flow_label);
    meta.ipv6_next_header = Some(next_header);

    // Walk the extension header chain (capped).
    let mut cur = off + 40;
    let mut ext_types = String::new();
    let mut is_frag = false;
    let mut hops = 0u8;
    loop {
        let is_ext = matches!(next_header, 0 | 43 | 44 | 60 | 51 | 135);
        if !is_ext || hops >= 8 {
            break;
        }
        let eh = match frame.get(cur..cur + 2) {
            Some(s) => s,
            None => break,
        };
        if !ext_types.is_empty() {
            ext_types.push(',');
        }
        let _ = write!(ext_types, "{next_header}");
        let this = next_header;
        next_header = eh[0];
        let ext_len = match this {
            44 => 8usize,                      // fragment header: fixed 8 bytes
            51 => (eh[1] as usize + 2) * 4,    // AH: (len+2)*4
            _ => (eh[1] as usize + 1) * 8,     // hop-by-hop/routing/dest/mobility
        };
        if this == 44 {
            is_frag = true;
            // fragment offset lives in bytes 2..3 (>>3); non-zero => not first frag
            if let Some(fo) = be_u16(frame, cur + 2) {
                if fo & 0xfff8 != 0 {
                    meta.is_fragment = Some(true);
                    meta.ip_proto = Some(next_header);
                    if !ext_types.is_empty() {
                        meta.ipv6_ext_headers = Some(ext_types);
                    }
                    return;
                }
            }
        }
        cur += ext_len;
        hops += 1;
        if next_header == IP_ESP {
            break;
        }
    }
    if !ext_types.is_empty() {
        meta.ipv6_ext_headers = Some(ext_types);
    }
    meta.is_fragment = Some(is_frag);
    meta.ip_proto = Some(next_header);

    let l4_end = {
        let by_total = off + 40 + payload_len as usize;
        by_total.min(frame.len()).max(cur.min(frame.len()))
    };
    l4::dispatch(frame, cur, l4_end, next_header, cfg, meta);
}
