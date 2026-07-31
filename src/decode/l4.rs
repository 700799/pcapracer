//! Transport-layer decoding: TCP (with options), UDP, ICMPv4/v6.

use super::*;
use crate::config::Config;

/// Dispatch on the IP protocol number. `[start, end)` bounds the L4 region.
pub fn dispatch(
    frame: &[u8],
    start: usize,
    end: usize,
    proto: u8,
    cfg: &Config,
    meta: &mut PacketMeta,
) {
    match proto {
        IP_TCP => decode_tcp(frame, start, end, cfg, meta),
        IP_UDP => decode_udp(frame, start, end, cfg, meta),
        IP_ICMP => decode_icmpv4(frame, start, end, meta),
        IP_ICMPV6 => decode_icmpv6(frame, start, end, meta),
        IP_IPIP => tunnel::decode_ipip(frame, start, cfg, meta, 4),
        IP_IPV6 => tunnel::decode_ipip(frame, start, cfg, meta, 6),
        IP_GRE => tunnel::decode_gre(frame, start, end, cfg, meta),
        _ => {}
    }
}

fn decode_tcp(frame: &[u8], start: usize, end: usize, cfg: &Config, meta: &mut PacketMeta) {
    let seg = match frame.get(start..end) {
        Some(s) if s.len() >= 20 => s,
        _ => return,
    };
    let data_off = (seg[12] >> 4) as usize * 4;
    if data_off < 20 || seg.len() < data_off {
        // Still record ports if we have them.
        meta.src_port = Some(u16::from_be_bytes([seg[0], seg[1]]));
        meta.dst_port = Some(u16::from_be_bytes([seg[2], seg[3]]));
        return;
    }
    meta.src_port = Some(u16::from_be_bytes([seg[0], seg[1]]));
    meta.dst_port = Some(u16::from_be_bytes([seg[2], seg[3]]));
    meta.tcp_seq = Some(u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]));
    meta.tcp_ack = Some(u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]));
    meta.tcp_header_len = Some(data_off as u8);
    let ns = seg[12] & 0x01;
    let flags = ((ns as u16) << 8) | seg[13] as u16;
    meta.tcp_flags = Some(flags);
    meta.tcp_window = Some(u16::from_be_bytes([seg[14], seg[15]]));
    meta.tcp_checksum = Some(u16::from_be_bytes([seg[16], seg[17]]));
    meta.tcp_urgent_ptr = Some(u16::from_be_bytes([seg[18], seg[19]]));

    parse_tcp_options(&seg[20..data_off], meta);

    let payload_off = start + data_off;
    let payload_len = end.saturating_sub(payload_off);
    meta.tcp_payload_len = Some(payload_len as u32);
    payload_stats(frame, payload_off, payload_len, cfg, meta);
}

/// Walk the TCP options region, extracting MSS/WScale/SACK-permitted/SACK/Timestamps.
fn parse_tcp_options(opts: &[u8], meta: &mut PacketMeta) {
    let mut i = 0usize;
    let mut sack_blocks = 0u8;
    while i < opts.len() {
        let kind = opts[i];
        match kind {
            0 => break, // end of options
            1 => {
                i += 1;
                continue;
            } // nop
            _ => {}
        }
        let len = match opts.get(i + 1) {
            Some(&l) => l as usize,
            None => break,
        };
        if len < 2 || i + len > opts.len() {
            break;
        }
        let body = &opts[i + 2..i + len];
        match kind {
            2 if body.len() == 2 => {
                meta.tcp_mss = Some(u16::from_be_bytes([body[0], body[1]]));
            }
            3 if !body.is_empty() => {
                meta.tcp_wscale = Some(body[0]);
            }
            4 => {
                meta.tcp_sack_permitted = Some(true);
            }
            5 => {
                sack_blocks = (body.len() / 8) as u8;
            }
            8 if body.len() == 8 => {
                meta.tcp_ts_val = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                meta.tcp_ts_ecr = Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]));
            }
            _ => {}
        }
        i += len;
    }
    if sack_blocks > 0 {
        meta.tcp_sack_count = Some(sack_blocks);
    }
    if meta.tcp_sack_permitted.is_none() {
        meta.tcp_sack_permitted = Some(false);
    }
}

fn decode_udp(frame: &[u8], start: usize, end: usize, cfg: &Config, meta: &mut PacketMeta) {
    let seg = match frame.get(start..end) {
        Some(s) if s.len() >= 8 => s,
        _ => return,
    };
    let sport = u16::from_be_bytes([seg[0], seg[1]]);
    let dport = u16::from_be_bytes([seg[2], seg[3]]);
    meta.src_port = Some(sport);
    meta.dst_port = Some(dport);
    meta.udp_len = Some(u16::from_be_bytes([seg[4], seg[5]]));
    meta.udp_checksum = Some(u16::from_be_bytes([seg[6], seg[7]]));

    let payload_off = start + 8;
    let payload_len = end.saturating_sub(payload_off);
    payload_stats(frame, payload_off, payload_len, cfg, meta);

    // VXLAN (RFC 7348 port 4789; Linux default 8472) carries an inner Ethernet frame.
    if (dport == 4789 || dport == 8472) && meta.tunnel_depth < MAX_TUNNEL_DEPTH {
        tunnel::decode_vxlan(frame, payload_off, end, cfg, meta);
    }
}

fn decode_icmpv4(frame: &[u8], start: usize, end: usize, meta: &mut PacketMeta) {
    let seg = match frame.get(start..end) {
        Some(s) if s.len() >= 4 => s,
        _ => return,
    };
    let ty = seg[0];
    meta.icmp_type = Some(ty);
    meta.icmp_code = Some(seg[1]);
    match ty {
        0 | 8 => {
            if seg.len() >= 8 {
                meta.icmp_echo_id = Some(u16::from_be_bytes([seg[4], seg[5]]));
                meta.icmp_echo_seq = Some(u16::from_be_bytes([seg[6], seg[7]]));
            }
        }
        3 => {
            // destination unreachable; frag-needed carries next-hop MTU in bytes 6..8
            if seg.len() >= 8 {
                meta.icmp_mtu = Some(u16::from_be_bytes([seg[6], seg[7]]));
            }
        }
        _ => {}
    }
}

fn decode_icmpv6(frame: &[u8], start: usize, end: usize, meta: &mut PacketMeta) {
    let seg = match frame.get(start..end) {
        Some(s) if s.len() >= 4 => s,
        _ => return,
    };
    let ty = seg[0];
    meta.icmp_type = Some(ty);
    meta.icmp_code = Some(seg[1]);
    match ty {
        128 | 129 => {
            if seg.len() >= 8 {
                meta.icmp_echo_id = Some(u16::from_be_bytes([seg[4], seg[5]]));
                meta.icmp_echo_seq = Some(u16::from_be_bytes([seg[6], seg[7]]));
            }
        }
        2 => {
            // packet too big: 32-bit MTU in bytes 4..8
            if seg.len() >= 8 {
                let mtu = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
                meta.icmp_mtu = u16::try_from(mtu).ok();
            }
        }
        _ => {}
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
            app_buffer_budget: 1 << 26,
            hex_prefix_len: 0,
            threads: 1,
            batch_size: 128,
        }
    }

    #[test]
    fn tcp_options_parsed() {
        // TCP header with MSS, SACK-permitted, WScale, Timestamps options
        let mut seg = vec![
            0x04, 0xd2, // sport 1234
            0x00, 0x50, // dport 80
            0, 0, 0, 1, // seq
            0, 0, 0, 0, // ack
            0xa0, 0x02, // data offset 10 words (40 bytes), flags SYN
            0xff, 0xff, // window
            0, 0, // csum
            0, 0, // urg
        ];
        // options: MSS=1460, SACKOK, WScale=7, TS(val=1,ecr=2), then EOL/pad
        seg.extend_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
        seg.extend_from_slice(&[4, 2]); // SACK permitted
        seg.extend_from_slice(&[3, 3, 7]); // wscale 7
        seg.extend_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 2]); // timestamps
        seg.push(0); // eol
        // pad to 40 bytes header
        while seg.len() < 40 {
            seg.push(1);
        }
        let mut m = PacketMeta::default();
        let end = seg.len();
        decode_tcp(&seg, 0, end, &cfg(), &mut m);
        assert_eq!(m.tcp_mss, Some(1460));
        assert_eq!(m.tcp_sack_permitted, Some(true));
        assert_eq!(m.tcp_wscale, Some(7));
        assert_eq!(m.tcp_ts_val, Some(1));
        assert_eq!(m.tcp_ts_ecr, Some(2));
    }

    #[test]
    fn bad_option_length_no_panic() {
        // option kind 2 claims length 99 (overruns) — must not panic
        let mut seg = vec![
            0, 80, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x02, 0, 0, 0, 0, 0, 0,
        ];
        seg.extend_from_slice(&[2, 99, 0, 0]); // malformed
        let end = seg.len();
        let mut m = PacketMeta::default();
        decode_tcp(&seg, 0, end, &cfg(), &mut m);
        // parsed ports, did not crash, MSS not set
        assert_eq!(m.src_port, Some(80));
        assert_eq!(m.tcp_mss, None);
    }
}
