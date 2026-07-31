//! Network layer: IPv4, IPv6 with its extension-header chain, ICMP, ICMPv6 and IGMP.

use std::net::IpAddr;

use crate::bytes::{fmt_mac, hex, is_private_v4, is_private_v6, Cur};
use crate::dissect::{l4, tunnel, Ctx, Tuple};
use crate::error::{DResult, DissectError};

// IP protocol numbers.
pub const IP_ICMP: u8 = 1;
pub const IP_IGMP: u8 = 2;
pub const IP_IPIP: u8 = 4;
pub const IP_TCP: u8 = 6;
pub const IP_UDP: u8 = 17;
pub const IP_IPV6: u8 = 41;
pub const IP_ROUTING: u8 = 43;
pub const IP_FRAGMENT: u8 = 44;
pub const IP_GRE: u8 = 47;
pub const IP_ESP: u8 = 50;
pub const IP_AH: u8 = 51;
pub const IP_ICMPV6: u8 = 58;
pub const IP_NONE: u8 = 59;
pub const IP_DSTOPTS: u8 = 60;
pub const IP_HOPOPTS: u8 = 0;
pub const IP_OSPF: u8 = 89;
pub const IP_PIM: u8 = 103;
pub const IP_VRRP: u8 = 112;
pub const IP_L2TP: u8 = 115;
pub const IP_SCTP: u8 = 132;
pub const IP_MOBILITY: u8 = 135;
pub const IP_UDPLITE: u8 = 136;

pub fn proto_name(p: u8) -> &'static str {
    match p {
        IP_HOPOPTS => "hopopt",
        IP_ICMP => "icmp",
        IP_IGMP => "igmp",
        IP_IPIP => "ipip",
        IP_TCP => "tcp",
        IP_UDP => "udp",
        IP_IPV6 => "ipv6",
        IP_GRE => "gre",
        IP_ESP => "esp",
        IP_AH => "ah",
        IP_ICMPV6 => "ipv6-icmp",
        IP_OSPF => "ospf",
        IP_PIM => "pim",
        IP_VRRP => "vrrp",
        IP_L2TP => "l2tp",
        IP_SCTP => "sctp",
        IP_UDPLITE => "udplite",
        _ => "other",
    }
}

pub fn ipv4(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("ip");
    let start = c.pos();
    let ver_ihl = c.u8()?;
    if ver_ihl >> 4 != 4 {
        return Err(DissectError::Malformed);
    }
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err(DissectError::Malformed);
    }
    let tos = c.u8()?;
    let total_len = c.be16()?;
    let id = c.be16()?;
    let flags_frag = c.be16()?;
    let ttl = c.u8()?;
    let proto = c.u8()?;
    let checksum = c.be16()?;
    let src = c.ipv4()?;
    let dst = c.ipv4()?;

    ctx.pkt.ip_version = Some(4);
    ctx.pkt.ip_hdr_len = Some(ihl as u8);
    ctx.pkt.ip_tos = Some(tos);
    ctx.pkt.ip_dscp = Some(tos >> 2);
    ctx.pkt.ip_ecn = Some(tos & 0x3);
    ctx.pkt.ip_total_len = Some(total_len as u32);
    ctx.pkt.ip_id = Some(id as u32);
    ctx.pkt.ip_flag_df = Some(flags_frag & 0x4000 != 0);
    ctx.pkt.ip_flag_mf = Some(flags_frag & 0x2000 != 0);
    let frag_offset = (flags_frag & 0x1fff) * 8;
    ctx.pkt.ip_frag_offset = Some(frag_offset);
    ctx.pkt.ip_ttl = Some(ttl);
    ctx.pkt.ip_proto = Some(proto);
    ctx.pkt.ip_proto_name = Some(proto_name(proto).to_string());
    ctx.pkt.ip_checksum = Some(checksum);
    ctx.pkt.ip_src = Some(src.to_string());
    ctx.pkt.ip_dst = Some(dst.to_string());
    ctx.pkt.ip_src_is_private = Some(is_private_v4(&src));
    ctx.pkt.ip_dst_is_private = Some(is_private_v4(&dst));

    // Options, if the header is longer than the fixed 20 bytes.
    if ihl > 20 {
        let opts = c.take(ihl - 20)?;
        ctx.pkt.ip_options = Some(hex(opts));
    }

    // `total_len` bounds the payload; a frame can carry trailing padding past it, and a
    // corrupt value can exceed what we actually captured. Clamp to both.
    let consumed = c.pos() - start;
    if (total_len as usize) > consumed {
        let want = total_len as usize - consumed;
        if want < c.remaining() {
            let sub = c.take(want)?;
            let mut sc = Cur::new(sub);
            return after_ip(&mut sc, proto, src.into(), dst.into(), frag_offset, ctx);
        }
    }
    after_ip(c, proto, src.into(), dst.into(), frag_offset, ctx)
}

pub fn ipv6(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("ipv6");
    let w = c.be32()?;
    if w >> 28 != 6 {
        return Err(DissectError::Malformed);
    }
    let payload_len = c.be16()?;
    let next_header = c.u8()?;
    let hop_limit = c.u8()?;
    let src = c.ipv6()?;
    let dst = c.ipv6()?;

    ctx.pkt.ip_version = Some(6);
    ctx.pkt.ip6_traffic_class = Some(((w >> 20) & 0xff) as u8);
    ctx.pkt.ip6_flow_label = Some(w & 0x000f_ffff);
    ctx.pkt.ip6_payload_len = Some(payload_len);
    ctx.pkt.ip6_next_header = Some(next_header);
    ctx.pkt.ip6_hop_limit = Some(hop_limit);
    ctx.pkt.ip_ttl = Some(hop_limit);
    ctx.pkt.ip_src = Some(src.to_string());
    ctx.pkt.ip_dst = Some(dst.to_string());
    ctx.pkt.ip_src_is_private = Some(is_private_v6(&src));
    ctx.pkt.ip_dst_is_private = Some(is_private_v6(&dst));

    // Walk the extension-header chain to the first upper-layer protocol.
    let mut proto = next_header;
    let mut chain: Vec<&'static str> = Vec::new();
    let mut frag_offset = 0u16;
    let mut guard = 0;
    loop {
        // Each extension header is itself a chance to loop forever on crafted input.
        guard += 1;
        if guard > 16 {
            return Err(DissectError::Malformed);
        }
        match proto {
            IP_HOPOPTS | IP_ROUTING | IP_DSTOPTS | IP_MOBILITY => {
                chain.push(match proto {
                    IP_HOPOPTS => "hopopt",
                    IP_ROUTING => "routing",
                    IP_DSTOPTS => "dstopts",
                    _ => "mobility",
                });
                let nh = c.u8()?;
                let len = c.u8()? as usize;
                c.skip((len + 1) * 8 - 2)?;
                proto = nh;
            }
            IP_FRAGMENT => {
                chain.push("frag");
                let nh = c.u8()?;
                let _res = c.u8()?;
                let off_flags = c.be16()?;
                let ident = c.be32()?;
                frag_offset = off_flags & 0xfff8;
                ctx.pkt.ip_frag_offset = Some(frag_offset);
                ctx.pkt.ip_flag_mf = Some(off_flags & 1 == 1);
                ctx.pkt.ip_id = Some(ident);
                proto = nh;
            }
            IP_AH => {
                chain.push("ah");
                let nh = c.u8()?;
                let len = c.u8()? as usize;
                c.skip((len + 2) * 4 - 2)?;
                proto = nh;
            }
            IP_NONE => break,
            _ => break,
        }
    }
    if !chain.is_empty() {
        ctx.pkt.ip6_ext_headers = Some(chain.join(","));
    }
    ctx.pkt.ip_proto = Some(proto);
    ctx.pkt.ip_proto_name = Some(proto_name(proto).to_string());

    after_ip(c, proto, src.into(), dst.into(), frag_offset, ctx)
}

/// Dispatch on the IP protocol number once addressing is known.
fn after_ip(
    c: &mut Cur,
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    frag_offset: u16,
    ctx: &mut Ctx,
) -> DResult<()> {
    // A non-first fragment has no transport header to read — its bytes are the middle of
    // someone else's payload. Reassembly (when enabled) handles these separately.
    if frag_offset != 0 {
        ctx.layer("ip-fragment");
        return Ok(());
    }

    // Every IP packet belongs to a conversation, so the tuple is established here with no
    // ports and the transport dissectors overwrite it once they have some. Doing it up front
    // rather than per-branch is what gives ICMP, ESP, GRE and friends a flow — ping sweeps
    // and ICMP tunnelling are precisely the things an analyst wants aggregated, and a
    // port-bearing-protocols-only flow table silently omits them.
    set_tuple(ctx, src, dst, 0, 0, proto);

    match proto {
        IP_TCP => l4::tcp(c, src, dst, ctx),
        IP_UDP | IP_UDPLITE => l4::udp(c, src, dst, proto, ctx),
        IP_SCTP => l4::sctp(c, src, dst, ctx),
        IP_ICMP => icmp(c, ctx),
        IP_ICMPV6 => icmpv6(c, ctx),
        IP_IGMP => igmp(c, ctx),
        IP_GRE => tunnel::gre(c, ctx),
        IP_IPIP => tunnel::ip_in_ip(c, false, ctx),
        IP_IPV6 => tunnel::ip_in_ip(c, true, ctx),
        IP_ESP => esp(c, ctx),
        IP_OSPF => {
            ctx.layer("ospf");
            Ok(())
        }
        IP_VRRP => {
            ctx.layer("vrrp");
            Ok(())
        }
        IP_PIM => {
            ctx.layer("pim");
            Ok(())
        }
        _ => Err(DissectError::Unsupported),
    }
}

pub fn set_tuple(ctx: &mut Ctx, src: IpAddr, dst: IpAddr, sp: u16, dp: u16, proto: u8) {
    ctx.tuple = Some(Tuple {
        src_ip: src,
        dst_ip: dst,
        src_port: sp,
        dst_port: dp,
        proto,
    });
}

fn esp(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("esp");
    ctx.pkt.esp_spi = Some(c.be32()?);
    ctx.pkt.esp_seq = Some(c.be32()?);
    Ok(())
}

fn icmp_type_name(t: u8) -> &'static str {
    match t {
        0 => "echo-reply",
        3 => "dest-unreachable",
        4 => "source-quench",
        5 => "redirect",
        8 => "echo-request",
        9 => "router-advertisement",
        10 => "router-solicitation",
        11 => "time-exceeded",
        12 => "parameter-problem",
        13 => "timestamp-request",
        14 => "timestamp-reply",
        _ => "other",
    }
}

pub fn icmp(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("icmp");
    let t = c.u8()?;
    let code = c.u8()?;
    let _checksum = c.be16()?;
    ctx.pkt.icmp_type = Some(t);
    ctx.pkt.icmp_code = Some(code);
    ctx.pkt.icmp_type_name = Some(icmp_type_name(t).to_string());

    match t {
        // Echo and timestamp carry an identifier/sequence pair used to match request to reply.
        0 | 8 | 13 | 14 => {
            ctx.pkt.icmp_id = Some(c.be16()?);
            ctx.pkt.icmp_seq = Some(c.be16()?);
        }
        3 => {
            let _unused = c.be16()?;
            ctx.pkt.icmp_mtu = Some(c.be16()?);
        }
        5 => {
            ctx.pkt.icmp_gateway = Some(c.ipv4()?.to_string());
        }
        _ => {}
    }
    // The quoted original datagram is deliberately not re-dissected: it would overwrite the
    // outer addressing with the inner packet's and confuse the flow table.
    Ok(())
}

fn icmp6_type_name(t: u8) -> &'static str {
    match t {
        1 => "dest-unreachable",
        2 => "packet-too-big",
        3 => "time-exceeded",
        4 => "parameter-problem",
        128 => "echo-request",
        129 => "echo-reply",
        133 => "router-solicitation",
        134 => "router-advertisement",
        135 => "neighbor-solicitation",
        136 => "neighbor-advertisement",
        137 => "redirect",
        143 => "multicast-listener-report",
        _ => "other",
    }
}

pub fn icmpv6(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("icmpv6");
    let t = c.u8()?;
    let code = c.u8()?;
    let _checksum = c.be16()?;
    ctx.pkt.icmp6_type = Some(t);
    ctx.pkt.icmp6_code = Some(code);
    ctx.pkt.icmp6_type_name = Some(icmp6_type_name(t).to_string());

    match t {
        128 | 129 => {
            ctx.pkt.icmp_id = Some(c.be16()?);
            ctx.pkt.icmp_seq = Some(c.be16()?);
        }
        135 | 136 => {
            let _reserved = c.be32()?;
            ctx.pkt.icmp6_nd_target = Some(c.ipv6()?.to_string());
            // Neighbour discovery options: type 1 (source LL addr) / 2 (target LL addr)
            // carry the MAC, which is what makes ND useful for host inventory.
            if let (Ok(opt_type), Ok(opt_len)) = (c.u8(), c.u8()) {
                if (opt_type == 1 || opt_type == 2) && opt_len == 1 {
                    if let Ok(m) = c.mac() {
                        ctx.pkt.icmp6_nd_option_mac = Some(fmt_mac(&m));
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn igmp(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("igmp");
    ctx.pkt.igmp_type = Some(c.u8()?);
    ctx.pkt.igmp_max_resp = Some(c.u8()?);
    let _checksum = c.be16()?;
    ctx.pkt.igmp_group = Some(c.ipv4()?.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::l2::LINKTYPE_RAW;
    use crate::schema::Packet;

    fn dissect(bytes: &[u8]) -> (Packet, Result<(), DissectError>) {
        let mut p = Packet::default();
        let r = {
            let mut ctx = Ctx::new(&mut p);
            let r = crate::dissect::dissect_frame(bytes, LINKTYPE_RAW, &mut ctx);
            ctx.finish();
            r
        };
        (p, r)
    }

    fn ipv4_hdr(proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut v = vec![
            0x45,
            0x00,
            (total >> 8) as u8,
            total as u8,
            0xab,
            0xcd,
            0x40,
            0x00, // DF
            64,
            proto,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ];
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn ipv4_icmp_echo() {
        let icmp = [8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
        let (p, r) = dissect(&ipv4_hdr(IP_ICMP, &icmp));
        r.unwrap();
        assert_eq!(p.ip_src.as_deref(), Some("10.0.0.1"));
        assert_eq!(p.ip_src_is_private, Some(true));
        assert_eq!(p.ip_flag_df, Some(true));
        assert_eq!(p.icmp_type_name.as_deref(), Some("echo-request"));
        assert_eq!(p.icmp_id, Some(0x1234));
        assert_eq!(p.proto_stack.as_deref(), Some("ip:icmp"));
    }

    #[test]
    fn non_first_fragment_has_no_transport_header() {
        let mut v = ipv4_hdr(IP_TCP, &[0xaa; 16]);
        // fragment offset 185 (=1480 bytes), MF set
        v[6] = 0x20;
        v[7] = 0xb9;
        let (p, r) = dissect(&v);
        r.unwrap();
        assert_eq!(p.ip_frag_offset, Some(1480));
        // Crucially we did NOT invent TCP ports from payload bytes.
        assert!(p.src_port.is_none());
        assert_eq!(p.highest_layer.as_deref(), Some("ip-fragment"));
    }

    #[test]
    fn ipv6_extension_chain_is_walked() {
        let mut v = vec![0x60, 0, 0, 0];
        v.extend_from_slice(&[0, 16]); // payload len
        v.push(IP_HOPOPTS);
        v.push(64);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // hop-by-hop: next=ICMPv6, len=0 -> 8 bytes total
        v.extend_from_slice(&[IP_ICMPV6, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&[128, 0, 0, 0, 0x11, 0x22, 0, 5]);

        let (p, r) = dissect(&v);
        r.unwrap();
        assert_eq!(p.ip_version, Some(6));
        assert_eq!(p.ip_src.as_deref(), Some("2001:db8::1"));
        assert_eq!(p.ip6_ext_headers.as_deref(), Some("hopopt"));
        assert_eq!(p.icmp6_type_name.as_deref(), Some("echo-request"));
    }

    #[test]
    fn ipv6_extension_loop_is_bounded() {
        // A hop-by-hop header whose next-header points at itself, forever.
        let mut v = vec![0x60, 0, 0, 0, 0x00, 0xff, IP_HOPOPTS, 64];
        v.extend_from_slice(&[0u8; 32]);
        for _ in 0..64 {
            v.extend_from_slice(&[IP_HOPOPTS, 0, 0, 0, 0, 0, 0, 0]);
        }
        let (_, r) = dissect(&v);
        assert_eq!(r, Err(DissectError::Malformed));
    }

    /// Every IP packet must get a flow tuple, not just the port-bearing protocols — an
    /// ICMP-only flow table would omit ping sweeps and ICMP tunnelling entirely.
    #[test]
    fn portless_protocols_still_get_a_flow_tuple() {
        for proto in [IP_ICMP, IP_IGMP, IP_ESP, IP_OSPF, IP_VRRP] {
            let mut p = Packet::default();
            let tuple = {
                let mut ctx = Ctx::new(&mut p);
                let _ = crate::dissect::dissect_frame(
                    &ipv4_hdr(proto, &[0u8; 16]),
                    LINKTYPE_RAW,
                    &mut ctx,
                );
                ctx.finish();
                ctx.tuple
            };
            let tuple = tuple.unwrap_or_else(|| panic!("proto {proto} produced no flow tuple"));
            assert_eq!(tuple.proto, proto);
            assert_eq!(tuple.src_port, 0);
            assert_eq!(tuple.dst_port, 0);
        }
    }

    #[test]
    fn echo_request_and_reply_normalize_to_one_flow() {
        let mut request = Packet::default();
        let a = {
            let mut ctx = Ctx::new(&mut request);
            let _ = crate::dissect::dissect_frame(
                &ipv4_hdr(IP_ICMP, &[8, 0, 0, 0, 0x12, 0x34, 0, 1]),
                LINKTYPE_RAW,
                &mut ctx,
            );
            ctx.tuple.unwrap()
        };

        // The reply swaps source and destination.
        let mut v = ipv4_hdr(IP_ICMP, &[0, 0, 0, 0, 0x12, 0x34, 0, 1]);
        v[12..16].copy_from_slice(&[10, 0, 0, 2]);
        v[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let mut reply = Packet::default();
        let b = {
            let mut ctx = Ctx::new(&mut reply);
            let _ = crate::dissect::dissect_frame(&v, LINKTYPE_RAW, &mut ctx);
            ctx.tuple.unwrap()
        };

        assert_eq!(a.normalized().0, b.normalized().0);
    }

    #[test]
    fn bad_ihl_is_rejected() {
        let mut v = ipv4_hdr(IP_ICMP, &[0; 8]);
        v[0] = 0x43; // IHL of 3 words = 12 bytes, shorter than the fixed header
        let (_, r) = dissect(&v);
        assert_eq!(r, Err(DissectError::Malformed));
    }
}
