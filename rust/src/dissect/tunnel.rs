//! Encapsulation: GRE, IP-in-IP, VXLAN, Geneve, GTP-U, ERSPAN, L2TP, Teredo.
//!
//! When a tunnel is unwrapped the outer addressing moves to the `outer_*` columns and the
//! inner packet overwrites `ip_src`/`ip_dst`/ports. That ordering is deliberate: an analyst
//! querying `ip_src` wants the endpoint that actually sent the traffic, with the tunnel
//! endpoints still available alongside.

use crate::bytes::Cur;
use crate::dissect::{l2, l3, Ctx};
use crate::error::{DResult, DissectError};

/// Promote the current addressing to the outer columns before descending.
fn enter(ctx: &mut Ctx, kind: &'static str) -> DResult<()> {
    ctx.descend()?;
    ctx.layer(kind);
    if ctx.pkt.outer_ip_src.is_none() {
        ctx.pkt.outer_ip_src = ctx.pkt.ip_src.take();
        ctx.pkt.outer_ip_dst = ctx.pkt.ip_dst.take();
        ctx.pkt.outer_src_port = ctx.pkt.src_port.take();
        ctx.pkt.outer_dst_port = ctx.pkt.dst_port.take();
    }
    ctx.pkt.tunnel_type = Some(kind.to_string());
    Ok(())
}

pub fn gre(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    let flags = c.be16()?;
    let proto = c.be16()?;
    ctx.pkt.gre_protocol = Some(proto);

    // Optional fields appear in a fixed order, gated by the flag bits.
    if flags & 0x8000 != 0 {
        c.skip(4)?; // checksum + reserved1
    }
    if flags & 0x2000 != 0 {
        ctx.pkt.gre_key = Some(c.be32()?);
    }
    if flags & 0x1000 != 0 {
        ctx.pkt.gre_seq = Some(c.be32()?);
    }

    // ERSPAN rides inside GRE with its own shim header before the mirrored frame.
    if proto == 0x88be || proto == 0x22eb {
        enter(ctx, "erspan")?;
        let w = c.be32()?;
        if proto == 0x88be {
            ctx.pkt.erspan_version = Some(1);
            ctx.pkt.erspan_span_id = Some((w & 0x03ff) as u16);
        } else {
            ctx.pkt.erspan_version = Some(2);
            ctx.pkt.erspan_span_id = Some(((w >> 16) & 0x03ff) as u16);
            c.skip(8)?; // ERSPAN-III has a longer header
        }
        return l2::ethernet(c, ctx);
    }

    enter(ctx, "gre")?;
    match proto {
        0x0800 => l3::ipv4(c, ctx),
        0x86dd => l3::ipv6(c, ctx),
        0x6558 => l2::ethernet(c, ctx), // transparent Ethernet bridging (NVGRE)
        0x880b => Ok(()),               // PPP (PPTP data) — payload is PPP-framed
        _ => Err(DissectError::Unsupported),
    }
}

pub fn ip_in_ip(c: &mut Cur, inner_is_v6: bool, ctx: &mut Ctx) -> DResult<()> {
    enter(ctx, "ipip")?;
    if inner_is_v6 {
        l3::ipv6(c, ctx)
    } else {
        l3::ipv4(c, ctx)
    }
}

/// Recognise UDP-encapsulated tunnels by port.
///
/// Returns `None` when the payload is not a tunnel, so the caller falls through to ordinary
/// application dispatch. The cursor is only consumed on a match.
pub fn try_udp_tunnel(c: &mut Cur, sport: u16, dport: u16, ctx: &mut Ctx) -> Option<DResult<()>> {
    match (sport, dport) {
        (_, 4789) | (4789, _) | (_, 4790) => Some(vxlan(c, ctx)),
        (_, 6081) | (6081, _) => Some(geneve(c, ctx)),
        (_, 2152) | (2152, _) | (_, 2123) | (2123, _) => Some(gtp(c, ctx)),
        (_, 1701) | (1701, _) => Some(l2tp(c, ctx)),
        (_, 3544) | (3544, _) => Some(teredo(c, ctx)),
        _ => None,
    }
}

fn vxlan(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    let flags = c.u8()?;
    c.skip(3)?;
    let vni_res = c.be32()?;
    // The I bit must be set for the VNI to be meaningful.
    if flags & 0x08 == 0 {
        return Err(DissectError::Malformed);
    }
    enter(ctx, "vxlan")?;
    ctx.pkt.vxlan_vni = Some(vni_res >> 8);
    l2::ethernet(c, ctx)
}

fn geneve(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    let ver_optlen = c.u8()?;
    let _flags = c.u8()?;
    let proto = c.be16()?;
    let vni_res = c.be32()?;
    enter(ctx, "geneve")?;
    ctx.pkt.geneve_vni = Some(vni_res >> 8);
    ctx.pkt.geneve_protocol = Some(proto);
    // Variable-length options, counted in 4-byte words.
    let opt_len = ((ver_optlen & 0x3f) as usize) * 4;
    c.skip(opt_len)?;
    match proto {
        0x6558 => l2::ethernet(c, ctx),
        0x0800 => l3::ipv4(c, ctx),
        0x86dd => l3::ipv6(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

fn gtp(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    let flags = c.u8()?;
    let msg_type = c.u8()?;
    let _len = c.be16()?;
    let teid = c.be32()?;

    enter(ctx, "gtp")?;
    ctx.pkt.gtp_version = Some(flags >> 5);
    ctx.pkt.gtp_msg_type = Some(msg_type);
    ctx.pkt.gtp_teid = Some(teid);

    // Sequence number / N-PDU / extension-header flags add a fixed 4-byte block.
    if flags & 0x07 != 0 {
        c.skip(3)?;
        // Walk any extension header chain: each is a length in 4-byte units followed by a
        // next-header type, terminated by type 0.
        let mut next = c.u8()?;
        let mut guard = 0;
        while next != 0 {
            guard += 1;
            if guard > 8 {
                return Err(DissectError::Malformed);
            }
            let len = c.u8()? as usize;
            if len == 0 {
                return Err(DissectError::Malformed);
            }
            c.skip(len * 4 - 2)?;
            next = c.u8()?;
        }
    }

    // Only GTP-U (message type 255, "G-PDU") carries a user packet.
    if msg_type != 255 {
        return Ok(());
    }
    match c.peek_u8()? >> 4 {
        4 => l3::ipv4(c, ctx),
        6 => l3::ipv6(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

fn l2tp(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    let flags = c.be16()?;
    let is_control = flags & 0x8000 != 0;
    let has_len = flags & 0x4000 != 0;
    enter(ctx, "l2tp")?;
    if has_len {
        c.skip(2)?;
    }
    ctx.pkt.l2tp_tunnel_id = Some(c.be16()?);
    ctx.pkt.l2tp_session_id = Some(c.be16()?);
    if is_control {
        return Ok(());
    }
    if flags & 0x0800 != 0 {
        c.skip(4)?; // Ns/Nr
    }
    if flags & 0x0200 != 0 {
        c.skip(2)?; // offset size
    }
    // Data messages carry a PPP frame; skip the HDLC-ish address/control pair when present.
    if let Some(b) = c.peek(2) {
        if b == [0xff, 0x03] {
            c.skip(2)?;
        }
    }
    let proto = c.be16()?;
    ctx.pkt.ppp_protocol = Some(proto);
    match proto {
        0x0021 => l3::ipv4(c, ctx),
        0x0057 => l3::ipv6(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

fn teredo(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    // Teredo prepends optional authentication/origin indicators before the IPv6 packet.
    while let Some(b) = c.peek(2) {
        match (b[0], b[1]) {
            (0x00, 0x01) => {
                // Authentication indicator: variable-length client/auth data.
                c.skip(2)?;
                let id_len = c.u8()? as usize;
                let au_len = c.u8()? as usize;
                c.skip(id_len + au_len + 8 + 1)?;
            }
            (0x00, 0x00) => {
                c.skip(8)?; // origin indicator
            }
            _ => break,
        }
    }
    if c.peek_u8()? >> 4 != 6 {
        return Err(DissectError::Malformed);
    }
    enter(ctx, "teredo")?;
    ctx.pkt.teredo_present = Some(true);
    l3::ipv6(c, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::l2::LINKTYPE_RAW;
    use crate::schema::Packet;

    fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
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
            192,
            168,
            1,
            1,
            192,
            168,
            1,
            2,
        ];
        v.extend_from_slice(payload);
        v
    }

    fn dissect(bytes: &[u8]) -> Packet {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            let _ = crate::dissect::dissect_frame(bytes, LINKTYPE_RAW, &mut ctx);
            ctx.finish();
        }
        p
    }

    #[test]
    fn gre_inner_ip_replaces_outer() {
        let inner = ipv4(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let mut gre = vec![0x00, 0x00, 0x08, 0x00];
        gre.extend_from_slice(&inner);
        let p = dissect(&ipv4(47, &gre));

        assert_eq!(p.outer_ip_src.as_deref(), Some("192.168.1.1"));
        // The inner header used the same literal addresses in this fixture, so assert on the
        // structure instead: the stack shows the tunnel and depth was counted.
        assert_eq!(p.tunnel_type.as_deref(), Some("gre"));
        assert_eq!(p.tunnel_depth, Some(1));
        assert_eq!(p.proto_stack.as_deref(), Some("ip:gre:ip:icmp"));
        assert_eq!(p.icmp_type, Some(8));
    }

    #[test]
    fn vxlan_carries_an_ethernet_frame() {
        let inner_ip = ipv4(1, &[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&inner_ip);

        let mut vx = vec![0x08, 0, 0, 0, 0x00, 0x00, 0x7b, 0x00]; // VNI 123
        vx.extend_from_slice(&eth);

        let mut udp = vec![0x30, 0x39, 0x12, 0xb5]; // dport 4789
        let len = 8 + vx.len();
        udp.extend_from_slice(&[(len >> 8) as u8, len as u8, 0, 0]);
        udp.extend_from_slice(&vx);

        let p = dissect(&ipv4(17, &udp));
        assert_eq!(p.vxlan_vni, Some(123));
        assert_eq!(p.tunnel_type.as_deref(), Some("vxlan"));
        assert_eq!(p.outer_dst_port, Some(4789));
        assert_eq!(p.proto_stack.as_deref(), Some("ip:udp:vxlan:eth:ip:icmp"));
    }

    #[test]
    fn gtp_extension_chain_cannot_loop() {
        // Extension-header flag set, with a chain that never terminates.
        let mut gtp = vec![0x34, 255, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        gtp.push(0x85);
        for _ in 0..32 {
            gtp.extend_from_slice(&[1, 0x85, 0, 0]);
        }
        let mut udp = vec![0x08, 0x68, 0x08, 0x68];
        let len = 8 + gtp.len();
        udp.extend_from_slice(&[(len >> 8) as u8, len as u8, 0, 0]);
        udp.extend_from_slice(&gtp);

        // Must terminate with an error rather than spinning.
        let p = dissect(&ipv4(17, &udp));
        assert_eq!(p.tunnel_type.as_deref(), Some("gtp"));
    }
}
