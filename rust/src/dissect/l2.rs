//! Link layer: pcap link types, Ethernet and its tag stacks, ARP, and 802.11.

use crate::bytes::{ascii_string, fmt_mac, fmt_oui, Cur};
use crate::dissect::{l3, Ctx};
use crate::error::{DResult, DissectError};

// pcap LINKTYPE_* values we handle.
pub const LINKTYPE_NULL: u16 = 0;
pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_PPP: u16 = 9;
pub const LINKTYPE_RAW: u16 = 101;
pub const LINKTYPE_IEEE802_11: u16 = 105;
pub const LINKTYPE_LOOP: u16 = 108;
pub const LINKTYPE_LINUX_SLL: u16 = 113;
pub const LINKTYPE_IEEE802_11_RADIOTAP: u16 = 127;
pub const LINKTYPE_IPV4: u16 = 228;
pub const LINKTYPE_IPV6: u16 = 229;
pub const LINKTYPE_LINUX_SLL2: u16 = 276;

// EtherTypes.
pub const ET_IPV4: u16 = 0x0800;
pub const ET_ARP: u16 = 0x0806;
pub const ET_RARP: u16 = 0x8035;
pub const ET_VLAN: u16 = 0x8100;
pub const ET_IPV6: u16 = 0x86dd;
pub const ET_QINQ_1: u16 = 0x88a8;
pub const ET_QINQ_2: u16 = 0x9100;
pub const ET_MPLS_UC: u16 = 0x8847;
pub const ET_MPLS_MC: u16 = 0x8848;
pub const ET_PPPOE_DISC: u16 = 0x8863;
pub const ET_PPPOE_SESS: u16 = 0x8864;
pub const ET_LLDP: u16 = 0x88cc;

pub fn dissect_link(c: &mut Cur, linktype: u16, ctx: &mut Ctx) -> DResult<()> {
    match linktype {
        LINKTYPE_ETHERNET => ethernet(c, ctx),
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => {
            // No link header at all: the first nibble tells us the IP version.
            raw_ip(c, ctx)
        }
        LINKTYPE_NULL | LINKTYPE_LOOP => {
            // BSD loopback: a 4-byte host-order address family.
            let af = c.le32().map_err(|_| DissectError::Truncated)?;
            ctx.layer("null");
            match af {
                2 => l3::ipv4(c, ctx),
                24 | 28 | 30 => l3::ipv6(c, ctx),
                _ => Err(DissectError::Unsupported),
            }
        }
        LINKTYPE_LINUX_SLL => linux_sll(c, ctx),
        LINKTYPE_LINUX_SLL2 => linux_sll2(c, ctx),
        LINKTYPE_PPP => {
            ctx.layer("ppp");
            let proto = c.be16()?;
            ctx.pkt.ppp_protocol = Some(proto);
            ppp_payload(c, proto, ctx)
        }
        LINKTYPE_IEEE802_11 => ieee80211(c, ctx),
        LINKTYPE_IEEE802_11_RADIOTAP => radiotap(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

fn raw_ip(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    match c.peek_u8()? >> 4 {
        4 => l3::ipv4(c, ctx),
        6 => l3::ipv6(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

pub fn ethernet(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("eth");
    let dst = c.mac()?;
    let src = c.mac()?;
    let ethertype = c.be16()?;

    ctx.pkt.eth_dst = Some(fmt_mac(&dst));
    ctx.pkt.eth_src = Some(fmt_mac(&src));
    ctx.pkt.eth_src_oui = Some(fmt_oui(&src));
    ctx.pkt.eth_is_broadcast = Some(dst == [0xff; 6]);
    // The multicast bit is the low bit of the first octet; broadcast is a special case of it.
    ctx.pkt.eth_is_multicast = Some(dst[0] & 0x01 != 0);
    ctx.pkt.eth_type = Some(ethertype);

    // Values <= 1500 are an 802.3 length field, not an EtherType: LLC follows.
    if ethertype <= 1500 {
        return llc(c, ctx);
    }
    ethertype_payload(c, ethertype, ctx)
}

pub fn ethertype_payload(c: &mut Cur, ethertype: u16, ctx: &mut Ctx) -> DResult<()> {
    match ethertype {
        ET_IPV4 => l3::ipv4(c, ctx),
        ET_IPV6 => l3::ipv6(c, ctx),
        ET_ARP | ET_RARP => arp(c, ctx),
        ET_VLAN | ET_QINQ_1 | ET_QINQ_2 => vlan(c, ctx),
        ET_MPLS_UC | ET_MPLS_MC => mpls(c, ctx),
        ET_PPPOE_SESS => pppoe(c, ctx),
        ET_PPPOE_DISC => {
            ctx.layer("pppoed");
            Ok(())
        }
        ET_LLDP => {
            ctx.layer("lldp");
            Ok(())
        }
        _ => Err(DissectError::Unsupported),
    }
}

fn vlan(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("vlan");
    let tci = c.be16()?;
    let vid = tci & 0x0fff;
    // An outer tag already recorded means this is the inner tag of a QinQ stack.
    if ctx.pkt.vlan_id.is_some() {
        ctx.pkt.vlan_inner_id = Some(vid);
    } else {
        ctx.pkt.vlan_id = Some(vid);
        ctx.pkt.vlan_pcp = Some((tci >> 13) as u8);
        ctx.pkt.vlan_dei = Some((tci >> 12) & 1 == 1);
    }
    let inner = c.be16()?;
    if inner <= 1500 {
        return llc(c, ctx);
    }
    ethertype_payload(c, inner, ctx)
}

fn mpls(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("mpls");
    // Walk the label stack to its bottom-of-stack marker.
    loop {
        let w = c.be32()?;
        let label = w >> 12;
        if ctx.pkt.mpls_label.is_none() {
            ctx.pkt.mpls_label = Some(label);
            ctx.pkt.mpls_tc = Some(((w >> 9) & 0x7) as u8);
            ctx.pkt.mpls_ttl = Some((w & 0xff) as u8);
        }
        if (w >> 8) & 1 == 1 {
            break;
        }
    }
    // MPLS carries no protocol identifier; the payload's first nibble is the only hint.
    match c.peek_u8()? >> 4 {
        4 => l3::ipv4(c, ctx),
        6 => l3::ipv6(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

fn pppoe(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("pppoe");
    let _ver_type = c.u8()?;
    let _code = c.u8()?;
    ctx.pkt.pppoe_session_id = Some(c.be16()?);
    let _len = c.be16()?;
    let proto = c.be16()?;
    ctx.pkt.ppp_protocol = Some(proto);
    ppp_payload(c, proto, ctx)
}

fn ppp_payload(c: &mut Cur, proto: u16, ctx: &mut Ctx) -> DResult<()> {
    match proto {
        0x0021 => l3::ipv4(c, ctx),
        0x0057 => l3::ipv6(c, ctx),
        _ => Err(DissectError::Unsupported),
    }
}

fn llc(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("llc");
    let dsap = c.u8()?;
    let ssap = c.u8()?;
    let control = c.u8()?;
    ctx.pkt.llc_dsap = Some(dsap);
    ctx.pkt.llc_ssap = Some(ssap);
    ctx.pkt.llc_control = Some(control);

    // 0xaa/0xaa is SNAP, which restores an EtherType.
    if dsap == 0xaa && ssap == 0xaa {
        ctx.layer("snap");
        let oui = c.be24()?;
        let pid = c.be16()?;
        ctx.pkt.snap_oui = Some(oui);
        ctx.pkt.snap_pid = Some(pid);
        if oui == 0 {
            return ethertype_payload(c, pid, ctx);
        }
    }
    Ok(())
}

fn linux_sll(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("sll");
    let _pkt_type = c.be16()?;
    let _addr_type = c.be16()?;
    let addr_len = c.be16()? as usize;
    let addr = c.take(8)?;
    if addr_len == 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&addr[..6]);
        ctx.pkt.eth_src = Some(fmt_mac(&m));
        ctx.pkt.eth_src_oui = Some(fmt_oui(&m));
    }
    let proto = c.be16()?;
    ctx.pkt.eth_type = Some(proto);
    ethertype_payload(c, proto, ctx)
}

fn linux_sll2(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("sll2");
    let proto = c.be16()?;
    let _reserved = c.be16()?;
    let ifindex = c.be32()?;
    ctx.pkt.iface_id = Some(ifindex);
    let _addr_type = c.be16()?;
    let _pkt_type = c.u8()?;
    let addr_len = c.u8()? as usize;
    let addr = c.take(8)?;
    if addr_len == 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&addr[..6]);
        ctx.pkt.eth_src = Some(fmt_mac(&m));
    }
    ctx.pkt.eth_type = Some(proto);
    ethertype_payload(c, proto, ctx)
}

fn arp(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("arp");
    let hw_type = c.be16()?;
    let proto_type = c.be16()?;
    let hw_len = c.u8()? as usize;
    let proto_len = c.u8()? as usize;
    let opcode = c.be16()?;

    ctx.pkt.arp_hw_type = Some(hw_type);
    ctx.pkt.arp_proto_type = Some(proto_type);
    ctx.pkt.arp_opcode = Some(opcode);
    ctx.pkt.arp_opcode_name = Some(
        match opcode {
            1 => "request",
            2 => "reply",
            3 => "rarp-request",
            4 => "rarp-reply",
            _ => "unknown",
        }
        .to_string(),
    );

    // Only Ethernet/IPv4 ARP has addresses worth naming; anything else we record the opcode
    // for and stop rather than mislabel the bytes.
    if hw_len == 6 && proto_len == 4 {
        let sha = c.mac()?;
        let spa = c.ipv4()?;
        let tha = c.mac()?;
        let tpa = c.ipv4()?;
        ctx.pkt.arp_sender_mac = Some(fmt_mac(&sha));
        ctx.pkt.arp_sender_ip = Some(spa.to_string());
        ctx.pkt.arp_target_mac = Some(fmt_mac(&tha));
        ctx.pkt.arp_target_ip = Some(tpa.to_string());
        // Sender and target protocol address equal: an unsolicited announcement, which is
        // also the shape of ARP-spoofing traffic.
        ctx.pkt.arp_is_gratuitous = Some(spa == tpa);
    }
    Ok(())
}

fn radiotap(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("radiotap");
    let _rev = c.u8()?;
    let _pad = c.u8()?;
    let len = c.le16()? as usize;
    if len < 4 {
        return Err(DissectError::Malformed);
    }
    // The header is self-describing but we only need to step over it to reach 802.11.
    c.skip(len - 4)?;
    ieee80211(c, ctx)
}

fn ieee80211(c: &mut Cur, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("wlan");
    let fc = c.le16()?;
    let ftype = ((fc >> 2) & 0x3) as u8;
    let subtype = ((fc >> 4) & 0xf) as u8;
    ctx.pkt.wlan_type = Some(ftype);
    ctx.pkt.wlan_subtype = Some(subtype);
    let _duration = c.le16()?;
    let addr1 = c.mac()?;
    let addr2 = c.mac()?;
    let addr3 = c.mac()?;
    let _seq = c.le16()?;

    // Which address is the BSSID depends on the to/from-DS bits.
    let to_ds = fc & 0x0100 != 0;
    let from_ds = fc & 0x0200 != 0;
    let bssid = match (to_ds, from_ds) {
        (false, false) => addr3,
        (true, false) => addr1,
        (false, true) => addr2,
        (true, true) => addr3,
    };
    ctx.pkt.wlan_bssid = Some(fmt_mac(&bssid));

    // Management beacons/probes carry the SSID as the first tagged parameter.
    if ftype == 0 && (subtype == 8 || subtype == 0 || subtype == 4 || subtype == 5) {
        if ftype == 0 && subtype == 8 {
            c.skip(12).ok(); // timestamp, beacon interval, capability
        }
        if let Ok(tag) = c.u8() {
            if tag == 0 {
                if let Ok(len) = c.u8() {
                    if let Ok(ssid) = c.take(len as usize) {
                        ctx.pkt.wlan_ssid = ascii_string(ssid);
                    }
                }
            }
        }
        return Ok(());
    }

    // Data frames carry LLC/SNAP then the usual EtherType payload.
    if ftype == 2 && (subtype & 0x08) == 0 {
        if to_ds && from_ds {
            c.skip(6)?; // 4-address format
        }
        return llc(c, ctx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn dissect(bytes: &[u8], linktype: u16) -> (Packet, Result<(), DissectError>) {
        let mut p = Packet::default();
        let r = {
            let mut ctx = Ctx::new(&mut p);
            let r = crate::dissect::dissect_frame(bytes, linktype, &mut ctx);
            ctx.finish();
            r
        };
        (p, r)
    }

    #[test]
    fn ethernet_arp_request() {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // broadcast dst
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&[0x08, 0x06]); // ARP
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&[10, 0, 0, 1]);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&[10, 0, 0, 2]);

        let (p, r) = dissect(&f, LINKTYPE_ETHERNET);
        r.unwrap();
        assert_eq!(p.eth_src.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(p.eth_is_broadcast, Some(true));
        assert_eq!(p.arp_opcode_name.as_deref(), Some("request"));
        assert_eq!(p.arp_sender_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(p.arp_is_gratuitous, Some(false));
        assert_eq!(p.proto_stack.as_deref(), Some("eth:arp"));
    }

    #[test]
    fn vlan_tag_is_unwrapped() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x81, 0x00]); // VLAN
        f.extend_from_slice(&[0x20, 0x64]); // pcp 1, vid 100
        f.extend_from_slice(&[0x08, 0x06]); // ARP inside
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
        f.extend_from_slice(&[0; 20]);

        let (p, r) = dissect(&f, LINKTYPE_ETHERNET);
        r.unwrap();
        assert_eq!(p.vlan_id, Some(100));
        assert_eq!(p.vlan_pcp, Some(1));
        assert_eq!(p.arp_opcode, Some(2));
    }

    #[test]
    fn truncated_frame_errors_without_panicking() {
        for n in 0..14 {
            let (_, r) = dissect(&vec![0u8; n], LINKTYPE_ETHERNET);
            assert!(r.is_err(), "{n}-byte frame should not parse");
        }
    }

    #[test]
    fn unknown_linktype_is_unsupported_not_fatal() {
        let (_, r) = dissect(&[0u8; 64], 9999);
        assert_eq!(r, Err(DissectError::Unsupported));
    }
}
