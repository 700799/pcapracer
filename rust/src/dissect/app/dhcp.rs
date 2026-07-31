//! DHCPv4 and DHCPv6.

use crate::bytes::{ascii_string, cap, fmt_mac, Cur};
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

const MAGIC_COOKIE: u32 = 0x6382_5363;

fn msg_type_name(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "OTHER",
    }
}

pub fn parse(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("dhcp");
    let mut c = Cur::new(payload);

    let op = c.u8()?;
    let _htype = c.u8()?;
    let hlen = c.u8()? as usize;
    let _hops = c.u8()?;
    let xid = c.be32()?;
    let _secs = c.be16()?;
    let _flags = c.be16()?;
    let ciaddr = c.ipv4()?;
    let yiaddr = c.ipv4()?;
    let _siaddr = c.ipv4()?;
    let _giaddr = c.ipv4()?;
    let chaddr = c.take(16)?;

    ctx.pkt.dhcp_op = Some(op);
    ctx.pkt.dhcp_transaction_id = Some(xid);
    if !ciaddr.is_unspecified() {
        ctx.pkt.dhcp_client_ip = Some(ciaddr.to_string());
    }
    if !yiaddr.is_unspecified() {
        ctx.pkt.dhcp_your_ip = Some(yiaddr.to_string());
    }
    if hlen == 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&chaddr[..6]);
        ctx.pkt.dhcp_client_mac = Some(fmt_mac(&m));
    }

    c.skip(64 + 128)?; // sname + file
    if c.be32()? != MAGIC_COOKIE {
        return Err(DissectError::Malformed);
    }

    let mut guard = 0;
    while let Ok(code) = c.u8() {
        guard += 1;
        if guard > 128 {
            break;
        }
        match code {
            0 => continue, // pad
            255 => break,  // end
            _ => {}
        }
        let len = match c.u8() {
            Ok(l) => l as usize,
            Err(_) => break,
        };
        let val = match c.take(len) {
            Ok(v) => v,
            Err(_) => break,
        };
        match code {
            12 => ctx.pkt.dhcp_hostname = val_str(val),
            15 => ctx.pkt.dhcp_domain = val_str(val),
            50 if len == 4 => {
                ctx.pkt.dhcp_requested_ip =
                    Some(std::net::Ipv4Addr::new(val[0], val[1], val[2], val[3]).to_string())
            }
            51 if len == 4 => {
                ctx.pkt.dhcp_lease_time = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]))
            }
            53 if len == 1 => {
                ctx.pkt.dhcp_msg_type = Some(val[0]);
                ctx.pkt.dhcp_msg_type_name = Some(msg_type_name(val[0]).to_string());
            }
            54 if len == 4 => {
                ctx.pkt.dhcp_server_id =
                    Some(std::net::Ipv4Addr::new(val[0], val[1], val[2], val[3]).to_string())
            }
            55 => {
                // The parameter request list, in order, is the classic DHCP OS fingerprint —
                // the same sequence identifies the client stack across leases.
                let list = val
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                ctx.pkt.dhcp_fingerprint = Some(cap(list.clone(), 512));
                ctx.pkt.dhcp_param_req_list = Some(cap(list, 512));
            }
            60 => ctx.pkt.dhcp_vendor_class = val_str(val),
            _ => {}
        }
    }
    Ok(())
}

fn val_str(v: &[u8]) -> Option<String> {
    ascii_string(v).map(|s| cap(s, 256))
}

pub fn parse_v6(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("dhcpv6");
    let mut c = Cur::new(payload);
    let msg_type = c.u8()?;
    let xid = c.be24()?;
    ctx.pkt.dhcp6_msg_type = Some(msg_type);
    ctx.pkt.dhcp6_transaction_id = Some(xid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn discover() -> Vec<u8> {
        let mut v = vec![1, 1, 6, 0];
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // xid
        v.extend_from_slice(&[0, 0, 0, 0]); // secs + flags
        v.extend_from_slice(&[0, 0, 0, 0]); // ciaddr
        v.extend_from_slice(&[10, 0, 0, 55]); // yiaddr
        v.extend_from_slice(&[0, 0, 0, 0]); // siaddr
        v.extend_from_slice(&[0, 0, 0, 0]); // giaddr
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        v.extend_from_slice(&[0u8; 10]); // chaddr padding
        v.extend_from_slice(&[0u8; 64 + 128]);
        v.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        v.extend_from_slice(&[53, 1, 1]); // DHCPDISCOVER
        v.extend_from_slice(&[12, 7]);
        v.extend_from_slice(b"laptop1");
        v.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
        v.push(255);
        v
    }

    #[test]
    fn parses_a_discover() {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            parse(&discover(), &mut ctx).unwrap();
        }
        assert_eq!(p.dhcp_msg_type_name.as_deref(), Some("DISCOVER"));
        assert_eq!(p.dhcp_client_mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(p.dhcp_hostname.as_deref(), Some("laptop1"));
        assert_eq!(p.dhcp_fingerprint.as_deref(), Some("1,3,6,15"));
        assert_eq!(p.dhcp_your_ip.as_deref(), Some("10.0.0.55"));
    }

    #[test]
    fn missing_magic_cookie_is_rejected() {
        let mut v = discover();
        v[236] = 0;
        let mut p = Packet::default();
        let r = {
            let mut ctx = Ctx::new(&mut p);
            parse(&v, &mut ctx)
        };
        assert_eq!(r, Err(DissectError::Malformed));
    }

    #[test]
    fn truncated_options_do_not_panic() {
        let full = discover();
        for n in 240..full.len() {
            let mut p = Packet::default();
            let mut ctx = Ctx::new(&mut p);
            let _ = parse(&full[..n], &mut ctx);
        }
    }
}
