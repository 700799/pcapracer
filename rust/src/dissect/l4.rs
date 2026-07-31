//! Transport layer: TCP (with options), UDP, SCTP.

use std::net::IpAddr;

use crate::bytes::{entropy, is_mostly_printable, preview, Cur};
use crate::dissect::{app, l3, tunnel, Ctx};
use crate::error::DResult;

pub const TCP_FIN: u16 = 0x001;
pub const TCP_SYN: u16 = 0x002;
pub const TCP_RST: u16 = 0x004;
pub const TCP_PSH: u16 = 0x008;
pub const TCP_ACK: u16 = 0x010;
pub const TCP_URG: u16 = 0x020;
pub const TCP_ECE: u16 = 0x040;
pub const TCP_CWR: u16 = 0x080;

pub fn flags_string(f: u16) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(4);
    for (bit, name) in [
        (TCP_FIN, "FIN"),
        (TCP_SYN, "SYN"),
        (TCP_RST, "RST"),
        (TCP_PSH, "PSH"),
        (TCP_ACK, "ACK"),
        (TCP_URG, "URG"),
        (TCP_ECE, "ECE"),
        (TCP_CWR, "CWR"),
    ] {
        if f & bit != 0 {
            parts.push(name);
        }
    }
    parts.join(",")
}

pub fn tcp(c: &mut Cur, src: IpAddr, dst: IpAddr, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("tcp");
    let start = c.pos();
    let sport = c.be16()?;
    let dport = c.be16()?;
    let seq = c.be32()?;
    let ack = c.be32()?;
    let offset_flags = c.be16()?;
    let window = c.be16()?;
    let checksum = c.be16()?;
    let urgent = c.be16()?;

    let data_offset = ((offset_flags >> 12) & 0xf) as usize * 4;
    let flags = offset_flags & 0x01ff;

    ctx.pkt.l4_proto = Some("tcp".to_string());
    ctx.pkt.src_port = Some(sport);
    ctx.pkt.dst_port = Some(dport);
    ctx.pkt.tcp_seq = Some(seq);
    ctx.pkt.tcp_ack = Some(ack);
    ctx.pkt.tcp_flags = Some(flags);
    ctx.pkt.tcp_flags_str = Some(flags_string(flags));
    ctx.pkt.tcp_flag_fin = Some(flags & TCP_FIN != 0);
    ctx.pkt.tcp_flag_syn = Some(flags & TCP_SYN != 0);
    ctx.pkt.tcp_flag_rst = Some(flags & TCP_RST != 0);
    ctx.pkt.tcp_flag_psh = Some(flags & TCP_PSH != 0);
    ctx.pkt.tcp_flag_ack = Some(flags & TCP_ACK != 0);
    ctx.pkt.tcp_flag_urg = Some(flags & TCP_URG != 0);
    ctx.pkt.tcp_flag_ece = Some(flags & TCP_ECE != 0);
    ctx.pkt.tcp_flag_cwr = Some(flags & TCP_CWR != 0);
    ctx.pkt.tcp_window = Some(window);
    ctx.pkt.tcp_checksum = Some(checksum);
    ctx.pkt.tcp_urgent_ptr = Some(urgent);
    ctx.pkt.tcp_hdr_len = Some(data_offset as u8);

    l3::set_tuple(ctx, src, dst, sport, dport, l3::IP_TCP);

    // A data offset below the 20-byte minimum is corrupt; above it, options follow.
    if data_offset >= 20 {
        let consumed = c.pos() - start;
        let opt_len = data_offset - consumed;
        if opt_len > 0 && opt_len <= c.remaining() {
            let opts = c.take(opt_len)?;
            parse_tcp_options(opts, ctx);
        }
    }

    let payload = c.take_rest();
    ctx.pkt.tcp_payload_len = Some(payload.len() as u32);
    record_payload(payload, ctx);

    if !payload.is_empty() && !ctx.defer_tcp_app {
        app::dispatch(payload, sport, dport, true, ctx);
    }
    Ok(())
}

fn parse_tcp_options(opts: &[u8], ctx: &mut Ctx) {
    let mut c = Cur::new(opts);
    let mut kinds: Vec<String> = Vec::new();
    // Options are attacker-controlled and self-describing; every read is checked and any
    // inconsistency ends the walk rather than failing the packet.
    while let Ok(kind) = c.u8() {
        match kind {
            0 => break, // end of option list
            1 => {
                kinds.push("nop".into());
                continue;
            }
            _ => {}
        }
        let len = match c.u8() {
            Ok(l) if l >= 2 => l as usize,
            _ => break,
        };
        let body = match c.take(len - 2) {
            Ok(b) => b,
            Err(_) => break,
        };
        match kind {
            2 => {
                kinds.push("mss".into());
                if body.len() == 2 {
                    ctx.pkt.tcp_mss = Some(u16::from_be_bytes([body[0], body[1]]));
                }
            }
            3 => {
                kinds.push("wscale".into());
                if body.len() == 1 {
                    ctx.pkt.tcp_window_scale = Some(body[0]);
                }
            }
            4 => {
                kinds.push("sackok".into());
                ctx.pkt.tcp_sack_permitted = Some(true);
            }
            5 => {
                kinds.push("sack".into());
                let mut blocks = Vec::new();
                for chunk in body.chunks_exact(8) {
                    let l = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let r = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                    blocks.push(format!("{l}-{r}"));
                }
                if !blocks.is_empty() {
                    ctx.pkt.tcp_sack_blocks = Some(blocks.join(","));
                }
            }
            8 => {
                kinds.push("timestamp".into());
                if body.len() == 8 {
                    ctx.pkt.tcp_ts_val =
                        Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                    ctx.pkt.tcp_ts_ecr =
                        Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]));
                }
            }
            other => kinds.push(format!("opt{other}")),
        }
    }
    if !kinds.is_empty() {
        // The option kind order is itself a passive OS fingerprint, so keep the sequence.
        ctx.pkt.tcp_option_kinds = Some(kinds.join(","));
    }
}

pub fn udp(c: &mut Cur, src: IpAddr, dst: IpAddr, proto: u8, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("udp");
    let sport = c.be16()?;
    let dport = c.be16()?;
    let len = c.be16()?;
    let checksum = c.be16()?;

    ctx.pkt.l4_proto = Some(
        if proto == l3::IP_UDPLITE {
            "udplite"
        } else {
            "udp"
        }
        .to_string(),
    );
    ctx.pkt.src_port = Some(sport);
    ctx.pkt.dst_port = Some(dport);
    ctx.pkt.udp_len = Some(len);
    ctx.pkt.udp_checksum = Some(checksum);
    l3::set_tuple(ctx, src, dst, sport, dport, proto);

    // The UDP length covers the header too, and can lie; clamp before slicing.
    if (len as usize) >= 8 {
        let want = len as usize - 8;
        if want < c.remaining() {
            let body = c.take(want)?;
            let mut sc = Cur::new(body);
            return udp_payload(&mut sc, sport, dport, ctx);
        }
    }
    udp_payload(c, sport, dport, ctx)
}

fn udp_payload(c: &mut Cur, sport: u16, dport: u16, ctx: &mut Ctx) -> DResult<()> {
    // UDP-borne tunnels must be unwrapped before application dispatch, or we would label
    // the outer port's protocol onto the encapsulated packet's payload.
    if let Some(r) = tunnel::try_udp_tunnel(c, sport, dport, ctx) {
        return r;
    }

    let payload = c.take_rest();
    ctx.pkt.udp_payload_len = Some(payload.len() as u32);
    record_payload(payload, ctx);
    if !payload.is_empty() {
        app::dispatch(payload, sport, dport, false, ctx);
    }
    Ok(())
}

pub fn sctp(c: &mut Cur, src: IpAddr, dst: IpAddr, ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("sctp");
    let sport = c.be16()?;
    let dport = c.be16()?;
    let vtag = c.be32()?;
    let checksum = c.be32()?;

    ctx.pkt.l4_proto = Some("sctp".to_string());
    ctx.pkt.src_port = Some(sport);
    ctx.pkt.dst_port = Some(dport);
    ctx.pkt.sctp_verification_tag = Some(vtag);
    ctx.pkt.sctp_checksum = Some(checksum);
    l3::set_tuple(ctx, src, dst, sport, dport, l3::IP_SCTP);

    // Chunk walk: the type sequence distinguishes association setup from data transfer.
    let mut types = Vec::new();
    let mut count = 0u16;
    while let Ok(t) = c.u8() {
        let _flags = match c.u8() {
            Ok(f) => f,
            Err(_) => break,
        };
        let len = match c.be16() {
            Ok(l) if l >= 4 => l as usize,
            _ => break,
        };
        types.push(match t {
            0 => "DATA".to_string(),
            1 => "INIT".to_string(),
            2 => "INIT_ACK".to_string(),
            3 => "SACK".to_string(),
            4 => "HEARTBEAT".to_string(),
            5 => "HEARTBEAT_ACK".to_string(),
            6 => "ABORT".to_string(),
            7 => "SHUTDOWN".to_string(),
            10 => "COOKIE_ECHO".to_string(),
            11 => "COOKIE_ACK".to_string(),
            other => format!("CHUNK{other}"),
        });
        count += 1;
        // Chunks are padded to a 4-byte boundary.
        let advance = ((len - 4) + 3) & !3;
        if c.skip(advance).is_err() {
            break;
        }
        if count >= 64 {
            break;
        }
    }
    if !types.is_empty() {
        ctx.pkt.sctp_chunk_types = Some(types.join(","));
        ctx.pkt.sctp_num_chunks = Some(count);
    }
    Ok(())
}

/// Payload-shape columns that apply regardless of which application protocol was found —
/// entropy in particular is how you spot tunnelled or encrypted data on a plaintext port.
pub fn record_payload(payload: &[u8], ctx: &mut Ctx) {
    if payload.is_empty() {
        return;
    }
    ctx.pkt.payload_len = Some(payload.len() as u32);
    ctx.pkt.payload_entropy = Some(entropy(payload));
    ctx.pkt.payload_preview = Some(preview(payload, 96));
    ctx.pkt.payload_is_printable = Some(is_mostly_printable(payload));
    let n = payload.len().min(16);
    ctx.pkt.payload_first_bytes = Some(payload[..n].to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::l2::LINKTYPE_RAW;
    use crate::schema::Packet;

    fn ipv4_tcp(payload: &[u8], opts: &[u8]) -> Vec<u8> {
        let doff = (20 + opts.len()) / 4;
        let mut tcp = vec![0x1f, 0x90, 0x00, 0x50]; // 8080 -> 80
        tcp.extend_from_slice(&[0, 0, 0, 1]); // seq
        tcp.extend_from_slice(&[0, 0, 0, 2]); // ack
        tcp.push((doff as u8) << 4);
        tcp.push(0x18); // PSH|ACK
        tcp.extend_from_slice(&[0xff, 0xff]); // window
        tcp.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent
        tcp.extend_from_slice(opts);
        tcp.extend_from_slice(payload);

        let total = 20 + tcp.len();
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
            6,
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
        v.extend_from_slice(&tcp);
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
    fn tcp_flags_and_payload() {
        let p = dissect(&ipv4_tcp(b"hello", &[]));
        assert_eq!(p.src_port, Some(8080));
        assert_eq!(p.dst_port, Some(80));
        assert_eq!(p.tcp_flags_str.as_deref(), Some("PSH,ACK"));
        assert_eq!(p.tcp_flag_syn, Some(false));
        assert_eq!(p.tcp_payload_len, Some(5));
        assert_eq!(p.payload_preview.as_deref(), Some("hello"));
    }

    #[test]
    fn tcp_options_are_parsed_in_order() {
        // MSS 1460, SACK permitted, NOP, window scale 7
        let opts = [2u8, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7, 0, 0];
        let p = dissect(&ipv4_tcp(b"", &opts));
        assert_eq!(p.tcp_mss, Some(1460));
        assert_eq!(p.tcp_sack_permitted, Some(true));
        assert_eq!(p.tcp_window_scale, Some(7));
        assert_eq!(p.tcp_option_kinds.as_deref(), Some("mss,sackok,nop,wscale"));
    }

    #[test]
    fn malformed_tcp_option_length_does_not_hang() {
        // A length byte of 0 would loop forever if not guarded.
        let opts = [5u8, 0, 0, 0];
        let p = dissect(&ipv4_tcp(b"x", &opts));
        assert_eq!(p.src_port, Some(8080));
    }

    #[test]
    fn flags_string_covers_all_bits() {
        assert_eq!(flags_string(TCP_SYN), "SYN");
        assert_eq!(flags_string(TCP_FIN | TCP_ACK), "FIN,ACK");
        assert_eq!(flags_string(0), "");
    }
}
