//! Compact binary protocols: NTP, SNMP, TFTP, NetBIOS, RADIUS, MQTT, WireGuard, IKE,
//! RTP/RTCP and RDP.

use crate::bytes::{ascii_string, cap, hex, Cur};
use crate::dissect::app::ber;
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

pub fn ntp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("ntp");
    let mut c = Cur::new(payload);
    let b0 = c.u8()?;
    ctx.pkt.ntp_leap = Some(b0 >> 6);
    ctx.pkt.ntp_version = Some((b0 >> 3) & 0x7);
    let mode = b0 & 0x7;
    ctx.pkt.ntp_mode = Some(mode);
    ctx.pkt.ntp_mode_name = Some(
        match mode {
            1 => "symmetric-active",
            2 => "symmetric-passive",
            3 => "client",
            4 => "server",
            5 => "broadcast",
            6 => "control",
            7 => "private",
            _ => "reserved",
        }
        .to_string(),
    );
    let stratum = c.u8()?;
    ctx.pkt.ntp_stratum = Some(stratum);
    ctx.pkt.ntp_poll = Some(c.u8()? as i8 as i64);
    ctx.pkt.ntp_precision = Some(c.u8()? as i8 as i64);
    c.skip(8)?; // root delay + dispersion
    let ref_id = c.take(4)?;
    // For stratum 0/1 the reference ID is a four-character code (e.g. "GPS "); above that it
    // is the IPv4 address of the upstream server.
    ctx.pkt.ntp_ref_id = Some(if stratum <= 1 {
        crate::bytes::preview(ref_id, 4)
    } else {
        std::net::Ipv4Addr::new(ref_id[0], ref_id[1], ref_id[2], ref_id[3]).to_string()
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// SNMP
// ---------------------------------------------------------------------------

pub fn snmp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("snmp");
    let mut c = Cur::new(payload);
    let seq = ber::read_in(&mut c)?;
    if !seq.constructed || seq.tag != ber::TAG_SEQUENCE {
        return Err(DissectError::Malformed);
    }
    let mut s = seq.cur();

    let version = ber::read_in(&mut s)?;
    ctx.pkt.snmp_version = version.as_u64().map(|v| v as u8);

    // v3 replaces the community string with a security-parameters structure, so stop here.
    if ctx.pkt.snmp_version == Some(3) {
        return Ok(());
    }

    let community = ber::read_in(&mut s)?;
    // The community string is the v1/v2c credential — the single most useful SNMP field.
    ctx.pkt.snmp_community = community.as_str().map(|v| cap(v, 256));

    let pdu = ber::read_in(&mut s)?;
    if pdu.class != ber::CLASS_CONTEXT {
        return Ok(());
    }
    ctx.pkt.snmp_pdu_type = Some(pdu.tag);
    ctx.pkt.snmp_pdu_type_name = Some(
        match pdu.tag {
            0 => "get-request",
            1 => "get-next-request",
            2 => "get-response",
            3 => "set-request",
            4 => "trap-v1",
            5 => "get-bulk-request",
            6 => "inform-request",
            7 => "trap-v2",
            8 => "report",
            _ => "unknown",
        }
        .to_string(),
    );

    let mut p = pdu.cur();
    if let Ok(req_id) = ber::read_in(&mut p) {
        ctx.pkt.snmp_request_id = req_id.as_i64();
    }
    if let Ok(err) = ber::read_in(&mut p) {
        ctx.pkt.snmp_error_status = err.as_u64().map(|v| v as u8);
    }

    // Collect the OIDs from the varbind list.
    let mut oids: Vec<ber::Tlv> = Vec::new();
    ber::collect(
        pdu.val,
        6,
        32,
        &|t: &ber::Tlv| t.class == ber::CLASS_UNIVERSAL && t.tag == ber::TAG_OID,
        &mut oids,
    );
    let rendered: Vec<String> = oids.iter().filter_map(|t| t.as_oid()).collect();
    if !rendered.is_empty() {
        ctx.pkt.snmp_oids = Some(cap(rendered.join(","), 1024));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TFTP
// ---------------------------------------------------------------------------

pub fn tftp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("tftp");
    let mut c = Cur::new(payload);
    let opcode = c.be16()?;
    ctx.pkt.tftp_opcode = Some(opcode);
    // Only read/write requests carry a filename; data and ack packets carry a block number.
    if opcode == 1 || opcode == 2 {
        let rest = c.take_rest();
        let mut it = rest.split(|&b| b == 0);
        ctx.pkt.tftp_filename = it.next().and_then(ascii_string).map(|s| cap(s, 512));
        ctx.pkt.tftp_mode = it.next().and_then(ascii_string);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NetBIOS
// ---------------------------------------------------------------------------

/// Decode the first-level NetBIOS name encoding: each byte is split into two nibbles, each
/// offset by 'A'.
fn nb_decode(encoded: &[u8]) -> Option<String> {
    if encoded.len() < 32 {
        return None;
    }
    let mut s = String::with_capacity(16);
    for pair in encoded[..32].chunks_exact(2) {
        let hi = pair[0].wrapping_sub(b'A');
        let lo = pair[1].wrapping_sub(b'A');
        if hi > 15 || lo > 15 {
            return None;
        }
        s.push(((hi << 4) | lo) as char);
    }
    Some(s.trim_end().to_string())
}

pub fn nbns(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("nbns");
    let mut c = Cur::new(payload);
    let _txid = c.be16()?;
    let flags = c.be16()?;
    ctx.pkt.nbns_opcode = Some(((flags >> 11) & 0xf) as u8);
    c.skip(8)?; // counts
    let len = c.u8()? as usize;
    let name = c.take(len)?;
    ctx.pkt.nbns_name = nb_decode(name);
    Ok(())
}

pub fn nbss(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("nbss");
    let mut c = Cur::new(payload);
    ctx.pkt.nbss_type = Some(c.u8()?);
    Ok(())
}

// ---------------------------------------------------------------------------
// RADIUS
// ---------------------------------------------------------------------------

pub fn radius(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("radius");
    let mut c = Cur::new(payload);
    let code = c.u8()?;
    ctx.pkt.radius_code = Some(code);
    ctx.pkt.radius_code_name = Some(
        match code {
            1 => "Access-Request",
            2 => "Access-Accept",
            3 => "Access-Reject",
            4 => "Accounting-Request",
            5 => "Accounting-Response",
            11 => "Access-Challenge",
            _ => "Other",
        }
        .to_string(),
    );
    ctx.pkt.radius_identifier = Some(c.u8()?);
    let len = c.be16()? as usize;
    c.skip(16)?; // authenticator

    // Attributes fill the remainder of the declared length.
    let body_len = len.saturating_sub(20).min(c.remaining());
    let mut a = Cur::new(c.take(body_len)?);
    let mut guard = 0;
    while a.remaining() >= 2 {
        guard += 1;
        if guard > 128 {
            break;
        }
        let t = a.u8()?;
        let l = a.u8()? as usize;
        if l < 2 {
            break;
        }
        let v = match a.take(l - 2) {
            Ok(v) => v,
            Err(_) => break,
        };
        match t {
            1 => ctx.pkt.radius_username = ascii_string(v).map(|s| cap(s, 256)),
            4 if v.len() == 4 => {
                ctx.pkt.radius_nas_ip =
                    Some(std::net::Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string())
            }
            30 => ctx.pkt.radius_called_station = ascii_string(v).map(|s| cap(s, 256)),
            31 => ctx.pkt.radius_calling_station = ascii_string(v).map(|s| cap(s, 256)),
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MQTT
// ---------------------------------------------------------------------------

pub fn mqtt(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("mqtt");
    let mut c = Cur::new(payload);
    let b0 = c.u8()?;
    let msg_type = b0 >> 4;
    ctx.pkt.mqtt_msg_type = Some(msg_type);
    ctx.pkt.mqtt_msg_type_name = Some(
        match msg_type {
            1 => "CONNECT",
            2 => "CONNACK",
            3 => "PUBLISH",
            4 => "PUBACK",
            8 => "SUBSCRIBE",
            9 => "SUBACK",
            12 => "PINGREQ",
            13 => "PINGRESP",
            14 => "DISCONNECT",
            _ => "OTHER",
        }
        .to_string(),
    );
    ctx.pkt.mqtt_qos = Some((b0 >> 1) & 0x3);

    // Remaining length is a base-128 varint of at most four bytes.
    let mut remaining: u32 = 0;
    let mut shift = 0;
    loop {
        let b = c.u8()?;
        remaining |= ((b & 0x7f) as u32) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 21 {
            return Err(DissectError::Malformed);
        }
    }
    ctx.pkt.mqtt_payload_len = Some(remaining);

    match msg_type {
        1 => {
            // CONNECT: protocol name, level, flags, keepalive, then the client identifier.
            let name_len = c.be16()? as usize;
            c.skip(name_len)?;
            let _level = c.u8()?;
            let flags = c.u8()?;
            let _keepalive = c.be16()?;
            let id_len = c.be16()? as usize;
            ctx.pkt.mqtt_client_id = ascii_string(c.take(id_len)?).map(|s| cap(s, 256));
            // Will topic/message precede the credentials when the will flag is set.
            if flags & 0x04 != 0 {
                let wt = c.be16()? as usize;
                c.skip(wt)?;
                let wm = c.be16()? as usize;
                c.skip(wm)?;
            }
            if flags & 0x80 != 0 {
                let ul = c.be16()? as usize;
                ctx.pkt.mqtt_username = ascii_string(c.take(ul)?).map(|s| cap(s, 256));
            }
        }
        3 => {
            let topic_len = c.be16()? as usize;
            ctx.pkt.mqtt_topic = ascii_string(c.take(topic_len)?).map(|s| cap(s, 512));
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WireGuard / IKE
// ---------------------------------------------------------------------------

pub fn wireguard(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("wireguard");
    let mut c = Cur::new(payload);
    let t = c.u8()?;
    if !(1..=4).contains(&t) {
        return Err(DissectError::Malformed);
    }
    c.skip(3)?; // reserved
    ctx.pkt.wireguard_type = Some(t);
    match t {
        1 => ctx.pkt.wireguard_sender = Some(c.le32()?),
        2 => {
            ctx.pkt.wireguard_sender = Some(c.le32()?);
            ctx.pkt.wireguard_receiver = Some(c.le32()?);
        }
        3 | 4 => ctx.pkt.wireguard_receiver = Some(c.le32()?),
        _ => {}
    }
    Ok(())
}

pub fn ike(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("ike");
    let mut c = Cur::new(payload);

    // IKE over port 4500 is prefixed with a four-byte zero non-ESP marker.
    if c.peek(4) == Some(&[0, 0, 0, 0]) {
        c.skip(4)?;
    }
    ctx.pkt.ike_initiator_spi = Some(hex(c.take(8)?));
    ctx.pkt.ike_responder_spi = Some(hex(c.take(8)?));
    let _next_payload = c.u8()?;
    let version = c.u8()?;
    ctx.pkt.ike_version = Some(format!("{}.{}", version >> 4, version & 0xf));
    ctx.pkt.ike_exchange_type = Some(c.u8()?);
    let _flags = c.u8()?;
    ctx.pkt.ike_message_id = Some(c.be32()?);
    Ok(())
}

// ---------------------------------------------------------------------------
// RTP / RTCP
// ---------------------------------------------------------------------------

/// RTP has no port registration and no magic number, so misidentifying it is easy. Require
/// version 2 and a payload type outside the range RTCP uses.
pub fn looks_like_rtp(d: &[u8]) -> bool {
    d.len() >= 12 && (d[0] >> 6) == 2 && !(72..=95).contains(&(d[1] & 0x7f))
}

pub fn looks_like_rtcp(d: &[u8]) -> bool {
    d.len() >= 8 && (d[0] >> 6) == 2 && (200..=207).contains(&d[1])
}

pub fn rtp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("rtp");
    let mut c = Cur::new(payload);
    let b0 = c.u8()?;
    let b1 = c.u8()?;
    ctx.pkt.rtp_version = Some(b0 >> 6);
    ctx.pkt.rtp_marker = Some(b1 & 0x80 != 0);
    ctx.pkt.rtp_payload_type = Some(b1 & 0x7f);
    ctx.pkt.rtp_seq = Some(c.be16()?);
    ctx.pkt.rtp_timestamp = Some(c.be32()?);
    ctx.pkt.rtp_ssrc = Some(c.be32()?);
    Ok(())
}

pub fn rtcp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("rtcp");
    let mut c = Cur::new(payload);
    let _b0 = c.u8()?;
    ctx.pkt.rtcp_type = Some(c.u8()?);
    let _len = c.be16()?;
    ctx.pkt.rtcp_ssrc = Some(c.be32()?);
    Ok(())
}

// ---------------------------------------------------------------------------
// RDP
// ---------------------------------------------------------------------------

pub fn rdp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("rdp");
    let mut c = Cur::new(payload);
    // TPKT header: version 3, reserved, 16-bit length.
    if c.u8()? != 3 {
        return Err(DissectError::Malformed);
    }
    c.skip(3)?;
    let _li = c.u8()?;
    let code = c.u8()?;
    ctx.pkt.rdp_type = Some(
        match code >> 4 {
            0xe => "connection-request",
            0xd => "connection-confirm",
            0xf => "data",
            _ => "other",
        }
        .to_string(),
    );

    if code >> 4 == 0xe {
        c.skip(5)?; // dst-ref, src-ref, class
        let rest = c.take_rest();
        let text = String::from_utf8_lossy(rest);
        // The routing token or cookie identifies the target host or user, and is the field
        // worth keeping from an otherwise opaque connection request.
        if let Some(i) = text.find("Cookie: ") {
            let tail = &text[i + 8..];
            let end = tail.find('\r').unwrap_or(tail.len().min(256));
            ctx.pkt.rdp_cookie = Some(cap(tail[..end].to_string(), 256));
        }
        // RDP negotiation request: type 1, flags, length, requested protocols.
        if let Some(pos) = rest.iter().position(|&b| b == 0x01) {
            if rest.len() >= pos + 8 {
                let p = &rest[pos + 4..pos + 8];
                ctx.pkt.rdp_requested_protocols =
                    Some(u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn run<F: FnOnce(&mut Ctx) -> DResult<()>>(f: F) -> Packet {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            f(&mut ctx).unwrap();
        }
        p
    }

    #[test]
    fn ntp_client_request() {
        let mut v = vec![0x1b, 0, 4, 0xfa]; // LI 0, v3, mode 3
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(b"GPS ");
        v.extend_from_slice(&[0u8; 32]);
        let p = run(|ctx| ntp(&v, ctx));
        assert_eq!(p.ntp_version, Some(3));
        assert_eq!(p.ntp_mode_name.as_deref(), Some("client"));
        assert_eq!(p.ntp_precision, Some(-6));
    }

    #[test]
    fn snmp_get_request_yields_community_and_oid() {
        // SEQUENCE { INTEGER 0, OCTET STRING "public", [0] { INTEGER 1, INTEGER 0, INTEGER 0,
        //   SEQUENCE { SEQUENCE { OID 1.3.6.1, NULL } } } }
        let varbind = [
            0x30, 0x0a, 0x30, 0x08, 0x06, 0x04, 0x2b, 0x06, 0x01, 0x01, 0x05, 0x00,
        ];
        let mut pdu = vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        pdu.extend_from_slice(&varbind);
        let mut body = vec![0x02, 0x01, 0x00, 0x04, 0x06];
        body.extend_from_slice(b"public");
        body.push(0xa0);
        body.push(pdu.len() as u8);
        body.extend_from_slice(&pdu);
        let mut msg = vec![0x30, body.len() as u8];
        msg.extend_from_slice(&body);

        let p = run(|ctx| snmp(&msg, ctx));
        assert_eq!(p.snmp_version, Some(0));
        assert_eq!(p.snmp_community.as_deref(), Some("public"));
        assert_eq!(p.snmp_pdu_type_name.as_deref(), Some("get-request"));
        assert_eq!(p.snmp_oids.as_deref(), Some("1.3.6.1.1"));
    }

    #[test]
    fn tftp_read_request() {
        let mut v = vec![0, 1];
        v.extend_from_slice(b"boot.cfg\0octet\0");
        let p = run(|ctx| tftp(&v, ctx));
        assert_eq!(p.tftp_filename.as_deref(), Some("boot.cfg"));
        assert_eq!(p.tftp_mode.as_deref(), Some("octet"));
    }

    #[test]
    fn mqtt_connect_yields_client_id() {
        let mut body = vec![0, 4];
        body.extend_from_slice(b"MQTT");
        body.push(4); // level
        body.push(0x80); // username flag
        body.extend_from_slice(&[0, 60]); // keepalive
        body.extend_from_slice(&[0, 6]);
        body.extend_from_slice(b"sensor");
        body.extend_from_slice(&[0, 5]);
        body.extend_from_slice(b"admin");

        let mut v = vec![0x10, body.len() as u8];
        v.extend_from_slice(&body);
        let p = run(|ctx| mqtt(&v, ctx));
        assert_eq!(p.mqtt_msg_type_name.as_deref(), Some("CONNECT"));
        assert_eq!(p.mqtt_client_id.as_deref(), Some("sensor"));
        assert_eq!(p.mqtt_username.as_deref(), Some("admin"));
    }

    #[test]
    fn radius_access_request_username() {
        let mut v = vec![1, 42];
        let attrs = {
            let mut a = vec![1, 7];
            a.extend_from_slice(b"alice");
            a
        };
        let len = 20 + attrs.len();
        v.extend_from_slice(&[(len >> 8) as u8, len as u8]);
        v.extend_from_slice(&[0u8; 16]);
        v.extend_from_slice(&attrs);
        let p = run(|ctx| radius(&v, ctx));
        assert_eq!(p.radius_code_name.as_deref(), Some("Access-Request"));
        assert_eq!(p.radius_username.as_deref(), Some("alice"));
    }

    #[test]
    fn rtp_sniffing_rejects_rtcp_payload_types() {
        let rtcp_pkt = [0x80, 200, 0, 6, 1, 2, 3, 4];
        assert!(!looks_like_rtp(&rtcp_pkt));
        assert!(looks_like_rtcp(&rtcp_pkt));

        let rtp_pkt = [0x80, 0x08, 0, 1, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];
        assert!(looks_like_rtp(&rtp_pkt));
        let p = run(|ctx| rtp(&rtp_pkt, ctx));
        assert_eq!(p.rtp_ssrc, Some(0xdead_beef));
        assert_eq!(p.rtp_payload_type, Some(8));
    }

    #[test]
    fn ike_handles_the_non_esp_marker() {
        let mut v = vec![0, 0, 0, 0];
        v.extend_from_slice(&[0x11; 8]);
        v.extend_from_slice(&[0x22; 8]);
        v.extend_from_slice(&[33, 0x20, 34, 0x08, 0, 0, 0, 1]);
        let p = run(|ctx| ike(&v, ctx));
        assert_eq!(p.ike_version.as_deref(), Some("2.0"));
        assert_eq!(p.ike_exchange_type, Some(34));
        assert_eq!(p.ike_initiator_spi.as_deref(), Some("1111111111111111"));
    }

    #[test]
    fn netbios_name_decoding() {
        // "FRED" encoded: each nibble offset by 'A', padded with spaces to 16 bytes.
        let mut enc = Vec::new();
        for b in b"FRED            " {
            enc.push(b'A' + (b >> 4));
            enc.push(b'A' + (b & 0xf));
        }
        assert_eq!(nb_decode(&enc).as_deref(), Some("FRED"));
        // Out-of-range nibbles must be rejected rather than producing mojibake.
        assert!(nb_decode(&[0xff; 32]).is_none());
    }
}
