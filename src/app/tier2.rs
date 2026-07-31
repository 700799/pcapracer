//! Tier-2 protocol detectors: SNMP, TFTP, Syslog, SIP (UDP) and
//! Modbus/TCP, SMB (TCP). All best-effort, single-packet, panic-free.

use crate::decode::PacketMeta;

/// UDP tier-2 dispatch by port. Returns true if a protocol was recognized.
pub fn parse_udp(payload: &[u8], meta: &mut PacketMeta) -> bool {
    let sp = meta.src_port.unwrap_or(0);
    let dp = meta.dst_port.unwrap_or(0);
    let has = |p| sp == p || dp == p;
    if has(161) || has(162) {
        return snmp(payload, meta);
    }
    if has(69) {
        return tftp(payload, meta);
    }
    if has(514) {
        return syslog(payload, meta);
    }
    if has(5060) {
        return sip(payload, meta);
    }
    false
}

/// TCP tier-2 dispatch by port (single-packet, worker inline).
pub fn parse_tcp(payload: &[u8], meta: &mut PacketMeta) {
    let sp = meta.src_port.unwrap_or(0);
    let dp = meta.dst_port.unwrap_or(0);
    let has = |p| sp == p || dp == p;
    if has(502) {
        modbus(payload, meta);
    } else if has(445) || has(139) {
        smb(payload, meta);
    } else if has(5060) {
        sip(payload, meta);
    }
}

/// SNMP: parse the outer ASN.1 SEQUENCE for version (INTEGER) and community.
fn snmp(payload: &[u8], meta: &mut PacketMeta) -> bool {
    // SEQUENCE (0x30) len, INTEGER version, OCTET STRING community
    if payload.len() < 2 || payload[0] != 0x30 {
        return false;
    }
    let (_seq_len, mut p) = match ber_len(payload, 1) {
        Some(v) => v,
        None => return false,
    };
    // version INTEGER
    if payload.get(p) != Some(&0x02) {
        return false;
    }
    let (vlen, vstart) = match ber_len(payload, p + 1) {
        Some(v) => v,
        None => return false,
    };
    if vlen == 0 || vstart + vlen > payload.len() {
        return false;
    }
    meta.snmp_version = Some(payload[vstart + vlen - 1]);
    p = vstart + vlen;
    // community OCTET STRING
    if payload.get(p) == Some(&0x04) {
        if let Some((clen, cstart)) = ber_len(payload, p + 1) {
            if cstart + clen <= payload.len() {
                let community = &payload[cstart..cstart + clen];
                let mut s = String::with_capacity(clen);
                for &b in community {
                    s.push(if (0x20..=0x7e).contains(&b) {
                        b as char
                    } else {
                        '.'
                    });
                }
                meta.snmp_community = Some(s);
            }
        }
    }
    meta.app_proto = Some("snmp");
    true
}

/// Parse a short-form or long-form BER length at `off`; returns (len, value_start).
fn ber_len(b: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = *b.get(off)?;
    if first & 0x80 == 0 {
        Some((first as usize, off + 1))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(off + 1 + i)? as usize;
        }
        Some((len, off + 1 + n))
    }
}

fn tftp(payload: &[u8], meta: &mut PacketMeta) -> bool {
    if payload.len() < 2 {
        return false;
    }
    let opcode = u16::from_be_bytes([payload[0], payload[1]]);
    if (1..=6).contains(&opcode) {
        meta.tftp_opcode = Some(opcode as u8);
        meta.app_proto = Some("tftp");
        return true;
    }
    false
}

fn syslog(payload: &[u8], meta: &mut PacketMeta) -> bool {
    // Syslog messages begin with "<PRI>" where PRI = facility*8 + severity.
    if payload.first() != Some(&b'<') {
        return false;
    }
    let mut pri = 0u32;
    let mut i = 1;
    while i < payload.len() && i < 5 {
        let c = payload[i];
        if c == b'>' {
            meta.syslog_facility = Some((pri / 8) as u8);
            meta.syslog_severity = Some((pri % 8) as u8);
            meta.app_proto = Some("syslog");
            return true;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        pri = pri * 10 + (c - b'0') as u32;
        i += 1;
    }
    false
}

fn sip(payload: &[u8], meta: &mut PacketMeta) -> bool {
    const METHODS: [&[u8]; 8] = [
        b"INVITE ",
        b"ACK ",
        b"BYE ",
        b"CANCEL ",
        b"REGISTER ",
        b"OPTIONS ",
        b"INFO ",
        b"SIP/",
    ];
    if !METHODS.iter().any(|m| payload.starts_with(m)) {
        return false;
    }
    let line_end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len().min(256));
    let line = &payload[..line_end.min(256)];
    let mut parts = line.splitn(3, |&b| b == b' ');
    if let Some(m) = parts.next() {
        meta.sip_method = Some(String::from_utf8_lossy(m).into_owned());
    }
    if let Some(uri) = parts.next() {
        meta.sip_uri = Some(String::from_utf8_lossy(uri).into_owned());
    }
    meta.app_proto = Some("sip");
    true
}

fn modbus(payload: &[u8], meta: &mut PacketMeta) {
    // MBAP: transaction(2) protocol(2)=0 length(2) unit(1) function(1)
    if payload.len() >= 8 && payload[2] == 0 && payload[3] == 0 {
        meta.modbus_unit_id = Some(payload[6]);
        meta.modbus_function = Some(payload[7]);
        meta.app_proto = Some("modbus");
    }
}

fn smb(payload: &[u8], meta: &mut PacketMeta) {
    // Payload may be preceded by a 4-byte NetBIOS session header.
    let p = if payload.len() > 4 && payload[0] == 0x00 {
        &payload[4..]
    } else {
        payload
    };
    if p.len() >= 8 && &p[1..4] == b"SMB" {
        meta.smb_dialect = Some(match p[0] {
            0xff => "smb1",
            0xfe => "smb2",
            0xfd => "smb3",
            _ => "smb",
        });
        meta.app_proto = Some(meta.smb_dialect.unwrap_or("smb"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::field_reassign_with_default)]
    fn meta_ports(sp: u16, dp: u16) -> PacketMeta {
        let mut m = PacketMeta::default();
        m.src_port = Some(sp);
        m.dst_port = Some(dp);
        m
    }

    #[test]
    fn snmp_v2c() {
        // SEQ { INTEGER 1, OCTET STRING "public", ... }
        let mut pkt = vec![0x30, 0x0c, 0x02, 0x01, 0x01, 0x04, 0x06];
        pkt.extend_from_slice(b"public");
        let mut m = meta_ports(40000, 161);
        assert!(snmp(&pkt, &mut m));
        assert_eq!(m.snmp_version, Some(1));
        assert_eq!(m.snmp_community.as_deref(), Some("public"));
    }

    #[test]
    fn modbus_read() {
        let pkt = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03];
        let mut m = meta_ports(40000, 502);
        modbus(&pkt, &mut m);
        assert_eq!(m.modbus_unit_id, Some(0x11));
        assert_eq!(m.modbus_function, Some(0x03));
    }

    #[test]
    fn smb2_detect() {
        let mut pkt = vec![0x00, 0x00, 0x00, 0x40, 0xfe];
        pkt.extend_from_slice(b"SMB");
        pkt.extend_from_slice(&[0u8; 4]);
        let mut m = meta_ports(40000, 445);
        smb(&pkt, &mut m);
        assert_eq!(m.smb_dialect, Some("smb2"));
    }

    #[test]
    fn syslog_pri() {
        let mut m = meta_ports(40000, 514);
        assert!(syslog(b"<34>Oct 11 22:14:15 host msg", &mut m));
        assert_eq!(m.syslog_facility, Some(4));
        assert_eq!(m.syslog_severity, Some(2));
    }
}
