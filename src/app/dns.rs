//! DNS-family message parser (DNS, mDNS, LLMNR, NBNS) with hardened
//! name decompression. Never panics on malformed input.

use crate::decode::PacketMeta;
use crate::schema::dns::{DnsAnswer, DnsRow};
use crate::util::{write_hex, write_ipv4, write_ipv6};
use std::fmt::Write as _;

const MAX_ANSWERS: usize = 32;
const MAX_JUMPS: u32 = 16;

/// Parse a DNS-family message. Fills inline `meta` summary fields and returns a
/// full row for the `dns` table. Returns None if it isn't a plausible message.
pub fn parse(
    payload: &[u8],
    service: &'static str,
    meta: &mut PacketMeta,
    ts_ns: i64,
) -> Option<DnsRow> {
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qd = u16::from_be_bytes([payload[4], payload[5]]);
    let an = u16::from_be_bytes([payload[6], payload[7]]);
    let ns = u16::from_be_bytes([payload[8], payload[9]]);
    let ar = u16::from_be_bytes([payload[10], payload[11]]);

    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let rcode = (flags & 0x000f) as u8;

    // Reject obviously non-DNS traffic: opcode must be a known value and the
    // question/answer counts shouldn't be absurd for the payload size.
    if opcode > 6 {
        return None;
    }
    let max_records = payload.len() as u32; // 1 record needs >= a few bytes
    if qd as u32 + an as u32 + ns as u32 + ar as u32 > max_records {
        return None;
    }

    let mut pos = 12usize;

    let mut qname = None;
    let mut qtype = None;
    let mut qclass = None;
    if qd >= 1 {
        if let Some((name, next)) = read_name(payload, pos) {
            let qt = u16::from_be_bytes([*payload.get(next)?, *payload.get(next + 1)?]);
            let qc = u16::from_be_bytes([*payload.get(next + 2)?, *payload.get(next + 3)?]);
            qname = Some(name);
            qtype = Some(qt);
            qclass = Some(qc);
            pos = next + 4;
        } else {
            return None;
        }
    }

    // Skip remaining questions.
    for _ in 1..qd {
        match skip_name(payload, pos) {
            Some(next) if next + 4 <= payload.len() => pos = next + 4,
            _ => break,
        }
    }

    // Parse answer + authority + additional records (capped).
    let total_rr = an as usize + ns as usize + ar as usize;
    let mut answers = Vec::new();
    for _ in 0..total_rr.min(MAX_ANSWERS * 2) {
        if answers.len() >= MAX_ANSWERS {
            break;
        }
        let (name, next) = match read_name(payload, pos) {
            Some(v) => v,
            None => break,
        };
        let rtype = match be16(payload, next) {
            Some(v) => v,
            None => break,
        };
        let _class = be16(payload, next + 2);
        let ttl = match be32(payload, next + 4) {
            Some(v) => v,
            None => break,
        };
        let rdlen = match be16(payload, next + 8) {
            Some(v) => v as usize,
            None => break,
        };
        let rdstart = next + 10;
        let rdend = rdstart + rdlen;
        if rdend > payload.len() {
            break;
        }
        // OPT records (type 41) are EDNS metadata, not real answers.
        if rtype != 41 {
            let rdata = render_rdata(payload, rtype, rdstart, rdend);
            answers.push(DnsAnswer {
                name,
                rtype,
                ttl,
                rdata,
            });
        }
        pos = rdend;
    }

    // Inline packet summary fields.
    meta.app_proto = Some(service);
    meta.dns_is_response = Some(is_response);
    if let Some(ref q) = qname {
        meta.dns_qname = Some(q.clone());
    }
    meta.dns_qtype = qtype;

    Some(DnsRow {
        ts_ns,
        src_ip: meta.src_ip?,
        dst_ip: meta.dst_ip?,
        src_port: meta.src_port.unwrap_or(0),
        dst_port: meta.dst_port.unwrap_or(0),
        proto: meta.ip_proto.unwrap_or(0),
        service,
        id,
        is_response,
        opcode,
        rcode,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        rd: flags & 0x0100 != 0,
        ra: flags & 0x0080 != 0,
        ad: flags & 0x0020 != 0,
        cd: flags & 0x0010 != 0,
        qdcount: qd,
        ancount: an,
        nscount: ns,
        arcount: ar,
        qtype_name: qtype.map(qtype_name),
        qname,
        qtype,
        qclass,
        answers,
    })
}

#[inline]
fn be16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

#[inline]
fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a (possibly compressed) domain name; returns (name, position after the
/// name in the primary stream).
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut jumps = 0u32;
    loop {
        let len = *msg.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let b2 = *msg.get(pos + 1)?;
            let ptr = ((len as usize & 0x3f) << 8) | b2 as usize;
            if after.is_none() {
                after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_JUMPS || ptr >= msg.len() {
                return None;
            }
            pos = ptr;
        } else if len == 0 {
            if after.is_none() {
                after = Some(pos + 1);
            }
            break;
        } else {
            let l = len as usize;
            let label = msg.get(pos + 1..pos + 1 + l)?;
            if !name.is_empty() {
                name.push('.');
            }
            for &b in label {
                name.push(if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '?'
                });
            }
            pos += 1 + l;
            if name.len() > 255 {
                return None;
            }
        }
    }
    Some((name, after.unwrap_or(pos)))
}

/// Skip over a name, returning the position after it.
fn skip_name(msg: &[u8], start: usize) -> Option<usize> {
    read_name(msg, start).map(|(_, next)| next)
}

fn render_rdata(msg: &[u8], rtype: u16, start: usize, end: usize) -> String {
    let rd = &msg[start..end];
    let mut s = String::new();
    match rtype {
        1 if rd.len() == 4 => write_ipv4(&mut s, [rd[0], rd[1], rd[2], rd[3]]),
        28 if rd.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rd);
            write_ipv6(&mut s, o);
        }
        2 | 5 | 12 => {
            // NS / CNAME / PTR: a domain name (possibly compressed within msg)
            if let Some((n, _)) = read_name(msg, start) {
                s = n;
            } else {
                write_hex(&mut s, &rd[..rd.len().min(64)]);
            }
        }
        15 => {
            // MX: preference (2) + exchange name
            if rd.len() >= 3 {
                let pref = u16::from_be_bytes([rd[0], rd[1]]);
                let name = read_name(msg, start + 2)
                    .map(|(n, _)| n)
                    .unwrap_or_default();
                let _ = write!(s, "{pref} {name}");
            }
        }
        16 => {
            // TXT: one or more length-prefixed strings
            let mut i = 0;
            while i < rd.len() {
                let l = rd[i] as usize;
                if i + 1 + l > rd.len() {
                    break;
                }
                if !s.is_empty() {
                    s.push(' ');
                }
                for &b in &rd[i + 1..i + 1 + l] {
                    s.push(if (0x20..=0x7e).contains(&b) {
                        b as char
                    } else {
                        '.'
                    });
                }
                i += 1 + l;
            }
        }
        _ => {
            write_hex(&mut s, &rd[..rd.len().min(64)]);
        }
    }
    s
}

pub fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        52 => "TLSA",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::field_reassign_with_default)]
    fn meta() -> PacketMeta {
        let mut m = PacketMeta::default();
        m.src_ip = Some(crate::util::IpRepr::V4([1, 2, 3, 4]));
        m.dst_ip = Some(crate::util::IpRepr::V4([5, 6, 7, 8]));
        m.src_port = Some(1234);
        m.dst_port = Some(53);
        m.ip_proto = Some(17);
        m
    }

    #[test]
    fn parse_query() {
        // id=0x1234, flags=0x0100 (RD), qd=1, name=example.com A IN
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&[7]);
        p.extend_from_slice(b"example");
        p.extend_from_slice(&[3]);
        p.extend_from_slice(b"com");
        p.push(0);
        p.extend_from_slice(&[0, 1, 0, 1]); // A IN
        let mut m = meta();
        let row = parse(&p, "dns", &mut m, 0).unwrap();
        assert_eq!(row.qname.as_deref(), Some("example.com"));
        assert_eq!(row.qtype, Some(1));
        assert!(!row.is_response);
        assert_eq!(m.dns_qname.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_response_with_compression() {
        // query example.com, answer A 93.184.216.34 with a compression pointer
        let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        // question at offset 12
        p.extend_from_slice(&[7]);
        p.extend_from_slice(b"example");
        p.extend_from_slice(&[3]);
        p.extend_from_slice(b"com");
        p.push(0);
        p.extend_from_slice(&[0, 1, 0, 1]);
        // answer: name = pointer to offset 12
        p.extend_from_slice(&[0xc0, 12]);
        p.extend_from_slice(&[0, 1, 0, 1]); // A IN
        p.extend_from_slice(&[0, 0, 1, 44]); // ttl 300
        p.extend_from_slice(&[0, 4]); // rdlen
        p.extend_from_slice(&[93, 184, 216, 34]);
        let mut m = meta();
        let row = parse(&p, "dns", &mut m, 0).unwrap();
        assert!(row.is_response);
        assert_eq!(row.answers.len(), 1);
        assert_eq!(row.answers[0].name, "example.com");
        assert_eq!(row.answers[0].rdata, "93.184.216.34");
        assert_eq!(row.answers[0].ttl, 300);
    }

    #[test]
    fn pointer_loop_does_not_hang() {
        // header + a name that is a pointer to itself (offset 12)
        let mut p = vec![0x00, 0x00, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend_from_slice(&[0xc0, 12]); // pointer to offset 12 (itself)
        p.extend_from_slice(&[0, 1, 0, 1]);
        let mut m = meta();
        // Must return (None or Some) without hanging.
        let _ = parse(&p, "dns", &mut m, 0);
    }
}
