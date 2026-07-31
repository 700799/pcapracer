//! DNS, and its mDNS/LLMNR variants.

use crate::bytes::{cap, entropy, Cur};
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

pub fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        59 => "CDS",
        60 => "CDNSKEY",
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

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "OTHER",
    }
}

/// Decode a (possibly compressed) DNS name starting at `pos` within `msg`.
///
/// Returns the name and the offset just past the name *in the original record*, which is not
/// the same as where decoding ended once a compression pointer has been followed.
fn read_name(msg: &[u8], mut pos: usize) -> DResult<(String, usize)> {
    let mut out = String::new();
    let mut end_pos: Option<usize> = None;
    // Compression pointers can chain, and a crafted message can point them in a cycle.
    // Bounding the jumps is what makes this loop terminate on hostile input.
    let mut jumps = 0;
    let mut guard = 0;

    loop {
        guard += 1;
        if guard > 128 {
            return Err(DissectError::Malformed);
        }
        if pos >= msg.len() {
            return Err(DissectError::Truncated);
        }
        let len = msg[pos];

        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Pointer: the low 14 bits are an offset from the start of the message.
            if pos + 1 >= msg.len() {
                return Err(DissectError::Truncated);
            }
            let target = (((len & 0x3f) as usize) << 8) | msg[pos + 1] as usize;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 || target >= msg.len() {
                return Err(DissectError::Malformed);
            }
            pos = target;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(DissectError::Malformed); // reserved label type
        }

        let start = pos + 1;
        let stop = start + len as usize;
        if stop > msg.len() {
            return Err(DissectError::Truncated);
        }
        if !out.is_empty() {
            out.push('.');
        }
        // Label bytes are arbitrary octets; render them printable so the column stays clean.
        for &b in &msg[start..stop] {
            if (0x20..0x7f).contains(&b) {
                out.push(b as char);
            } else {
                out.push('?');
            }
        }
        pos = stop;
        if out.len() > 512 {
            return Err(DissectError::Malformed);
        }
    }

    Ok((out, end_pos.unwrap_or(pos)))
}

pub fn parse(
    msg: &[u8],
    ctx: &mut Ctx,
    is_mdns: bool,
    is_llmnr: bool,
    over_tcp: bool,
) -> DResult<()> {
    ctx.layer(if is_mdns {
        "mdns"
    } else if is_llmnr {
        "llmnr"
    } else {
        "dns"
    });
    ctx.pkt.dns_is_mdns = Some(is_mdns);
    ctx.pkt.dns_is_llmnr = Some(is_llmnr);
    ctx.pkt.dns_over_tcp = Some(over_tcp);

    let mut c = Cur::new(msg);
    let txid = c.be16()?;
    let flags = c.be16()?;
    let qdcount = c.be16()?;
    let ancount = c.be16()?;
    let nscount = c.be16()?;
    let arcount = c.be16()?;

    ctx.pkt.dns_transaction_id = Some(txid);
    ctx.pkt.dns_flags = Some(flags);
    ctx.pkt.dns_is_response = Some(flags & 0x8000 != 0);
    ctx.pkt.dns_opcode = Some(((flags >> 11) & 0xf) as u8);
    let rcode = (flags & 0xf) as u8;
    ctx.pkt.dns_rcode = Some(rcode);
    ctx.pkt.dns_rcode_name = Some(rcode_name(rcode).to_string());
    ctx.pkt.dns_flag_aa = Some(flags & 0x0400 != 0);
    ctx.pkt.dns_flag_tc = Some(flags & 0x0200 != 0);
    ctx.pkt.dns_flag_rd = Some(flags & 0x0100 != 0);
    ctx.pkt.dns_flag_ra = Some(flags & 0x0080 != 0);
    ctx.pkt.dns_qdcount = Some(qdcount);
    ctx.pkt.dns_ancount = Some(ancount);
    ctx.pkt.dns_nscount = Some(nscount);
    ctx.pkt.dns_arcount = Some(arcount);

    let mut pos = 12;

    // Questions. The first one populates the scalar qname columns, which is what analysts
    // group by; multi-question messages are vanishingly rare outside of test traffic.
    for i in 0..qdcount.min(8) {
        let (name, next) = read_name(msg, pos)?;
        pos = next;
        if pos + 4 > msg.len() {
            return Err(DissectError::Truncated);
        }
        let qtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let qclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        pos += 4;
        if i == 0 {
            ctx.pkt.dns_qname_len = Some(name.len() as u32);
            // Entropy over the queried name is the standard first-pass signal for DGA and
            // DNS-tunnelling traffic, so it is computed here rather than left to the analyst.
            ctx.pkt.dns_qname_entropy = Some(entropy(name.as_bytes()));
            ctx.pkt.dns_tld = name.rsplit('.').next().map(|s| s.to_string());
            ctx.pkt.dns_qname = Some(name);
            ctx.pkt.dns_qtype = Some(qtype);
            ctx.pkt.dns_qtype_name = Some(qtype_name(qtype).to_string());
            ctx.pkt.dns_qclass = Some(qclass);
        }
    }

    // Answers.
    let mut answers: Vec<String> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    let mut cnames: Vec<String> = Vec::new();
    let mut ns_names: Vec<String> = Vec::new();
    let mut mx_names: Vec<String> = Vec::new();
    let mut txts: Vec<String> = Vec::new();
    let mut ttl_min: Option<u32> = None;

    let total_rr = (ancount as usize + nscount as usize + arcount as usize).min(64);
    for _ in 0..total_rr {
        let (name, next) = match read_name(msg, pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = next;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            break;
        }
        let rdata = &msg[pos..pos + rdlen];

        // OPT (EDNS0) is pseudo-RR metadata, not an answer; its "TTL" is flags.
        if rtype != 41 {
            ttl_min = Some(ttl_min.map_or(ttl, |m: u32| m.min(ttl)));
        }

        match rtype {
            1 if rdlen == 4 => {
                let ip =
                    std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string();
                answers.push(format!("{name} A {ip}"));
                ips.push(ip);
            }
            28 if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                let ip = std::net::Ipv6Addr::from(o).to_string();
                answers.push(format!("{name} AAAA {ip}"));
                ips.push(ip);
            }
            5 => {
                if let Ok((target, _)) = read_name(msg, pos) {
                    answers.push(format!("{name} CNAME {target}"));
                    cnames.push(target);
                }
            }
            2 => {
                if let Ok((target, _)) = read_name(msg, pos) {
                    answers.push(format!("{name} NS {target}"));
                    ns_names.push(target);
                }
            }
            12 => {
                if let Ok((target, _)) = read_name(msg, pos) {
                    answers.push(format!("{name} PTR {target}"));
                }
            }
            15 => {
                if rdlen > 2 {
                    if let Ok((target, _)) = read_name(msg, pos + 2) {
                        answers.push(format!("{name} MX {target}"));
                        mx_names.push(target);
                    }
                }
            }
            16 => {
                // TXT rdata is a sequence of length-prefixed strings.
                let mut tc = Cur::new(rdata);
                while let Ok(l) = tc.u8() {
                    match tc.take(l as usize) {
                        Ok(s) => txts.push(String::from_utf8_lossy(s).to_string()),
                        Err(_) => break,
                    }
                }
            }
            33 if rdlen > 6 => {
                if let Ok((target, _)) = read_name(msg, pos + 6) {
                    answers.push(format!("{name} SRV {target}"));
                }
            }
            _ => {}
        }
        pos += rdlen;
    }

    if !answers.is_empty() {
        ctx.pkt.dns_answers = Some(cap(answers.join("; "), 2048));
    }
    if !ips.is_empty() {
        ctx.pkt.dns_answer_ips = Some(cap(ips.join(","), 1024));
    }
    if !cnames.is_empty() {
        ctx.pkt.dns_cnames = Some(cap(cnames.join(","), 1024));
    }
    if !ns_names.is_empty() {
        ctx.pkt.dns_ns_names = Some(cap(ns_names.join(","), 512));
    }
    if !mx_names.is_empty() {
        ctx.pkt.dns_mx_names = Some(cap(mx_names.join(","), 512));
    }
    if !txts.is_empty() {
        ctx.pkt.dns_txt_data = Some(cap(txts.join(" | "), 2048));
    }
    ctx.pkt.dns_ttl_min = ttl_min;
    Ok(())
}

/// DNS over TCP is preceded by a two-byte length.
pub fn parse_tcp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    let mut c = Cur::new(payload);
    let len = c.be16()? as usize;
    let msg = c.take(len.min(c.remaining()))?;
    parse(msg, ctx, false, false, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    /// A query for www.example.com, type A.
    fn query() -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&[3, b'w', b'w', b'w', 7]);
        v.extend_from_slice(b"example");
        v.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        v.extend_from_slice(&[0, 1, 0, 1]);
        v
    }

    fn run(msg: &[u8]) -> (Packet, Result<(), DissectError>) {
        let mut p = Packet::default();
        let r = {
            let mut ctx = Ctx::new(&mut p);
            parse(msg, &mut ctx, false, false, false)
        };
        (p, r)
    }

    #[test]
    fn parses_a_query() {
        let (p, r) = run(&query());
        r.unwrap();
        assert_eq!(p.dns_qname.as_deref(), Some("www.example.com"));
        assert_eq!(p.dns_qtype_name.as_deref(), Some("A"));
        assert_eq!(p.dns_is_response, Some(false));
        assert_eq!(p.dns_tld.as_deref(), Some("com"));
        assert!(p.dns_qname_entropy.unwrap() > 2.0);
    }

    #[test]
    fn parses_a_response_with_compression() {
        let mut v = query();
        v[2] = 0x81; // QR + RD
        v[3] = 0x80; // RA
        v[7] = 1; // ancount
                  // Answer: pointer to offset 12, type A, TTL 300, 93.184.216.34
        v.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34,
        ]);

        let (p, r) = run(&v);
        r.unwrap();
        assert_eq!(p.dns_is_response, Some(true));
        assert_eq!(p.dns_answer_ips.as_deref(), Some("93.184.216.34"));
        assert_eq!(p.dns_ttl_min, Some(300));
        assert_eq!(p.dns_rcode_name.as_deref(), Some("NOERROR"));
    }

    #[test]
    fn compression_pointer_loop_terminates() {
        // A name that is a pointer to itself.
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&[0xc0, 0x0c]); // points back at offset 12, i.e. itself
        v.extend_from_slice(&[0, 1, 0, 1]);
        let (_, r) = run(&v);
        assert_eq!(r, Err(DissectError::Malformed));
    }

    #[test]
    fn pointer_past_end_of_message_is_rejected() {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&[0xc0, 0xff]);
        v.extend_from_slice(&[0, 1, 0, 1]);
        let (_, r) = run(&v);
        assert!(r.is_err());
    }

    #[test]
    fn truncated_messages_never_panic() {
        let full = query();
        for n in 0..full.len() {
            let _ = run(&full[..n]);
        }
    }
}
