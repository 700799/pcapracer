//! TLS handshake parsing over a reassembled TCP byte stream.
//!
//! Extracts ClientHello / ServerHello / Certificate messages and computes
//! JA3, JA3S and JA4 fingerprints. Never panics on malformed input.

use super::fingerprint::{self, ClientHelloInfo, ServerHelloInfo};
use super::AppCtx;
use crate::schema::tls::TlsRow;
use std::fmt::Write as _;

const MAX_HS_BYTES: usize = 65_536;

#[allow(clippy::large_enum_variant)]
pub enum TlsOutcome {
    Rows(Vec<TlsRow>),
    NeedMore,
    NotTls,
}

/// Attempt to parse TLS handshake messages from the (in-order) byte stream.
pub fn parse_stream(buf: &[u8], ctx: &AppCtx) -> TlsOutcome {
    if buf.is_empty() {
        return TlsOutcome::NeedMore;
    }
    // First byte must be a TLS content type; handshake is 0x16.
    if buf[0] != 0x16 {
        return TlsOutcome::NotTls;
    }

    let record_version = if buf.len() >= 3 {
        Some(u16::from_be_bytes([buf[1], buf[2]]))
    } else {
        None
    };

    // Assemble contiguous handshake record payloads.
    let mut hs = Vec::new();
    let mut pos = 0usize;
    let mut incomplete = false;
    while pos + 5 <= buf.len() {
        let ctype = buf[pos];
        if ctype != 0x16 {
            break; // end of the handshake flight
        }
        let rlen = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let rstart = pos + 5;
        let rend = rstart + rlen;
        if rend > buf.len() {
            incomplete = true;
            break;
        }
        hs.extend_from_slice(&buf[rstart..rend]);
        if hs.len() > MAX_HS_BYTES {
            break;
        }
        pos = rend;
    }
    if pos + 5 > buf.len() && hs.is_empty() {
        return TlsOutcome::NeedMore;
    }

    // Parse handshake messages from the assembled bytes.
    let mut rows = Vec::new();
    let mut hp = 0usize;
    let mut parsed_any = false;
    while hp + 4 <= hs.len() {
        let msg_type = hs[hp];
        let mlen =
            ((hs[hp + 1] as usize) << 16) | ((hs[hp + 2] as usize) << 8) | hs[hp + 3] as usize;
        let mstart = hp + 4;
        let mend = mstart + mlen;
        if mend > hs.len() {
            break; // message incomplete
        }
        let body = &hs[mstart..mend];
        match msg_type {
            1 => {
                if let Some(row) = parse_client_hello(body, record_version, ctx) {
                    rows.push(row);
                    parsed_any = true;
                }
            }
            2 => {
                if let Some(row) = parse_server_hello(body, record_version, ctx) {
                    rows.push(row);
                    parsed_any = true;
                }
            }
            11 => {
                if let Some(row) = parse_certificate(body, ctx) {
                    rows.push(row);
                    parsed_any = true;
                }
            }
            _ => {}
        }
        hp = mend;
    }

    if parsed_any {
        TlsOutcome::Rows(rows)
    } else if incomplete || hp + 4 > hs.len() {
        TlsOutcome::NeedMore
    } else {
        TlsOutcome::NotTls
    }
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn dash_u16(vals: &[u16]) -> String {
    let mut s = String::new();
    for &v in vals {
        if !s.is_empty() {
            s.push('-');
        }
        let _ = write!(s, "{v}");
    }
    s
}

fn dash_u8(vals: &[u8]) -> String {
    let mut s = String::new();
    for &v in vals {
        if !s.is_empty() {
            s.push('-');
        }
        let _ = write!(s, "{v}");
    }
    s
}

fn parse_client_hello(body: &[u8], record_version: Option<u16>, ctx: &AppCtx) -> Option<TlsRow> {
    // version(2) + random(32)
    let mut ch = ClientHelloInfo {
        legacy_version: read_u16(body, 0)?,
        ..Default::default()
    };
    let mut p = 2 + 32;
    // session id
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    // cipher suites
    let cs_len = read_u16(body, p)? as usize;
    p += 2;
    let cs_end = p + cs_len;
    while p + 2 <= cs_end && p + 2 <= body.len() {
        ch.ciphers.push(read_u16(body, p)?);
        p += 2;
    }
    p = cs_end;
    // compression methods
    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;
    // extensions
    if let Some(ext_total) = read_u16(body, p) {
        p += 2;
        let ext_end = (p + ext_total as usize).min(body.len());
        parse_extensions(&body[p.min(body.len())..ext_end], &mut ch);
    }

    let (ja3_hex, ja3_raw) = fingerprint::ja3(&ch);
    let ja4 = fingerprint::ja4(&ch);
    let version_max = ch
        .supported_versions
        .iter()
        .copied()
        .filter(|&v| !fingerprint::is_grease(v))
        .max();
    let alpn = if ch.alpn.is_empty() {
        None
    } else {
        Some(ch.alpn.join(","))
    };

    Some(TlsRow {
        ts_ns: ctx.ts_ns,
        src_ip: Some(ctx.src_ip),
        dst_ip: Some(ctx.dst_ip),
        src_port: ctx.src_port,
        dst_port: ctx.dst_port,
        msg: "client_hello",
        record_version,
        legacy_version: Some(ch.legacy_version),
        version_max,
        sni: ch.sni.clone(),
        alpn,
        cipher_count: Some(
            ch.ciphers
                .iter()
                .filter(|&&v| !fingerprint::is_grease(v))
                .count() as u16,
        ),
        ciphers: Some(dash_u16(&ch.ciphers)),
        extensions: Some(dash_u16(&ch.extensions)),
        groups: Some(dash_u16(&ch.groups)),
        ec_point_formats: Some(dash_u8(&ch.ec_point_formats)),
        sig_algs: Some(dash_u16(&ch.sig_algs)),
        ja3: Some(ja3_hex),
        ja3_raw: Some(ja3_raw),
        ja4: Some(ja4),
        ..Default::default()
    })
}

fn parse_extensions(data: &[u8], ch: &mut ClientHelloInfo) {
    let mut p = 0usize;
    while p + 4 <= data.len() {
        let etype = u16::from_be_bytes([data[p], data[p + 1]]);
        let elen = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        let estart = p + 4;
        let eend = estart + elen;
        if eend > data.len() {
            break;
        }
        let ed = &data[estart..eend];
        ch.extensions.push(etype);
        match etype {
            0x0000 => {
                // SNI: list_len(2), entry: type(1) + name_len(2) + name
                if ed.len() >= 5 {
                    let ntype = ed[2];
                    let nlen = u16::from_be_bytes([ed[3], ed[4]]) as usize;
                    if ntype == 0 && 5 + nlen <= ed.len() {
                        if let Ok(s) = std::str::from_utf8(&ed[5..5 + nlen]) {
                            ch.sni = Some(s.to_string());
                        }
                    }
                }
            }
            0x0010 => {
                // ALPN: list_len(2), then proto: len(1)+bytes
                let mut q = 2usize;
                while q < ed.len() {
                    let l = ed[q] as usize;
                    if q + 1 + l > ed.len() {
                        break;
                    }
                    if let Ok(s) = std::str::from_utf8(&ed[q + 1..q + 1 + l]) {
                        ch.alpn.push(s.to_string());
                    }
                    q += 1 + l;
                }
            }
            0x000a => {
                // supported groups: list_len(2) + u16 list
                let mut q = 2usize;
                while q + 2 <= ed.len() {
                    ch.groups.push(u16::from_be_bytes([ed[q], ed[q + 1]]));
                    q += 2;
                }
            }
            // ec point formats: len(1) + u8 list
            0x000b if !ed.is_empty() => {
                let l = ed[0] as usize;
                for &b in ed.iter().skip(1).take(l) {
                    ch.ec_point_formats.push(b);
                }
            }
            0x000d => {
                // signature algorithms: list_len(2) + u16 list
                let mut q = 2usize;
                while q + 2 <= ed.len() {
                    ch.sig_algs.push(u16::from_be_bytes([ed[q], ed[q + 1]]));
                    q += 2;
                }
            }
            // supported versions: len(1) + u16 list
            0x002b if !ed.is_empty() => {
                let l = ed[0] as usize;
                let mut q = 1usize;
                while q + 2 <= (1 + l).min(ed.len()) {
                    ch.supported_versions
                        .push(u16::from_be_bytes([ed[q], ed[q + 1]]));
                    q += 2;
                }
            }
            _ => {}
        }
        p = eend;
    }
}

fn parse_server_hello(body: &[u8], record_version: Option<u16>, ctx: &AppCtx) -> Option<TlsRow> {
    let mut sh = ServerHelloInfo {
        version: read_u16(body, 0)?,
        ..Default::default()
    };
    let mut p = 2 + 32;
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    sh.cipher = read_u16(body, p)?;
    p += 2;
    // compression(1)
    p += 1;
    let mut version_max = None;
    if let Some(ext_total) = read_u16(body, p) {
        p += 2;
        let ext_end = (p + ext_total as usize).min(body.len());
        let mut q = p.min(body.len());
        while q + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[q], body[q + 1]]);
            let elen = u16::from_be_bytes([body[q + 2], body[q + 3]]) as usize;
            sh.extensions.push(etype);
            // supported_versions in ServerHello carries the negotiated version
            if etype == 0x002b && q + 4 + 2 <= body.len() {
                version_max = Some(u16::from_be_bytes([body[q + 4], body[q + 5]]));
            }
            q += 4 + elen;
        }
    }

    let (ja3s_hex, ja3s_raw) = fingerprint::ja3s(&sh);
    Some(TlsRow {
        ts_ns: ctx.ts_ns,
        src_ip: Some(ctx.src_ip),
        dst_ip: Some(ctx.dst_ip),
        src_port: ctx.src_port,
        dst_port: ctx.dst_port,
        msg: "server_hello",
        record_version,
        legacy_version: Some(sh.version),
        version_max,
        extensions: Some(dash_u16(&sh.extensions)),
        cipher: Some(sh.cipher),
        ja3s: Some(ja3s_hex),
        ja3s_raw: Some(ja3s_raw),
        ..Default::default()
    })
}

fn parse_certificate(body: &[u8], ctx: &AppCtx) -> Option<TlsRow> {
    // Try TLS 1.2 layout (cert_list_len:3) then TLS 1.3 (ctx_len:1 + list).
    let (leaf, chain_len) = extract_leaf(body)?;
    let mut row = TlsRow {
        ts_ns: ctx.ts_ns,
        src_ip: Some(ctx.src_ip),
        dst_ip: Some(ctx.dst_ip),
        src_port: ctx.src_port,
        dst_port: ctx.dst_port,
        msg: "certificate",
        cert_chain_len: Some(chain_len),
        ..Default::default()
    };
    fill_cert_fields(leaf, &mut row);
    Some(row)
}

fn u24(b: &[u8], off: usize) -> Option<usize> {
    b.get(off..off + 3)
        .map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
}

/// Locate the leaf certificate DER and count the chain. Handles both TLS 1.2
/// and 1.3 Certificate message layouts.
fn extract_leaf(body: &[u8]) -> Option<(&[u8], u8)> {
    // TLS 1.2: [list_len:3][ (cert_len:3)(der) ]*
    if let Some(list_len) = u24(body, 0) {
        if 3 + list_len <= body.len() + 1 {
            if let Some(res) = walk_certs(body, 3) {
                return Some(res);
            }
        }
    }
    // TLS 1.3: [ctx_len:1][ctx][list_len:3][ (cert_len:3)(der)(ext_len:2)(ext) ]*
    let ctx_len = *body.first()? as usize;
    let start = 1 + ctx_len + 3;
    if start <= body.len() {
        if let Some(res) = walk_certs_13(body, 1 + ctx_len) {
            return Some(res);
        }
    }
    None
}

fn walk_certs(body: &[u8], mut p: usize) -> Option<(&[u8], u8)> {
    let mut count = 0u8;
    let mut leaf: Option<&[u8]> = None;
    while p + 3 <= body.len() {
        let clen = u24(body, p)?;
        let cstart = p + 3;
        let cend = cstart + clen;
        if cend > body.len() || clen == 0 {
            break;
        }
        if leaf.is_none() {
            leaf = Some(&body[cstart..cend]);
        }
        count = count.saturating_add(1);
        p = cend;
    }
    leaf.map(|l| (l, count))
}

fn walk_certs_13(body: &[u8], mut p: usize) -> Option<(&[u8], u8)> {
    // skip list_len(3)
    p += 3;
    let mut count = 0u8;
    let mut leaf: Option<&[u8]> = None;
    while p + 3 <= body.len() {
        let clen = u24(body, p)?;
        let cstart = p + 3;
        let cend = cstart + clen;
        if cend > body.len() || clen == 0 {
            break;
        }
        if leaf.is_none() {
            leaf = Some(&body[cstart..cend]);
        }
        count = count.saturating_add(1);
        // cert extensions
        let ext_len = read_u16(body, cend)? as usize;
        p = cend + 2 + ext_len;
    }
    leaf.map(|l| (l, count))
}

fn fill_cert_fields(der: &[u8], row: &mut TlsRow) {
    use x509_parser::prelude::*;
    if let Ok((_, cert)) = X509Certificate::from_der(der) {
        row.cert_subject = Some(cert.subject().to_string());
        row.cert_issuer = Some(cert.issuer().to_string());
        row.cert_not_before = Some(cert.validity().not_before.timestamp() * 1_000_000_000);
        row.cert_not_after = Some(cert.validity().not_after.timestamp() * 1_000_000_000);
        row.cert_serial = Some(cert.raw_serial_as_string());
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            let mut names = Vec::new();
            for gn in &san.value.general_names {
                if let GeneralName::DNSName(d) = gn {
                    names.push(d.to_string());
                }
            }
            if !names.is_empty() {
                row.cert_san = Some(names.into_iter().take(10).collect::<Vec<_>>().join(","));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::IpRepr;

    fn ctx() -> AppCtx {
        AppCtx {
            ts_ns: 0,
            src_ip: IpRepr::V4([1, 2, 3, 4]),
            dst_ip: IpRepr::V4([5, 6, 7, 8]),
            src_port: 12345,
            dst_port: 443,
        }
    }

    fn wrap_record(handshake: &[u8]) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01];
        v.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        v.extend_from_slice(handshake);
        v
    }

    fn client_hello() -> Vec<u8> {
        // handshake: type 1, len(3), body
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&[0, 4]); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]); // two ciphers
        body.extend_from_slice(&[1, 0]); // compression
                                         // extensions
        let mut ext = Vec::new();
        // SNI ext type 0
        let host = b"example.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
        sni.push(0); // name type host
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![1];
        hs.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn parse_ch_full_record() {
        let rec = wrap_record(&client_hello());
        match parse_stream(&rec, &ctx()) {
            TlsOutcome::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].msg, "client_hello");
                assert_eq!(rows[0].sni.as_deref(), Some("example.com"));
                assert!(rows[0].ja3.is_some());
                assert!(rows[0].ja4.as_ref().unwrap().starts_with("t12d"));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn split_client_hello_needs_more_then_parses() {
        let rec = wrap_record(&client_hello());
        let split = rec.len() / 2;
        // First half is incomplete.
        assert!(matches!(
            parse_stream(&rec[..split], &ctx()),
            TlsOutcome::NeedMore
        ));
        // Whole record parses.
        assert!(matches!(parse_stream(&rec, &ctx()), TlsOutcome::Rows(_)));
    }

    #[test]
    fn non_tls_rejected() {
        assert!(matches!(
            parse_stream(b"GET / HTTP/1.1\r\n", &ctx()),
            TlsOutcome::NotTls
        ));
    }
}
