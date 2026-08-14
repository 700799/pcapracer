//! TLS and DTLS handshakes, including certificate details and the JA3/JA4 fingerprints.

use crate::bytes::{ascii_string, cap, hex, Cur};
use crate::dissect::app::ber;
use crate::dissect::Ctx;
use crate::error::DResult;
use crate::fingerprint::{ja3, ja3s, ja4, ja4s, Ja3Input, Ja4Input};

pub fn version_name(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        0xfeff => "DTLS 1.0".into(),
        0xfefd => "DTLS 1.2".into(),
        0xfefc => "DTLS 1.3".into(),
        other => format!("0x{other:04x}"),
    }
}

fn handshake_type_name(t: u8) -> &'static str {
    match t {
        0 => "hello_request",
        1 => "client_hello",
        2 => "server_hello",
        4 => "new_session_ticket",
        8 => "encrypted_extensions",
        11 => "certificate",
        12 => "server_key_exchange",
        13 => "certificate_request",
        14 => "server_hello_done",
        15 => "certificate_verify",
        16 => "client_key_exchange",
        20 => "finished",
        _ => "unknown",
    }
}

/// Cheap shape check used by the sniffing fallback: a TLS record header is a known content
/// type followed by a plausible version.
pub fn looks_like_tls(d: &[u8]) -> bool {
    if d.len() < 3 {
        return false;
    }
    matches!(d[0], 20..=23) && d[1] == 0x03 && d[2] <= 0x04
}

pub fn looks_like_dtls(d: &[u8]) -> bool {
    d.len() >= 3 && matches!(d[0], 20..=23) && d[1] == 0xfe
}

pub fn parse(payload: &[u8], ctx: &mut Ctx, is_dtls: bool) -> DResult<()> {
    ctx.layer(if is_dtls { "dtls" } else { "tls" });
    ctx.pkt.tls_is_dtls = Some(is_dtls);

    let mut c = Cur::new(payload);
    let mut records = 0;

    // A single TCP segment can carry several records back to back.
    while c.remaining() >= 5 && records < 8 {
        records += 1;
        let rtype = c.u8()?;
        let rversion = c.be16()?;
        if is_dtls {
            c.skip(8)?; // epoch + sequence number
        }
        let len = c.be16()? as usize;

        if records == 1 {
            ctx.pkt.tls_record_type = Some(rtype);
            ctx.pkt.tls_record_version = Some(version_name(rversion));
        }

        let body = match c.take(len.min(c.remaining())) {
            Ok(b) => b,
            Err(_) => break,
        };

        match rtype {
            22 => {
                if handshake(body, ctx, is_dtls).is_err() {
                    break;
                }
            }
            21 => {
                let mut a = Cur::new(body);
                ctx.pkt.tls_alert_level = a.u8().ok();
                ctx.pkt.tls_alert_description = a.u8().ok();
            }
            // Application data is encrypted; there is nothing further to extract.
            23 | 20 => {}
            _ => break,
        }
    }
    Ok(())
}

fn handshake(body: &[u8], ctx: &mut Ctx, is_dtls: bool) -> DResult<()> {
    let mut c = Cur::new(body);
    let mut msgs = 0;
    while c.remaining() >= 4 && msgs < 8 {
        msgs += 1;
        let htype = c.u8()?;
        let hlen = c.be24()? as usize;
        if is_dtls {
            // message_seq, fragment_offset, fragment_length
            c.skip(8)?;
        }
        let msg = match c.take(hlen.min(c.remaining())) {
            Ok(m) => m,
            Err(_) => break,
        };

        if ctx.pkt.tls_handshake_type.is_none() {
            ctx.pkt.tls_handshake_type = Some(htype);
            ctx.pkt.tls_handshake_type_name = Some(handshake_type_name(htype).to_string());
        }

        match htype {
            1 => client_hello(msg, ctx, is_dtls)?,
            2 => server_hello(msg, ctx, is_dtls)?,
            11 => certificates(msg, ctx),
            _ => {}
        }
    }
    Ok(())
}

/// Extension values gathered while walking the extension block.
#[derive(Default)]
struct Exts {
    ids: Vec<u16>,
    sni: Option<String>,
    alpn: Vec<String>,
    groups: Vec<u16>,
    point_formats: Vec<u8>,
    sig_algs: Vec<u16>,
    supported_versions: Vec<u16>,
}

fn parse_extensions(c: &mut Cur) -> Exts {
    let mut e = Exts::default();
    let total = match c.be16() {
        Ok(t) => t as usize,
        Err(_) => return e,
    };
    let block = match c.take(total.min(c.remaining())) {
        Ok(b) => b,
        Err(_) => return e,
    };
    let mut ec = Cur::new(block);

    while ec.remaining() >= 4 {
        let id = match ec.be16() {
            Ok(v) => v,
            Err(_) => break,
        };
        let len = match ec.be16() {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        let data = match ec.take(len) {
            Ok(d) => d,
            Err(_) => break,
        };
        e.ids.push(id);
        let mut d = Cur::new(data);

        match id {
            0 => {
                // server_name: list of name entries, type 0 = host_name.
                if d.be16().is_ok() {
                    while d.remaining() >= 3 {
                        let ntype = match d.u8() {
                            Ok(t) => t,
                            Err(_) => break,
                        };
                        let nlen = match d.be16() {
                            Ok(l) => l as usize,
                            Err(_) => break,
                        };
                        match d.take(nlen) {
                            Ok(name) if ntype == 0 => {
                                e.sni = ascii_string(name);
                                break;
                            }
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                }
            }
            10 => {
                if let Ok(l) = d.be16() {
                    let mut g = Cur::new(d.take(l as usize).unwrap_or(&[]));
                    while let Ok(v) = g.be16() {
                        e.groups.push(v);
                    }
                }
            }
            11 => {
                if let Ok(l) = d.u8() {
                    if let Ok(pf) = d.take(l as usize) {
                        e.point_formats.extend_from_slice(pf);
                    }
                }
            }
            13 => {
                if let Ok(l) = d.be16() {
                    let mut s = Cur::new(d.take(l as usize).unwrap_or(&[]));
                    while let Ok(v) = s.be16() {
                        e.sig_algs.push(v);
                    }
                }
            }
            16 => {
                if d.be16().is_ok() {
                    while let Ok(l) = d.u8() {
                        match d.take(l as usize) {
                            Ok(p) => {
                                if let Some(s) = ascii_string(p) {
                                    e.alpn.push(s);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            43 => {
                // In a ClientHello this is a length-prefixed list; in a ServerHello it is a
                // single bare version. Distinguish by the declared length.
                if len == 2 {
                    if let Ok(v) = d.be16() {
                        e.supported_versions.push(v);
                    }
                } else if let Ok(l) = d.u8() {
                    let mut s = Cur::new(d.take(l as usize).unwrap_or(&[]));
                    while let Ok(v) = s.be16() {
                        e.supported_versions.push(v);
                    }
                }
            }
            _ => {}
        }
    }
    e
}

fn apply_exts(e: &Exts, ctx: &mut Ctx) {
    if !e.ids.is_empty() {
        ctx.pkt.tls_extension_count = Some(e.ids.len() as u16);
        ctx.pkt.tls_extensions = Some(
            e.ids
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(s) = &e.sni {
        ctx.pkt.tls_sni = Some(cap(s.clone(), 512));
    }
    if !e.alpn.is_empty() {
        ctx.pkt.tls_alpn = Some(e.alpn.join(","));
    }
    if !e.groups.is_empty() {
        ctx.pkt.tls_supported_groups = Some(
            e.groups
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !e.sig_algs.is_empty() {
        ctx.pkt.tls_sig_algs = Some(
            e.sig_algs
                .iter()
                .map(|x| format!("{:04x}", x))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !e.point_formats.is_empty() {
        ctx.pkt.tls_ec_point_formats = Some(
            e.point_formats
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !e.supported_versions.is_empty() {
        ctx.pkt.tls_supported_versions = Some(
            e.supported_versions
                .iter()
                .filter(|v| !crate::fingerprint::is_grease(**v))
                .map(|v| version_name(*v))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
}

/// The version a fingerprint should use: TLS 1.3 negotiates via `supported_versions` and
/// pins the legacy field at 1.2, so trusting the legacy field alone would label every 1.3
/// handshake as 1.2.
fn effective_version(legacy: u16, e: &Exts) -> u16 {
    e.supported_versions
        .iter()
        .copied()
        .filter(|v| !crate::fingerprint::is_grease(*v))
        .max()
        .unwrap_or(legacy)
}

fn client_hello(msg: &[u8], ctx: &mut Ctx, is_dtls: bool) -> DResult<()> {
    let mut c = Cur::new(msg);
    let legacy_version = c.be16()?;
    c.skip(32)?; // random

    let sid_len = c.u8()? as usize;
    ctx.pkt.tls_session_id_len = Some(sid_len as u16);
    c.skip(sid_len)?;

    if is_dtls {
        let cookie_len = c.u8()? as usize;
        c.skip(cookie_len)?;
    }

    let cs_len = c.be16()? as usize;
    let cs_bytes = c.take(cs_len)?;
    let mut ciphers: Vec<u16> = Vec::with_capacity(cs_len / 2);
    for ch in cs_bytes.chunks_exact(2) {
        ciphers.push(u16::from_be_bytes([ch[0], ch[1]]));
    }

    let comp_len = c.u8()? as usize;
    let comps = c.take(comp_len)?;
    ctx.pkt.tls_compression_methods = Some(
        comps
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );

    let e = parse_extensions(&mut c);
    let version = effective_version(legacy_version, &e);

    ctx.pkt.tls_version = Some(version_name(version));
    ctx.pkt.tls_cipher_suite_count = Some(ciphers.len() as u16);
    ctx.pkt.tls_cipher_suites = Some(cap(
        ciphers
            .iter()
            .map(|x| format!("{:04x}", x))
            .collect::<Vec<_>>()
            .join(","),
        1024,
    ));
    apply_exts(&e, ctx);

    let (h, full) = ja3(&Ja3Input {
        // JA3 is defined against the legacy version field, not the negotiated one.
        version: legacy_version,
        ciphers: &ciphers,
        extensions: &e.ids,
        curves: &e.groups,
        point_formats: &e.point_formats,
    });
    ctx.pkt.ja3 = Some(h);
    ctx.pkt.ja3_full = Some(cap(full, 2048));

    ctx.pkt.ja4 = Some(ja4(&Ja4Input {
        version,
        is_quic: false,
        has_sni: e.sni.is_some(),
        ciphers: &ciphers,
        extensions: &e.ids,
        sig_algs: &e.sig_algs,
        alpn: e.alpn.first().map(|s| s.as_str()),
    }));
    Ok(())
}

fn server_hello(msg: &[u8], ctx: &mut Ctx, _is_dtls: bool) -> DResult<()> {
    let mut c = Cur::new(msg);
    let legacy_version = c.be16()?;
    c.skip(32)?;
    let sid_len = c.u8()? as usize;
    c.skip(sid_len)?;
    let cipher = c.be16()?;
    let _comp = c.u8()?;

    let e = parse_extensions(&mut c);
    let version = effective_version(legacy_version, &e);

    ctx.pkt.tls_version = Some(version_name(version));
    ctx.pkt.tls_cipher_selected = Some(format!("{:04x}", cipher));
    apply_exts(&e, ctx);

    let (h, full) = ja3s(legacy_version, cipher, &e.ids);
    ctx.pkt.ja3s = Some(h);
    ctx.pkt.ja3s_full = Some(cap(full, 1024));
    ctx.pkt.ja4s = Some(ja4s(
        version,
        false,
        cipher,
        &e.ids,
        e.alpn.first().map(|s| s.as_str()),
    ));
    Ok(())
}

fn certificates(msg: &[u8], ctx: &mut Ctx) {
    let mut c = Cur::new(msg);
    let total = match c.be24() {
        Ok(t) => t as usize,
        Err(_) => return,
    };
    let mut list = Cur::new(c.take(total.min(c.remaining())).unwrap_or(&[]));

    let mut count = 0u8;
    let mut first: Option<&[u8]> = None;
    while list.remaining() > 3 && count < 16 {
        let len = match list.be24() {
            Ok(l) => l as usize,
            Err(_) => break,
        };
        match list.take(len) {
            Ok(der) => {
                if first.is_none() {
                    first = Some(der);
                }
                count += 1;
            }
            Err(_) => break,
        }
    }
    ctx.pkt.tls_cert_chain_len = Some(count);
    // Only the leaf is described: it carries the identity being asserted, and the chain
    // above it is usually a well-known CA that adds nothing per-connection.
    if let Some(der) = first {
        parse_certificate(der, ctx);
    }
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// Pull the analyst-relevant fields out of a DER certificate.
///
/// Deliberately partial: a full X.509 parser is a large attack surface, and subject, issuer,
/// SANs, serial and validity are what actually get pivoted on.
fn parse_certificate(der: &[u8], ctx: &mut Ctx) {
    let mut c = Cur::new(der);
    let cert = match ber::read_in(&mut c) {
        Ok(t) if t.constructed => t,
        _ => return,
    };
    let mut cc = cert.cur();
    let tbs = match ber::read_in(&mut cc) {
        Ok(t) if t.constructed => t,
        _ => return,
    };
    let mut t = tbs.cur();

    // The version is an optional [0]-tagged field; when absent the serial comes first.
    let mut next = match ber::read_in(&mut t) {
        Ok(v) => v,
        Err(_) => return,
    };
    if next.class == ber::CLASS_CONTEXT && next.tag == 0 {
        next = match ber::read_in(&mut t) {
            Ok(v) => v,
            Err(_) => return,
        };
    }
    ctx.pkt.tls_cert_serial = Some(hex(next.val));

    // signature AlgorithmIdentifier, then issuer / validity / subject in order.
    if ber::read_in(&mut t).is_err() {
        return;
    }
    let issuer = match ber::read_in(&mut t) {
        Ok(v) => v,
        Err(_) => return,
    };
    let validity = match ber::read_in(&mut t) {
        Ok(v) => v,
        Err(_) => return,
    };
    let subject = match ber::read_in(&mut t) {
        Ok(v) => v,
        Err(_) => return,
    };

    let issuer_cn = ber::find_after_oid(issuer.val, OID_CN, 6).and_then(|v| v.as_str());
    let subject_cn = ber::find_after_oid(subject.val, OID_CN, 6).and_then(|v| v.as_str());
    // A leaf whose issuer and subject match is self-signed — worth surfacing directly, since
    // it is the common shape for C2 and interception certificates.
    if let (Some(i), Some(s)) = (&issuer_cn, &subject_cn) {
        ctx.pkt.tls_cert_self_signed = Some(i == s);
    }
    ctx.pkt.tls_cert_issuer = issuer_cn.map(|s| cap(s, 512));
    ctx.pkt.tls_cert_subject = subject_cn.map(|s| cap(s, 512));

    let mut vc = validity.cur();
    if let Ok(nb) = ber::read_in(&mut vc) {
        ctx.pkt.tls_cert_not_before = nb.as_str();
    }
    if let Ok(na) = ber::read_in(&mut vc) {
        ctx.pkt.tls_cert_not_after = na.as_str();
    }

    if let Some(sans) = extract_sans(tbs.val) {
        ctx.pkt.tls_cert_sans = Some(cap(sans, 2048));
    }
}

/// Find the subjectAltName extension and collect its dNSName and iPAddress entries.
fn extract_sans(tbs: &[u8]) -> Option<String> {
    let mut octets: Vec<ber::Tlv> = Vec::new();
    // The extension is `SEQUENCE { OID, BOOLEAN OPTIONAL, OCTET STRING }`. Locating the OID
    // and taking the following OCTET STRING skips the optional criticality flag.
    let after = ber::find_after_oid(tbs, OID_SAN, 8)?;
    let inner = if after.tag == ber::TAG_OCTET_STRING {
        after.val
    } else {
        // The BOOLEAN was present; collect octet strings from the enclosing region instead.
        ber::collect(
            tbs,
            8,
            32,
            &|t: &ber::Tlv| t.tag == ber::TAG_OCTET_STRING && !t.constructed,
            &mut octets,
        );
        octets.iter().map(|t| t.val).find(|v| {
            let mut c = Cur::new(v);
            matches!(ber::read_in(&mut c), Ok(t) if t.constructed && t.tag == ber::TAG_SEQUENCE)
        })?
    };

    let mut c = Cur::new(inner);
    let seq = ber::read_in(&mut c).ok()?;
    let mut sc = seq.cur();
    let mut names = Vec::new();
    while let Ok(name) = ber::read_in(&mut sc) {
        if name.class != ber::CLASS_CONTEXT {
            continue;
        }
        match name.tag {
            2 => {
                if let Some(s) = ascii_string(name.val) {
                    names.push(s);
                }
            }
            7 => match name.val.len() {
                4 => names.push(
                    std::net::Ipv4Addr::new(name.val[0], name.val[1], name.val[2], name.val[3])
                        .to_string(),
                ),
                16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(name.val);
                    names.push(std::net::Ipv6Addr::from(o).to_string());
                }
                _ => {}
            },
            _ => {}
        }
        if names.len() >= 64 {
            break;
        }
    }
    if names.is_empty() {
        None
    } else {
        Some(names.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    /// Build a TLS record wrapping a handshake message.
    fn record(htype: u8, body: &[u8]) -> Vec<u8> {
        let hlen = body.len();
        let mut hs = vec![htype, (hlen >> 16) as u8, (hlen >> 8) as u8, hlen as u8];
        hs.extend_from_slice(body);
        let rlen = hs.len();
        let mut r = vec![22, 0x03, 0x01, (rlen >> 8) as u8, rlen as u8];
        r.extend_from_slice(&hs);
        r
    }

    fn client_hello_body() -> Vec<u8> {
        let mut b = vec![0x03, 0x03];
        b.extend_from_slice(&[0xab; 32]); // random
        b.push(0); // no session id
                   // cipher suites: GREASE, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        b.extend_from_slice(&[0, 6, 0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02]);
        b.extend_from_slice(&[1, 0]); // one compression method: null

        // Extensions: SNI, supported_groups, ALPN, supported_versions
        let mut ext = Vec::new();
        let host = b"example.com";
        let sni_inner_len = 3 + host.len();
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&[((sni_inner_len + 2) >> 8) as u8, (sni_inner_len + 2) as u8]);
        ext.extend_from_slice(&[(sni_inner_len >> 8) as u8, sni_inner_len as u8]);
        ext.push(0); // host_name
        ext.extend_from_slice(&[(host.len() >> 8) as u8, host.len() as u8]);
        ext.extend_from_slice(host);

        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]); // x25519

        // ALPN: "h2"
        ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        // supported_versions: list of one, TLS 1.3
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        b.extend_from_slice(&[(ext.len() >> 8) as u8, ext.len() as u8]);
        b.extend_from_slice(&ext);
        b
    }

    fn run(payload: &[u8]) -> Packet {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            let _ = parse(payload, &mut ctx, false);
        }
        p
    }

    #[test]
    fn client_hello_yields_sni_alpn_and_fingerprints() {
        let p = run(&record(1, &client_hello_body()));
        assert_eq!(p.tls_sni.as_deref(), Some("example.com"));
        assert_eq!(p.tls_alpn.as_deref(), Some("h2"));
        assert_eq!(p.tls_handshake_type_name.as_deref(), Some("client_hello"));
        // supported_versions must win over the legacy 0x0303 field.
        assert_eq!(p.tls_version.as_deref(), Some("TLS 1.3"));
        assert_eq!(p.tls_cipher_suite_count, Some(3));

        let ja3 = p.ja3.unwrap();
        assert_eq!(ja3.len(), 32);
        // GREASE must not appear in the JA3 string.
        assert!(!p.ja3_full.unwrap().contains("2570"));

        let ja4 = p.ja4.unwrap();
        assert!(ja4.starts_with("t13d"), "{ja4}");
        assert!(ja4.contains("h2"), "{ja4}");
    }

    #[test]
    fn server_hello_yields_ja3s() {
        let mut b = vec![0x03, 0x03];
        b.extend_from_slice(&[0xcd; 32]);
        b.push(0);
        b.extend_from_slice(&[0x13, 0x01]); // selected cipher
        b.push(0); // compression
        b.extend_from_slice(&[0x00, 0x00]); // empty extensions block

        let p = run(&record(2, &b));
        assert_eq!(p.tls_cipher_selected.as_deref(), Some("1301"));
        assert_eq!(p.ja3s.unwrap().len(), 32);
        assert!(p.ja4s.unwrap().starts_with("t12"));
    }

    #[test]
    fn alert_records_are_decoded() {
        let p = run(&[21, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        assert_eq!(p.tls_alert_level, Some(2));
        assert_eq!(p.tls_alert_description, Some(40));
    }

    #[test]
    fn truncated_handshakes_never_panic() {
        let full = record(1, &client_hello_body());
        for n in 0..full.len() {
            let _ = run(&full[..n]);
        }
    }

    #[test]
    fn sniffing_distinguishes_tls_from_dtls() {
        assert!(looks_like_tls(&[22, 3, 1, 0, 5]));
        assert!(!looks_like_tls(b"GET / HTTP"));
        assert!(looks_like_dtls(&[22, 0xfe, 0xfd]));
    }
}
