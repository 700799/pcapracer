//! JA3, JA3S and JA4 (TLS client) fingerprints.
//!
//! JA3/JA3S are MD5 fingerprints (public domain). JA4 here is the TLS *client*
//! fingerprint, the BSD-licensed component of the JA4+ suite; the FoxIO
//! non-commercial variants (JA4S/JA4H/JA4L) are intentionally not implemented.

use md5::Md5;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Parsed ClientHello fields needed for fingerprinting.
#[derive(Default, Debug)]
pub struct ClientHelloInfo {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub sig_algs: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
}

/// Parsed ServerHello fields needed for JA3S.
#[derive(Default, Debug)]
pub struct ServerHelloInfo {
    pub version: u16,
    pub cipher: u16,
    pub extensions: Vec<u16>,
}

#[inline]
pub fn is_grease(v: u16) -> bool {
    let b = (v & 0xff) as u8;
    (v >> 8) as u8 == b && (b & 0x0f) == 0x0a
}

fn dash_join_u16(vals: &[u16], filter_grease: bool) -> String {
    let mut s = String::new();
    for &v in vals {
        if filter_grease && is_grease(v) {
            continue;
        }
        if !s.is_empty() {
            s.push('-');
        }
        let _ = write!(s, "{v}");
    }
    s
}

fn dash_join_u8(vals: &[u8]) -> String {
    let mut s = String::new();
    for &v in vals {
        if !s.is_empty() {
            s.push('-');
        }
        let _ = write!(s, "{v}");
    }
    s
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut hex = String::with_capacity(32);
    for b in out {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

fn sha256_12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut hex = String::with_capacity(12);
    for b in out.iter().take(6) {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// JA3 fingerprint. Returns (md5_hex, raw_string).
pub fn ja3(ch: &ClientHelloInfo) -> (String, String) {
    let ciphers = dash_join_u16(&ch.ciphers, true);
    let exts = dash_join_u16(&ch.extensions, true);
    let curves = dash_join_u16(&ch.groups, true);
    let pf = dash_join_u8(&ch.ec_point_formats);
    let raw = format!(
        "{},{},{},{},{}",
        ch.legacy_version, ciphers, exts, curves, pf
    );
    (md5_hex(&raw), raw)
}

/// JA3S fingerprint. Returns (md5_hex, raw_string).
pub fn ja3s(sh: &ServerHelloInfo) -> (String, String) {
    let exts = dash_join_u16(&sh.extensions, true);
    let raw = format!("{},{},{}", sh.version, sh.cipher, exts);
    (md5_hex(&raw), raw)
}

fn ja4_version(ch: &ClientHelloInfo) -> &'static str {
    let best = ch
        .supported_versions
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .max()
        .unwrap_or(ch.legacy_version);
    match best {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn ja4_alpn(ch: &ClientHelloInfo) -> String {
    match ch.alpn.first() {
        None => "00".to_string(),
        Some(a) if a.is_empty() => "00".to_string(),
        Some(a) => {
            let first = a.chars().next().unwrap();
            let last = a.chars().last().unwrap();
            format!("{first}{last}")
        }
    }
}

fn ja4_hash_list(mut vals: Vec<String>) -> String {
    if vals.is_empty() {
        return "000000000000".to_string();
    }
    vals.sort();
    sha256_12(&vals.join(","))
}

/// JA4 (TLS client) fingerprint, e.g. `t13d1516h2_8daaf6152771_02713d6af862`.
pub fn ja4(ch: &ClientHelloInfo) -> String {
    let ver = ja4_version(ch);
    let sni = if ch.sni.is_some() { 'd' } else { 'i' };
    let n_ciphers = ch
        .ciphers
        .iter()
        .filter(|&&v| !is_grease(v))
        .count()
        .min(99);
    let n_exts = ch
        .extensions
        .iter()
        .filter(|&&v| !is_grease(v))
        .count()
        .min(99);
    let alpn = ja4_alpn(ch);
    let a = format!("t{ver}{sni}{n_ciphers:02}{n_exts:02}{alpn}");

    let cipher_hex: Vec<String> = ch
        .ciphers
        .iter()
        .filter(|&&v| !is_grease(v))
        .map(|v| format!("{v:04x}"))
        .collect();
    let b = ja4_hash_list(cipher_hex);

    // Extensions sorted, excluding GREASE, SNI (0x0000) and ALPN (0x0010).
    let mut ext_hex: Vec<String> = ch
        .extensions
        .iter()
        .filter(|&&v| !is_grease(v) && v != 0x0000 && v != 0x0010)
        .map(|v| format!("{v:04x}"))
        .collect();
    ext_hex.sort();
    let sig_hex: Vec<String> = ch.sig_algs.iter().map(|v| format!("{v:04x}")).collect();
    let c = if ext_hex.is_empty() && sig_hex.is_empty() {
        "000000000000".to_string()
    } else {
        let raw = format!("{}_{}", ext_hex.join(","), sig_hex.join(","));
        sha256_12(&raw)
    };

    format!("{a}_{b}_{c}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0000));
    }

    #[test]
    fn ja3_known_string() {
        // A minimal, hand-constructed ClientHello info.
        let ch = ClientHelloInfo {
            legacy_version: 771,
            ciphers: vec![0x1a1a, 0x1301, 0x1302], // first is GREASE, filtered
            extensions: vec![0x0000, 0x0017, 0x0a0a],
            groups: vec![0x001d, 0x0017],
            ec_point_formats: vec![0],
            ..Default::default()
        };
        let (_md5, raw) = ja3(&ch);
        assert_eq!(raw, "771,4865-4866,0-23,29-23,0");
    }
}
