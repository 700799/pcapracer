//! Passive TLS/SSH client and server fingerprints, and the Community ID flow hash.
//!
//! These are the identifiers threat-intel feeds are keyed on, so they are computed inline
//! during dissection rather than reconstructed later from the extracted columns.

use base64::Engine;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

/// GREASE values (RFC 8701) are random padding a client inserts to keep middleboxes honest.
/// They differ per connection, so leaving them in would make every fingerprint unique.
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0x00ff)
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

fn sha256_trunc12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let d = h.finalize();
    let mut out = String::with_capacity(12);
    for b in d.iter().take(6) {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// A JA4 component over an empty list is the literal string of twelve zeroes, not a hash of
/// the empty string — matching the reference implementation.
fn ja4_hash_list(items: &[String]) -> String {
    if items.is_empty() {
        return "000000000000".to_string();
    }
    sha256_trunc12(&items.join(","))
}

// ---------------------------------------------------------------------------
// JA3 / JA3S
// ---------------------------------------------------------------------------

pub struct Ja3Input<'a> {
    pub version: u16,
    pub ciphers: &'a [u16],
    pub extensions: &'a [u16],
    pub curves: &'a [u16],
    pub point_formats: &'a [u8],
}

/// JA3: MD5 over `version,ciphers,extensions,curves,point_formats`.
pub fn ja3(i: &Ja3Input) -> (String, String) {
    let j = |v: &[u16]| {
        v.iter()
            .filter(|x| !is_grease(**x))
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let full = format!(
        "{},{},{},{},{}",
        i.version,
        j(i.ciphers),
        j(i.extensions),
        j(i.curves),
        i.point_formats
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    );
    (md5_hex(&full), full)
}

/// JA3S: the server-side equivalent, over `version,cipher,extensions`.
pub fn ja3s(version: u16, cipher: u16, extensions: &[u16]) -> (String, String) {
    let exts = extensions
        .iter()
        .filter(|x| !is_grease(**x))
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let full = format!("{},{},{}", version, cipher, exts);
    (md5_hex(&full), full)
}

// ---------------------------------------------------------------------------
// JA4 / JA4S
// ---------------------------------------------------------------------------

/// Two-character TLS version code as used by JA4.
fn ja4_version(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

pub struct Ja4Input<'a> {
    /// The negotiated version, preferring `supported_versions` over the legacy field.
    pub version: u16,
    pub is_quic: bool,
    pub has_sni: bool,
    pub ciphers: &'a [u16],
    pub extensions: &'a [u16],
    pub sig_algs: &'a [u16],
    pub alpn: Option<&'a str>,
}

/// JA4, in its canonical `a_b_c` form.
///
/// The cipher and extension lists are sorted before hashing — that is what makes JA4 stable
/// against clients that shuffle their ordering, which is precisely the evasion JA3 is
/// vulnerable to.
pub fn ja4(i: &Ja4Input) -> String {
    let ciphers: Vec<u16> = i
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let all_exts: Vec<u16> = i
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();

    // The `a` part counts every extension, but SNI (0) and ALPN (16) are excluded from the
    // hashed list because they are already represented in the `a` part.
    let hashed_exts: Vec<u16> = all_exts
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();

    let alpn_code = match i.alpn {
        Some(a) if !a.is_empty() => {
            let bytes = a.as_bytes();
            let first = bytes[0] as char;
            let last = bytes[bytes.len() - 1] as char;
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    };

    let a = format!(
        "{}{}{}{:02}{:02}{}",
        if i.is_quic { 'q' } else { 't' },
        ja4_version(i.version),
        if i.has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        all_exts.len().min(99),
        alpn_code,
    );

    let mut sorted_ciphers: Vec<String> = ciphers.iter().map(|c| format!("{:04x}", c)).collect();
    sorted_ciphers.sort();
    let b = ja4_hash_list(&sorted_ciphers);

    let mut sorted_exts: Vec<String> = hashed_exts.iter().map(|e| format!("{:04x}", e)).collect();
    sorted_exts.sort();
    let sigs: Vec<String> = i.sig_algs.iter().map(|s| format!("{:04x}", s)).collect();
    // Signature algorithms keep their transmitted order and are appended after an underscore.
    let c_input = if sigs.is_empty() {
        sorted_exts.join(",")
    } else {
        format!("{}_{}", sorted_exts.join(","), sigs.join(","))
    };
    let c = if sorted_exts.is_empty() && sigs.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_trunc12(&c_input)
    };

    format!("{a}_{b}_{c}")
}

/// JA4S, the server-side counterpart.
pub fn ja4s(
    version: u16,
    is_quic: bool,
    cipher: u16,
    extensions: &[u16],
    alpn: Option<&str>,
) -> String {
    let exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let alpn_code = match alpn {
        Some(a) if !a.is_empty() => {
            let b = a.as_bytes();
            format!("{}{}", b[0] as char, b[b.len() - 1] as char)
        }
        _ => "00".to_string(),
    };
    let a = format!(
        "{}{}{:02}{}",
        if is_quic { 'q' } else { 't' },
        ja4_version(version),
        exts.len().min(99),
        alpn_code
    );
    // Server extensions keep transmitted order — a server does not shuffle them.
    let list: Vec<String> = exts.iter().map(|e| format!("{:04x}", e)).collect();
    format!("{a}_{:04x}_{}", cipher, ja4_hash_list(&list))
}

// ---------------------------------------------------------------------------
// HASSH
// ---------------------------------------------------------------------------

/// HASSH / HASSHServer: MD5 over the SSH algorithm negotiation lists.
pub fn hassh(kex: &str, enc: &str, mac: &str, comp: &str) -> String {
    md5_hex(&format!("{kex};{enc};{mac};{comp}"))
}

// ---------------------------------------------------------------------------
// Community ID
// ---------------------------------------------------------------------------

/// Community ID v1 — the cross-tool flow identifier (Zeek, Suricata, Arkime).
///
/// The endpoints are ordered so both directions of a conversation hash identically, then
/// SHA-1'd and base64'd behind the `1:` version prefix.
pub fn community_id(
    src_ip: &std::net::IpAddr,
    dst_ip: &std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    seed: u16,
) -> String {
    use sha1::Digest as Sha1Digest;

    let ordered = is_ordered(src_ip, dst_ip, src_port, dst_port);
    let (a_ip, b_ip, a_port, b_port) = if ordered {
        (src_ip, dst_ip, src_port, dst_port)
    } else {
        (dst_ip, src_ip, dst_port, src_port)
    };

    let mut h = Sha1::new();
    h.update(seed.to_be_bytes());
    match a_ip {
        std::net::IpAddr::V4(v) => h.update(v.octets()),
        std::net::IpAddr::V6(v) => h.update(v.octets()),
    }
    match b_ip {
        std::net::IpAddr::V4(v) => h.update(v.octets()),
        std::net::IpAddr::V6(v) => h.update(v.octets()),
    }
    h.update([proto, 0]);
    // Port-bearing protocols contribute their ports; others (ICMP, GRE, …) contribute none.
    if has_ports(proto) {
        h.update(a_port.to_be_bytes());
        h.update(b_port.to_be_bytes());
    }
    let digest = h.finalize();
    format!(
        "1:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn has_ports(proto: u8) -> bool {
    matches!(proto, 6 | 17 | 132 | 136)
}

fn is_ordered(
    src_ip: &std::net::IpAddr,
    dst_ip: &std::net::IpAddr,
    src_port: u16,
    dst_port: u16,
) -> bool {
    match src_ip.cmp(dst_ip) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => src_port <= dst_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a1a));
    }

    #[test]
    fn ja3_drops_grease_and_hashes_the_string() {
        let i = Ja3Input {
            version: 771,
            ciphers: &[0x0a0a, 0x1301, 0x1302],
            extensions: &[0x0000, 0x0010],
            curves: &[0x001d],
            point_formats: &[0],
        };
        let (hash, full) = ja3(&i);
        assert_eq!(full, "771,4865-4866,0-16,29,0");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, md5_hex(&full));
    }

    #[test]
    fn ja4_shape_and_stability_under_reordering() {
        let base = Ja4Input {
            version: 0x0304,
            is_quic: false,
            has_sni: true,
            ciphers: &[0x1301, 0x1302, 0x1303],
            extensions: &[0x0000, 0x0010, 0x002b, 0x000d],
            sig_algs: &[0x0403],
            alpn: Some("h2"),
        };
        let a = ja4(&base);
        // t13d + 3 ciphers + 4 extensions + "h2"
        assert!(a.starts_with("t13d0304h2_"), "{a}");
        assert_eq!(a.split('_').count(), 3);

        // JA4's defining property: shuffling the cipher list must not change the fingerprint.
        let shuffled = Ja4Input {
            ciphers: &[0x1303, 0x1301, 0x1302],
            ..base
        };
        assert_eq!(a, ja4(&shuffled));
    }

    #[test]
    fn ja4_empty_lists_use_the_zero_sentinel() {
        let i = Ja4Input {
            version: 0x0303,
            is_quic: false,
            has_sni: false,
            ciphers: &[],
            extensions: &[],
            sig_algs: &[],
            alpn: None,
        };
        let f = ja4(&i);
        assert_eq!(f, "t12i000000_000000000000_000000000000");
    }

    #[test]
    fn community_id_matches_the_reference_vector() {
        // From the community-id spec's test suite: 128.232.110.120:34855 -> 66.35.250.204:80 tcp
        let a: IpAddr = "128.232.110.120".parse().unwrap();
        let b: IpAddr = "66.35.250.204".parse().unwrap();
        let expected = "1:LQU9qZlK+B5F3KDmev6m5PMibrg=";
        assert_eq!(community_id(&a, &b, 34855, 80, 6, 0), expected);
        // Both directions must produce the same identifier.
        assert_eq!(community_id(&b, &a, 80, 34855, 6, 0), expected);
    }

    #[test]
    fn community_id_ignores_ports_for_portless_protocols() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        // ICMP: the "ports" carry type/code, which the caller may or may not supply.
        assert_eq!(
            community_id(&a, &b, 8, 0, 1, 0),
            community_id(&a, &b, 0, 0, 1, 0)
        );
    }

    #[test]
    fn hassh_is_an_md5_of_the_joined_lists() {
        let h = hassh("curve25519-sha256", "aes128-ctr", "hmac-sha2-256", "none");
        assert_eq!(h.len(), 32);
        assert_eq!(
            h,
            md5_hex("curve25519-sha256;aes128-ctr;hmac-sha2-256;none")
        );
    }
}
