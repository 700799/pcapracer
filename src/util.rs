use std::fmt::Write as _;
use std::net::Ipv6Addr;

/// Compact representation of an IP address, formatted lazily at output time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpRepr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpRepr {
    pub fn write(&self, s: &mut String) {
        match self {
            IpRepr::V4(o) => write_ipv4(s, *o),
            IpRepr::V6(o) => write_ipv6(s, *o),
        }
    }
}

#[inline]
pub fn write_ipv4(s: &mut String, o: [u8; 4]) {
    let _ = write!(s, "{}.{}.{}.{}", o[0], o[1], o[2], o[3]);
}

#[inline]
pub fn write_ipv6(s: &mut String, o: [u8; 16]) {
    // Ipv6Addr's Display implements RFC 5952 canonical compression.
    let _ = write!(s, "{}", Ipv6Addr::from(o));
}

#[inline]
pub fn write_mac(s: &mut String, m: [u8; 6]) {
    let _ = write!(
        s,
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    );
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Append lowercase hex of `bytes` to `s`.
pub fn write_hex(s: &mut String, bytes: &[u8]) {
    s.reserve(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
}

pub fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    write_hex(&mut s, bytes);
    s
}

/// Shannon entropy of a byte slice, in bits per byte (0.0..=8.0).
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Fraction of bytes that are printable ASCII (0.0..=1.0).
pub fn printable_ratio(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r')
        .count();
    printable as f32 / data.len() as f32
}

/// Read a big-endian u16 at `off`, or None if out of range.
#[inline]
pub fn be_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// Read a big-endian u32 at `off`, or None if out of range.
#[inline]
pub fn be_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_fmt() {
        let mut s = String::new();
        write_ipv4(&mut s, [192, 168, 1, 1]);
        assert_eq!(s, "192.168.1.1");
    }

    #[test]
    fn ipv6_fmt() {
        let mut s = String::new();
        write_ipv6(
            &mut s,
            [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        assert_eq!(s, "2001:db8::1");
    }

    #[test]
    fn mac_fmt() {
        let mut s = String::new();
        write_mac(&mut s, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(s, "de:ad:be:ef:00:01");
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7, 7, 7, 7]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-4);
    }

    #[test]
    fn printable() {
        assert!((printable_ratio(b"hello") - 1.0).abs() < 1e-6);
        assert_eq!(printable_ratio(&[0, 0]), 0.0);
    }
}
