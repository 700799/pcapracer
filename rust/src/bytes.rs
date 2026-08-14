//! A bounds-checked read cursor, plus the formatting helpers the dissectors share.
//!
//! Every dissector reads through `Cur`. Capture files are adversarial input by definition —
//! a malformed or deliberately crafted packet must produce `Err(Truncated)`, never a panic
//! that would take down the caller's Python process. Centralising the length checks here is
//! what makes `#![forbid(unsafe_code)]` across the dissect tree meaningful.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{DResult, DissectError};

#[derive(Debug, Clone)]
pub struct Cur<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Cur { data, pos: 0 }
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Everything not yet consumed, without consuming it.
    #[inline]
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Consume and return the remainder.
    #[inline]
    pub fn take_rest(&mut self) -> &'a [u8] {
        let r = &self.data[self.pos..];
        self.pos = self.data.len();
        r
    }

    #[inline]
    pub fn need(&self, n: usize) -> DResult<()> {
        if self.remaining() < n {
            Err(DissectError::Truncated)
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn take(&mut self, n: usize) -> DResult<&'a [u8]> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    #[inline]
    pub fn skip(&mut self, n: usize) -> DResult<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    /// Shrink the cursor's view to `n` more bytes. Used to confine a sub-dissector to a
    /// length-delimited region so it cannot read into the next record.
    pub fn sub(&mut self, n: usize) -> DResult<Cur<'a>> {
        Ok(Cur::new(self.take(n)?))
    }

    #[inline]
    pub fn u8(&mut self) -> DResult<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    pub fn peek_u8(&self) -> DResult<u8> {
        self.need(1)?;
        Ok(self.data[self.pos])
    }

    /// Peek `n` bytes ahead without consuming; returns `None` rather than erroring so
    /// protocol-sniffing code can branch on it directly.
    #[inline]
    pub fn peek(&self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            None
        } else {
            Some(&self.data[self.pos..self.pos + n])
        }
    }

    #[inline]
    pub fn be16(&mut self) -> DResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn be24(&mut self) -> DResult<u32> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    #[inline]
    pub fn be32(&mut self) -> DResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn be64(&mut self) -> DResult<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    #[inline]
    pub fn le16(&mut self) -> DResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn le32(&mut self) -> DResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    pub fn le64(&mut self) -> DResult<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn ipv4(&mut self) -> DResult<Ipv4Addr> {
        let b = self.take(4)?;
        Ok(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }

    pub fn ipv6(&mut self) -> DResult<Ipv6Addr> {
        let b = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(Ipv6Addr::from(a))
    }

    pub fn mac(&mut self) -> DResult<[u8; 6]> {
        let b = self.take(6)?;
        let mut a = [0u8; 6];
        a.copy_from_slice(b);
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub fn fmt_oui(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}", m[0], m[1], m[2])
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

/// True for RFC1918 / RFC4193 / link-local / loopback space. Cheap enough to compute per
/// packet and saves analysts a CASE expression in every query.
pub fn is_private_v4(a: &Ipv4Addr) -> bool {
    a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified()
}

pub fn is_private_v6(a: &Ipv6Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_unspecified()
        || (o[0] & 0xfe) == 0xfc
        || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
}

/// Shannon entropy over the byte distribution, in bits/byte (0.0-8.0).
///
/// Encrypted or compressed payloads sit near 8.0 and plaintext near 4.5, which makes this a
/// useful first-pass filter for tunnelled or obfuscated traffic.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c != 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// A printable, length-capped rendering of a payload for eyeballing in a query result.
/// Non-printable bytes become `.` so the string stays valid UTF-8 and Parquet-safe.
pub fn preview(data: &[u8], max: usize) -> String {
    let n = data.len().min(max);
    let mut s = String::with_capacity(n);
    for &b in &data[..n] {
        if (0x20..0x7f).contains(&b) {
            s.push(b as char);
        } else {
            s.push('.');
        }
    }
    s
}

pub fn is_mostly_printable(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let n = data.len().min(256);
    let printable = data[..n]
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\r' || b == b'\n' || b == b'\t')
        .count();
    printable * 10 >= n * 9
}

/// Lossy UTF-8 for protocol fields that are nominally ASCII but are attacker-controlled.
/// Returns `None` for empty input so the column stays null rather than storing `""`.
pub fn ascii_string(b: &[u8]) -> Option<String> {
    if b.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(b).replace('\u{0}', ""))
}

/// Truncate a string field to keep a single pathological packet from blowing up a row group.
pub fn cap(mut s: String, max: usize) -> String {
    if s.len() > max {
        s.truncate(max);
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_past_the_end_error_rather_than_panic() {
        let mut c = Cur::new(&[1, 2, 3]);
        assert_eq!(c.be16().unwrap(), 0x0102);
        assert!(c.be32().is_err());
        assert!(c.take(9).is_err());
        assert!(c.skip(2).is_err());
        // A failed read must not advance the cursor.
        assert_eq!(c.remaining(), 1);
    }

    #[test]
    fn sub_confines_a_dissector_to_its_region() {
        let mut c = Cur::new(&[1, 2, 3, 4, 5, 6]);
        let mut inner = c.sub(2).unwrap();
        assert_eq!(inner.remaining(), 2);
        assert!(inner.be32().is_err());
        assert_eq!(c.remaining(), 4);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 64]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn ipv6_uses_rfc5952_compression() {
        let mut c = Cur::new(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(c.ipv6().unwrap().to_string(), "2001:db8::1");
    }

    #[test]
    fn preview_neutralises_control_bytes() {
        assert_eq!(preview(b"ab\x00\xffcd", 10), "ab..cd");
    }
}
