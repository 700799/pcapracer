//! Minimal BER/DER reader shared by SNMP, LDAP, Kerberos and X.509.
//!
//! Just enough to walk a TLV tree and pull out primitives. Indefinite-length encodings are
//! rejected rather than guessed at — they do not appear in DER, and accepting them in BER
//! contexts would mean scanning for an end-of-contents marker in attacker-controlled bytes.

use crate::bytes::Cur;
use crate::error::{DResult, DissectError};

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_APPLICATION: u8 = 1;
pub const CLASS_CONTEXT: u8 = 2;

// Universal tag numbers.
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_SEQUENCE: u8 = 0x10;
pub const TAG_SET: u8 = 0x11;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_GENERAL_STRING: u8 = 0x1b;

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u8,
    pub val: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn cur(&self) -> Cur<'a> {
        Cur::new(self.val)
    }

    pub fn is(&self, class: u8, tag: u8) -> bool {
        self.class == class && self.tag == tag
    }

    /// Interpret the value as a big-endian signed integer, capped at 8 bytes.
    pub fn as_i64(&self) -> Option<i64> {
        if self.val.is_empty() || self.val.len() > 8 {
            return None;
        }
        let neg = self.val[0] & 0x80 != 0;
        let mut v: i64 = if neg { -1 } else { 0 };
        for &b in self.val {
            v = (v << 8) | b as i64;
        }
        Some(v)
    }

    pub fn as_u64(&self) -> Option<u64> {
        if self.val.is_empty() || self.val.len() > 8 {
            return None;
        }
        let mut v: u64 = 0;
        for &b in self.val {
            v = (v << 8) | b as u64;
        }
        Some(v)
    }

    pub fn as_str(&self) -> Option<String> {
        crate::bytes::ascii_string(self.val)
    }

    /// Dotted-decimal rendering of an OBJECT IDENTIFIER value.
    pub fn as_oid(&self) -> Option<String> {
        if self.val.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        let first = self.val[0] as u32;
        parts.push((first / 40).to_string());
        parts.push((first % 40).to_string());
        let mut acc: u64 = 0;
        let mut pending = false;
        for &b in &self.val[1..] {
            // Each sub-identifier is base-128 with a continuation bit; cap the accumulator
            // so a long run of 0x80 bytes cannot overflow.
            acc = acc.wrapping_mul(128) | (b & 0x7f) as u64;
            pending = true;
            if b & 0x80 == 0 {
                parts.push(acc.to_string());
                acc = 0;
                pending = false;
            }
        }
        if pending {
            return None; // truncated final sub-identifier
        }
        Some(parts.join("."))
    }
}

/// Read one TLV, borrowing from the cursor's buffer.
pub fn read_in<'a>(c: &mut Cur<'a>) -> DResult<Tlv<'a>> {
    let id = c.u8()?;
    let class = id >> 6;
    let constructed = id & 0x20 != 0;
    let mut tag = id & 0x1f;

    // High-tag-number form: 0x1f means the tag continues in base-128 bytes.
    if tag == 0x1f {
        let mut t: u32 = 0;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4 {
                return Err(DissectError::Malformed);
            }
            let b = c.u8()?;
            t = (t << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
        tag = (t & 0xff) as u8;
    }

    let first = c.u8()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            // 0 is the indefinite form; >4 would exceed any sane packet length.
            return Err(DissectError::Malformed);
        }
        let b = c.take(n)?;
        let mut v: usize = 0;
        for &x in b {
            v = (v << 8) | x as usize;
        }
        v
    };

    let val = c.take(len)?;
    Ok(Tlv {
        class,
        constructed,
        tag,
        val,
    })
}

/// Depth-first search for the first TLV whose value contains the given OID encoding,
/// returning the TLV that immediately follows it within the same SEQUENCE.
///
/// This is how attribute lookups work in X.509 names: `SEQUENCE { OID, value }`.
pub fn find_after_oid<'a>(data: &'a [u8], oid: &[u8], depth: u8) -> Option<Tlv<'a>> {
    if depth == 0 {
        return None;
    }
    let mut c = Cur::new(data);
    while !c.is_empty() {
        let t = match read_in(&mut c) {
            Ok(t) => t,
            Err(_) => return None,
        };
        if t.class == CLASS_UNIVERSAL && t.tag == TAG_OID && t.val == oid {
            // The value we want is the next element at this level.
            if let Ok(next) = read_in(&mut c) {
                return Some(next);
            }
            return None;
        }
        if t.constructed {
            if let Some(found) = find_after_oid(t.val, oid, depth - 1) {
                return Some(found);
            }
        }
    }
    None
}

/// Collect every TLV matching a predicate, depth-first, up to `limit` results.
pub fn collect<'a, F>(data: &'a [u8], depth: u8, limit: usize, pred: &F, out: &mut Vec<Tlv<'a>>)
where
    F: Fn(&Tlv<'a>) -> bool,
{
    if depth == 0 || out.len() >= limit {
        return;
    }
    let mut c = Cur::new(data);
    while !c.is_empty() && out.len() < limit {
        let t = match read_in(&mut c) {
            Ok(t) => t,
            Err(_) => return,
        };
        if pred(&t) {
            out.push(t);
        }
        if t.constructed {
            collect(t.val, depth - 1, limit, pred, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_simple_sequence() {
        // SEQUENCE { INTEGER 1, OCTET STRING "hi" }
        let data = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'h', b'i'];
        let mut c = Cur::new(&data);
        let seq = read_in(&mut c).unwrap();
        assert!(seq.constructed);
        assert_eq!(seq.tag, TAG_SEQUENCE);

        let mut inner = seq.cur();
        assert_eq!(read_in(&mut inner).unwrap().as_i64(), Some(1));
        assert_eq!(read_in(&mut inner).unwrap().as_str().as_deref(), Some("hi"));
    }

    #[test]
    fn long_form_length() {
        let mut data = vec![0x04, 0x81, 0x80];
        data.extend_from_slice(&[0xaa; 128]);
        let mut c = Cur::new(&data);
        assert_eq!(read_in(&mut c).unwrap().val.len(), 128);
    }

    #[test]
    fn indefinite_length_is_rejected() {
        let data = [0x30, 0x80, 0x00, 0x00];
        let mut c = Cur::new(&data);
        assert_eq!(read_in(&mut c).unwrap_err(), DissectError::Malformed);
    }

    #[test]
    fn truncated_value_errors() {
        let data = [0x04, 0x10, 0x01, 0x02];
        let mut c = Cur::new(&data);
        assert!(read_in(&mut c).is_err());
    }

    #[test]
    fn oid_rendering() {
        // 1.2.840.113549 (RSA)
        let data = [0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d];
        let mut c = Cur::new(&data);
        assert_eq!(
            read_in(&mut c).unwrap().as_oid().as_deref(),
            Some("1.2.840.113549")
        );
    }

    #[test]
    fn find_after_oid_locates_a_name_attribute() {
        // SET { SEQUENCE { OID 2.5.4.3 (CN), PrintableString "example.com" } }
        let data = [
            0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0b, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        let v = find_after_oid(&data, &[0x55, 0x04, 0x03], 6).unwrap();
        assert_eq!(v.as_str().as_deref(), Some("example.com"));
    }
}
