//! pcapng block parsing (SHB / IDB / EPB / SPB / obsolete PB).
//!
//! Handles multiple sections (SHB resets interface state), per-interface
//! link type and timestamp resolution/offset.

use crate::error::{Error, Result};
use crate::reader::RecMeta;

const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_PB: u32 = 0x0000_0002;
const BT_SPB: u32 = 0x0000_0003;
const BT_EPB: u32 = 0x0000_0006;

#[derive(Clone, Copy)]
struct Iface {
    linktype: u16,
    snaplen: u32,
    ts_den: u64,
    tsoffset_ns: i64,
}

impl Default for Iface {
    fn default() -> Iface {
        Iface {
            linktype: 1,
            snaplen: 0,
            ts_den: 1_000_000, // microseconds
            tsoffset_ns: 0,
        }
    }
}

pub struct PcapngState {
    big_endian: bool,
    ifaces: Vec<Iface>,
}

impl PcapngState {
    /// Peek the first SHB to learn the section's byte order.
    pub fn open(bytes: &[u8]) -> Result<(PcapngState, usize)> {
        if bytes.len() < 12 {
            return Err(Error::Invalid("truncated pcapng header".into()));
        }
        let bom = &bytes[8..12];
        let big_endian = match bom {
            [0x1a, 0x2b, 0x3c, 0x4d] => true,
            [0x4d, 0x3c, 0x2b, 0x1a] => false,
            _ => return Err(Error::Invalid("bad pcapng byte-order magic".into())),
        };
        Ok((
            PcapngState {
                big_endian,
                ifaces: Vec::new(),
            },
            0,
        ))
    }

    fn u16(&self, b: &[u8], off: usize) -> Option<u16> {
        let s = b.get(off..off + 2)?;
        Some(if self.big_endian {
            u16::from_be_bytes([s[0], s[1]])
        } else {
            u16::from_le_bytes([s[0], s[1]])
        })
    }

    fn u32(&self, b: &[u8], off: usize) -> Option<u32> {
        let s = b.get(off..off + 4)?;
        Some(if self.big_endian {
            u32::from_be_bytes([s[0], s[1], s[2], s[3]])
        } else {
            u32::from_le_bytes([s[0], s[1], s[2], s[3]])
        })
    }

    /// Advance through blocks until the next packet record, or None at EOF.
    pub fn next_record(&mut self, bytes: &[u8], pos: &mut usize) -> Option<RecMeta> {
        loop {
            if *pos + 8 > bytes.len() {
                return None;
            }
            let btype = self.u32(bytes, *pos)?;

            if btype == BT_SHB {
                // Re-derive endianness (a new section may differ) and reset ifaces.
                if let Some(b) = bytes.get(*pos + 8..*pos + 12) {
                    self.big_endian = matches!(b, [0x1a, 0x2b, 0x3c, 0x4d]);
                }
                self.ifaces.clear();
                let total = self.u32(bytes, *pos + 4)? as usize;
                if total < 12 || *pos + total > bytes.len() {
                    return None;
                }
                *pos += total;
                continue;
            }

            let total = self.u32(bytes, *pos + 4)? as usize;
            if total < 12 || *pos + total > bytes.len() {
                return None;
            }
            let body_start = *pos + 8;
            let body_end = *pos + total - 4;
            let body = bytes.get(body_start..body_end)?;

            match btype {
                BT_IDB => {
                    self.parse_idb(body);
                    *pos += total;
                }
                BT_EPB => {
                    let rec = self.parse_epb(body, body_start);
                    *pos += total;
                    if let Some(r) = rec {
                        return Some(r);
                    }
                }
                BT_SPB => {
                    let rec = self.parse_spb(body, body_start);
                    *pos += total;
                    if let Some(r) = rec {
                        return Some(r);
                    }
                }
                BT_PB => {
                    let rec = self.parse_pb(body, body_start);
                    *pos += total;
                    if let Some(r) = rec {
                        return Some(r);
                    }
                }
                _ => {
                    *pos += total;
                }
            }
        }
    }

    fn parse_idb(&mut self, body: &[u8]) {
        let mut iface = Iface::default();
        if let Some(lt) = self.u16(body, 0) {
            iface.linktype = lt;
        }
        if let Some(sl) = self.u32(body, 4) {
            iface.snaplen = sl;
        }
        // Options begin after the 8-byte fixed IDB fields.
        self.parse_idb_options(&body[8.min(body.len())..], &mut iface);
        self.ifaces.push(iface);
    }

    fn parse_idb_options(&self, mut opts: &[u8], iface: &mut Iface) {
        while opts.len() >= 4 {
            let code = if self.big_endian {
                u16::from_be_bytes([opts[0], opts[1]])
            } else {
                u16::from_le_bytes([opts[0], opts[1]])
            };
            let len = if self.big_endian {
                u16::from_be_bytes([opts[2], opts[3]]) as usize
            } else {
                u16::from_le_bytes([opts[2], opts[3]]) as usize
            };
            if code == 0 {
                break; // opt_endofopt
            }
            let val_start = 4;
            let val_end = val_start + len;
            if val_end > opts.len() {
                break;
            }
            let val = &opts[val_start..val_end];
            match code {
                // if_tsresol: 1 byte
                9 if !val.is_empty() => {
                    let r = val[0];
                    iface.ts_den = if r & 0x80 != 0 {
                        1u64.checked_shl((r & 0x7f) as u32).unwrap_or(1)
                    } else {
                        10u64.checked_pow((r & 0x7f) as u32).unwrap_or(1_000_000)
                    };
                }
                // if_tsoffset: 8 bytes, seconds
                14 if val.len() == 8 => {
                    let secs = if self.big_endian {
                        i64::from_be_bytes(val.try_into().unwrap())
                    } else {
                        i64::from_le_bytes(val.try_into().unwrap())
                    };
                    iface.tsoffset_ns = secs.saturating_mul(1_000_000_000);
                }
                _ => {}
            }
            // advance past value padded to a multiple of 4
            let padded = (len + 3) & !3;
            let step = 4 + padded;
            if step > opts.len() {
                break;
            }
            opts = &opts[step..];
        }
    }

    fn ts_ns(&self, iface: &Iface, high: u32, low: u32) -> i64 {
        let ticks = ((high as u64) << 32) | low as u64;
        let den = iface.ts_den.max(1) as i128;
        let ns = (ticks as i128 * 1_000_000_000i128) / den;
        (ns as i64).saturating_add(iface.tsoffset_ns)
    }

    fn iface(&self, id: usize) -> Iface {
        self.ifaces.get(id).copied().unwrap_or_default()
    }

    fn parse_epb(&self, body: &[u8], body_start: usize) -> Option<RecMeta> {
        if body.len() < 20 {
            return None;
        }
        let iface_id = self.u32(body, 0)? as usize;
        let high = self.u32(body, 4)?;
        let low = self.u32(body, 8)?;
        let caplen = self.u32(body, 12)? as usize;
        let origlen = self.u32(body, 16)?;
        let data_off = body_start + 20;
        let avail = body.len().saturating_sub(20);
        let caplen = caplen.min(avail);
        let iface = self.iface(iface_id);
        Some(RecMeta {
            off: data_off as u64,
            caplen: caplen as u32,
            wirelen: origlen,
            ts_ns: self.ts_ns(&iface, high, low),
            iface: iface_id as u32,
            linktype: iface.linktype,
        })
    }

    fn parse_spb(&self, body: &[u8], body_start: usize) -> Option<RecMeta> {
        if body.len() < 4 {
            return None;
        }
        let origlen = self.u32(body, 0)?;
        let iface = self.iface(0);
        let snap = if iface.snaplen == 0 {
            u32::MAX
        } else {
            iface.snaplen
        };
        let avail = body.len().saturating_sub(4);
        let caplen = (origlen.min(snap) as usize).min(avail);
        Some(RecMeta {
            off: (body_start + 4) as u64,
            caplen: caplen as u32,
            wirelen: origlen,
            ts_ns: 0,
            iface: 0,
            linktype: iface.linktype,
        })
    }

    fn parse_pb(&self, body: &[u8], body_start: usize) -> Option<RecMeta> {
        // Obsolete Packet Block: iface_id(2) drops(2) ts_high(4) ts_low(4) caplen(4) origlen(4)
        if body.len() < 20 {
            return None;
        }
        let iface_id = self.u16(body, 0)? as usize;
        let high = self.u32(body, 4)?;
        let low = self.u32(body, 8)?;
        let caplen = self.u32(body, 12)? as usize;
        let origlen = self.u32(body, 16)?;
        let avail = body.len().saturating_sub(20);
        let caplen = caplen.min(avail);
        let iface = self.iface(iface_id);
        Some(RecMeta {
            off: (body_start + 20) as u64,
            caplen: caplen as u32,
            wirelen: origlen,
            ts_ns: self.ts_ns(&iface, high, low),
            iface: iface_id as u32,
            linktype: iface.linktype,
        })
    }
}
