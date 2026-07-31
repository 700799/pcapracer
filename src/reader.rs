//! Input reading: memory-mapped pcap (and, added in M2, pcapng + gzip).
//!
//! Records are yielded in fixed-size [`RawBatch`]es of `(offset, caplen, ...)`
//! metadata pointing into shared [`BatchData`], preserving zero-copy for the
//! mmap path.

use crate::config::Config;
use crate::error::{Error, Result};
use memmap2::Mmap;
use std::fs::File;
use std::sync::Arc;

/// Per-record metadata; `off` indexes into the owning batch's bytes.
#[derive(Clone, Copy, Debug)]
pub struct RecMeta {
    pub off: u64,
    pub caplen: u32,
    pub wirelen: u32,
    pub ts_ns: i64,
    pub iface: u32,
    pub linktype: u16,
}

/// Backing storage for a batch of records.
pub enum BatchData {
    Mmap(Arc<Mmap>),
    Owned(Vec<u8>),
}

impl BatchData {
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match self {
            BatchData::Mmap(m) => &m[..],
            BatchData::Owned(v) => v,
        }
    }
}

/// A batch of decoded record metadata sharing one backing buffer.
pub struct RawBatch {
    pub idx: u64,
    pub data: Arc<BatchData>,
    pub recs: Vec<RecMeta>,
}

#[derive(Clone, Copy)]
struct PcapFmt {
    big_endian: bool,
    nanos: bool,
    linktype: u16,
}

/// Streaming reader over an input file, yielding [`RawBatch`]es.
pub struct Reader {
    data: Arc<BatchData>,
    kind: Kind,
    pos: usize,
    idx: u64,
    batch_size: usize,
    pub total_records: u64,
}

enum Kind {
    Pcap(PcapFmt),
    Pcapng(crate::reader_ng::PcapngState),
}

impl Reader {
    pub fn open(cfg: &Config) -> Result<Reader> {
        let path = &cfg.input;
        let is_gz = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("gz"))
            .unwrap_or(false);

        let data = if is_gz {
            BatchData::Owned(read_gz(path)?)
        } else {
            let file = File::open(path)?;
            // SAFETY: file is opened read-only; we treat the map as immutable
            // bytes and never mutate through it.
            let mmap = unsafe { Mmap::map(&file)? };
            #[cfg(unix)]
            let _ = mmap.advise(memmap2::Advice::Sequential);
            BatchData::Mmap(Arc::new(mmap))
        };
        let data = Arc::new(data);
        let bytes = data.bytes();

        if bytes.len() < 4 {
            return Err(Error::Invalid("file too small to be a capture".into()));
        }
        let magic = &bytes[0..4];
        let (kind, start) = if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            let (state, start) = crate::reader_ng::PcapngState::open(bytes)?;
            (Kind::Pcapng(state), start)
        } else if let Some(fmt) = detect_pcap(bytes) {
            (Kind::Pcap(fmt), 24)
        } else {
            return Err(Error::Invalid(format!(
                "unrecognized capture format (magic {:02x}{:02x}{:02x}{:02x})",
                magic[0], magic[1], magic[2], magic[3]
            )));
        };

        Ok(Reader {
            data,
            kind,
            pos: start,
            idx: 0,
            batch_size: cfg.batch_size.max(1),
            total_records: 0,
        })
    }
}

impl Iterator for Reader {
    type Item = RawBatch;

    fn next(&mut self) -> Option<RawBatch> {
        let bytes = self.data.bytes();
        let mut recs = Vec::with_capacity(self.batch_size);
        while recs.len() < self.batch_size {
            let rec = match &mut self.kind {
                Kind::Pcap(fmt) => next_pcap_record(bytes, &mut self.pos, fmt),
                Kind::Pcapng(state) => state.next_record(bytes, &mut self.pos),
            };
            match rec {
                Some(r) => recs.push(r),
                None => break,
            }
        }
        if recs.is_empty() {
            return None;
        }
        self.total_records += recs.len() as u64;
        let batch = RawBatch {
            idx: self.idx,
            data: Arc::clone(&self.data),
            recs,
        };
        self.idx += 1;
        Some(batch)
    }
}

fn detect_pcap(bytes: &[u8]) -> Option<PcapFmt> {
    let m = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let (big_endian, nanos) = match m {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        _ => return None,
    };
    if bytes.len() < 24 {
        return None;
    }
    let linktype = if big_endian {
        u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
    } else {
        u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
    } as u16;
    Some(PcapFmt {
        big_endian,
        nanos,
        linktype,
    })
}

fn next_pcap_record(bytes: &[u8], pos: &mut usize, fmt: &PcapFmt) -> Option<RecMeta> {
    let hdr = bytes.get(*pos..*pos + 16)?;
    let (ts_sec, ts_frac, caplen, origlen) = if fmt.big_endian {
        (
            u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
            u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
            u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
            u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
        )
    } else {
        (
            u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
            u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
            u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
            u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
        )
    };
    let data_start = *pos + 16;
    // Clamp a lying/oversized caplen to what's actually present.
    let avail = bytes.len().saturating_sub(data_start);
    let caplen = (caplen as usize).min(avail);
    let frac_ns = if fmt.nanos {
        ts_frac as i64
    } else {
        (ts_frac as i64) * 1000
    };
    let ts_ns = (ts_sec as i64) * 1_000_000_000 + frac_ns;
    *pos = data_start + caplen;
    Some(RecMeta {
        off: data_start as u64,
        caplen: caplen as u32,
        wirelen: origlen,
        ts_ns,
        iface: 0,
        linktype: fmt.linktype,
    })
}

fn read_gz(path: &std::path::Path) -> Result<Vec<u8>> {
    use flate2::read::MultiGzDecoder;
    use std::io::Read;
    let file = File::open(path)?;
    let mut dec = MultiGzDecoder::new(file);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}
