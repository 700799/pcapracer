//! IP fragment and TCP stream reassembly.
//!
//! Both are strictly bounded. A capture is untrusted input, and the natural implementation of
//! either — hold everything until the message completes — is a memory-exhaustion bug waiting
//! for a crafted file with a million never-completed fragments. Every buffer here has a cap,
//! and anything dropped is counted rather than silently discarded.

use ahash::AHashMap;

use crate::dissect::Tuple;

/// Per-flow reassembly buffer ceiling. Enough for a large HTTP request head or an SMB
/// negotiate exchange; anything beyond is bulk transfer that L7 dissection gains nothing from.
pub const DEFAULT_MAX_STREAM_BYTES: usize = 1 << 20; // 1 MiB

/// Distinct reassembly buffers held at once.
pub const DEFAULT_MAX_STREAMS: usize = 1 << 18; // ~262k

/// Fragment sets held at once.
pub const DEFAULT_MAX_FRAG_SETS: usize = 1 << 16;

// ---------------------------------------------------------------------------
// IP fragments
// ---------------------------------------------------------------------------

/// Identity of a datagram being reassembled: RFC 791 specifies (src, dst, id, protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub id: u32,
    pub proto: u8,
}

/// Fragment metadata surfaced by L3 dissection for the serial reassembly pass. The payload
/// is copied out because reassembly happens after the (possibly parallel) dissection phase,
/// so it cannot borrow the frame buffer.
#[derive(Debug, Clone)]
pub struct FragMeta {
    pub key: FragKey,
    pub offset: u16,
    pub more_fragments: bool,
    pub payload: Vec<u8>,
}

#[derive(Default)]
struct FragSet {
    /// (offset, bytes) pieces, kept unsorted until assembly.
    pieces: Vec<(u16, Vec<u8>)>,
    total_len: Option<usize>,
    bytes_held: usize,
}

#[derive(Default)]
pub struct FragTable {
    sets: AHashMap<FragKey, FragSet>,
    max_sets: usize,
    max_bytes: usize,
    pub dropped: u64,
    pub completed: u64,
}

impl FragTable {
    pub fn new(max_sets: usize, max_bytes: usize) -> Self {
        FragTable {
            sets: AHashMap::new(),
            max_sets,
            max_bytes,
            dropped: 0,
            completed: 0,
        }
    }

    /// Add a fragment. Returns the reassembled payload once the datagram is complete.
    pub fn push(
        &mut self,
        key: FragKey,
        offset: u16,
        more_fragments: bool,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        if !self.sets.contains_key(&key) && self.sets.len() >= self.max_sets {
            self.dropped += 1;
            return None;
        }
        let set = self.sets.entry(key).or_default();

        if set.bytes_held + data.len() > self.max_bytes {
            // Over budget for this datagram: abandon it entirely rather than assembling a
            // partial payload that would dissect into wrong field values.
            self.sets.remove(&key);
            self.dropped += 1;
            return None;
        }

        // The last fragment (MF clear) is what tells us the total length.
        if !more_fragments {
            set.total_len = Some(offset as usize + data.len());
        }
        set.bytes_held += data.len();
        set.pieces.push((offset, data.to_vec()));

        let total = set.total_len?;
        // Assemble only once the pieces cover [0, total) with no hole.
        let mut pieces: Vec<(u16, Vec<u8>)> = std::mem::take(&mut set.pieces);
        pieces.sort_by_key(|(o, _)| *o);

        let mut out = Vec::with_capacity(total);
        for (off, bytes) in &pieces {
            let off = *off as usize;
            if off > out.len() {
                // Hole: put the pieces back and wait for more.
                let set = self.sets.get_mut(&key)?;
                set.pieces = pieces;
                return None;
            }
            // Overlapping fragments are a classic evasion; the earlier copy wins, matching
            // the conservative choice most modern stacks make.
            if off + bytes.len() > out.len() {
                let skip = out.len() - off;
                out.extend_from_slice(&bytes[skip..]);
            }
        }

        if out.len() < total {
            let set = self.sets.get_mut(&key)?;
            set.pieces = pieces;
            return None;
        }

        self.sets.remove(&key);
        self.completed += 1;
        out.truncate(total);
        Some(out)
    }

    pub fn pending(&self) -> usize {
        self.sets.len()
    }
}

// ---------------------------------------------------------------------------
// TCP streams
// ---------------------------------------------------------------------------

/// One direction of one TCP conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub flow: Tuple,
    /// True for the direction matching the normalised tuple.
    pub forward: bool,
}

#[derive(Default)]
struct Stream {
    /// Sequence number the buffer starts at, once known.
    base_seq: Option<u32>,
    buf: Vec<u8>,
    /// Out-of-order segments waiting for the gap ahead of them to fill.
    pending: Vec<(u32, Vec<u8>)>,
    truncated: bool,
}

/// What reassembly produced for a segment.
pub struct Reassembled<'a> {
    /// The bytes L7 dissection should run against.
    pub data: &'a [u8],
    /// True when `data` spans more than this one segment.
    pub multi_segment: bool,
    /// True when the stream hit its byte cap and earlier data was dropped.
    pub partial: bool,
}

#[derive(Default)]
pub struct StreamTable {
    streams: AHashMap<StreamKey, Stream>,
    max_streams: usize,
    max_bytes: usize,
    pub evicted: u64,
    pub truncated: u64,
}

impl StreamTable {
    pub fn new(max_streams: usize, max_bytes: usize) -> Self {
        StreamTable {
            streams: AHashMap::new(),
            max_streams,
            max_bytes,
            evicted: 0,
            truncated: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Feed a segment in, and get back the contiguous stream prefix to dissect.
    ///
    /// Returns `None` when the table is at capacity, in which case the caller should fall
    /// back to dissecting the bare segment.
    pub fn push(&mut self, key: StreamKey, seq: u32, payload: &[u8]) -> Option<Reassembled<'_>> {
        if payload.is_empty() {
            return None;
        }
        if !self.streams.contains_key(&key) && self.streams.len() >= self.max_streams {
            self.evicted += 1;
            return None;
        }
        let max_bytes = self.max_bytes;
        let s = self.streams.entry(key).or_default();

        let base = *s.base_seq.get_or_insert(seq);
        // Sequence numbers wrap at 2^32; wrapping arithmetic gives the right offset either
        // side of the wrap, as long as the stream stays under 2 GiB (it does — see the cap).
        let offset = seq.wrapping_sub(base) as usize;

        let mut appended = false;
        if offset == s.buf.len() {
            s.buf.extend_from_slice(payload);
            appended = true;
        } else if offset < s.buf.len() {
            // Retransmission or overlap: keep what we already have, append only new tail.
            let end = offset + payload.len();
            if end > s.buf.len() {
                let skip = s.buf.len() - offset;
                s.buf.extend_from_slice(&payload[skip..]);
                appended = true;
            }
        } else if offset < max_bytes {
            // Ahead of the gap: hold it until the missing segment arrives.
            s.pending.push((seq, payload.to_vec()));
            if s.pending.len() > 64 {
                // A stream that accumulates this many holes is not going to converge.
                s.pending.clear();
                s.truncated = true;
            }
        }

        // Drain anything that now sits flush against the buffer.
        if appended && !s.pending.is_empty() {
            let mut progress = true;
            while progress {
                progress = false;
                let buf_end = base.wrapping_add(s.buf.len() as u32);
                if let Some(i) = s.pending.iter().position(|(q, _)| *q == buf_end) {
                    let (_, bytes) = s.pending.remove(i);
                    s.buf.extend_from_slice(&bytes);
                    progress = true;
                }
            }
        }

        if s.buf.len() > max_bytes {
            s.buf.truncate(max_bytes);
            if !s.truncated {
                s.truncated = true;
                self.truncated += 1;
            }
        }

        let s = self.streams.get(&key)?;
        Some(Reassembled {
            data: &s.buf,
            multi_segment: s.buf.len() > payload.len(),
            partial: s.truncated,
        })
    }

    /// Forget a stream — called when the connection closes, so long captures do not hold
    /// every conversation they ever saw.
    pub fn close(&mut self, key: &StreamKey) {
        self.streams.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn key() -> StreamKey {
        StreamKey {
            flow: Tuple {
                src_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
                dst_ip: "10.0.0.2".parse::<IpAddr>().unwrap(),
                src_port: 1234,
                dst_port: 80,
                proto: 6,
            },
            forward: true,
        }
    }

    #[test]
    fn in_order_segments_concatenate() {
        let mut t = StreamTable::new(100, 4096);
        let k = key();
        assert_eq!(t.push(k, 1000, b"GET / HT").unwrap().data, b"GET / HT");
        let r = t.push(k, 1008, b"TP/1.1\r\n").unwrap();
        assert_eq!(r.data, b"GET / HTTP/1.1\r\n");
        assert!(r.multi_segment);
        assert!(!r.partial);
    }

    #[test]
    fn out_of_order_segments_are_held_then_joined() {
        let mut t = StreamTable::new(100, 4096);
        let k = key();
        t.push(k, 1000, b"AAAA").unwrap();
        // Arrives before the segment that precedes it.
        let r = t.push(k, 1008, b"CCCC").unwrap();
        assert_eq!(r.data, b"AAAA");
        // The gap filler releases both.
        let r = t.push(k, 1004, b"BBBB").unwrap();
        assert_eq!(r.data, b"AAAABBBBCCCC");
    }

    #[test]
    fn retransmissions_do_not_duplicate() {
        let mut t = StreamTable::new(100, 4096);
        let k = key();
        t.push(k, 1000, b"HELLO").unwrap();
        let r = t.push(k, 1000, b"HELLO").unwrap();
        assert_eq!(r.data, b"HELLO");
    }

    #[test]
    fn overlapping_retransmission_keeps_the_original_bytes() {
        let mut t = StreamTable::new(100, 4096);
        let k = key();
        t.push(k, 1000, b"AAAA").unwrap();
        // An overlapping segment rewriting earlier bytes is a classic IDS evasion; the first
        // copy must win.
        let r = t.push(k, 1002, b"XXBB").unwrap();
        assert_eq!(r.data, b"AAAABB");
    }

    #[test]
    fn stream_byte_cap_is_enforced_and_reported() {
        let mut t = StreamTable::new(100, 16);
        let k = key();
        let mut seq = 1000u32;
        for _ in 0..8 {
            t.push(k, seq, &[b'x'; 8]);
            seq = seq.wrapping_add(8);
        }
        let r = t.push(k, seq, b"tail").unwrap();
        assert_eq!(r.data.len(), 16);
        assert!(r.partial);
        assert_eq!(t.truncated, 1);
    }

    #[test]
    fn stream_table_capacity_falls_back_rather_than_growing() {
        let mut t = StreamTable::new(1, 4096);
        let mut k = key();
        t.push(k, 1, b"a").unwrap();
        k.forward = false;
        assert!(t.push(k, 1, b"b").is_none());
        assert_eq!(t.evicted, 1);
    }

    #[test]
    fn sequence_wraparound_is_handled() {
        let mut t = StreamTable::new(100, 4096);
        let k = key();
        let base = u32::MAX - 3;
        t.push(k, base, b"ABCD").unwrap();
        // Next segment's sequence number wraps past zero.
        let r = t.push(k, base.wrapping_add(4), b"EFGH").unwrap();
        assert_eq!(r.data, b"ABCDEFGH");
    }

    fn frag_key() -> FragKey {
        FragKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            id: 42,
            proto: 6,
        }
    }

    #[test]
    fn fragments_reassemble_in_any_order() {
        let mut t = FragTable::new(100, 65536);
        let k = frag_key();
        assert!(t.push(k, 8, false, b"WORLD").is_none());
        let out = t.push(k, 0, true, b"HELLO123").unwrap();
        assert_eq!(out, b"HELLO123WORLD");
        assert_eq!(t.completed, 1);
        assert_eq!(t.pending(), 0);
    }

    #[test]
    fn a_hole_leaves_the_datagram_incomplete() {
        let mut t = FragTable::new(100, 65536);
        let k = frag_key();
        assert!(t.push(k, 16, false, b"END").is_none());
        // Offset 8 is still missing.
        assert!(t.push(k, 0, true, b"ABCDEFGH").is_none());
        assert_eq!(t.completed, 0);
        assert_eq!(t.pending(), 1);
    }

    #[test]
    fn oversized_fragment_sets_are_dropped_and_counted() {
        let mut t = FragTable::new(100, 16);
        let k = frag_key();
        t.push(k, 0, true, &[0u8; 12]);
        assert!(t.push(k, 12, true, &[0u8; 12]).is_none());
        assert_eq!(t.dropped, 1);
        assert_eq!(t.pending(), 0);
    }
}
