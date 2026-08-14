//! Capture file reading: pcap, pcapng, and gzip-compressed variants of both.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};

use crate::error::{Error, Result};

/// One packet as it came off disk, before any dissection.
pub struct RawPacket<'a> {
    /// Nanoseconds since the Unix epoch.
    pub ts_ns: i64,
    /// Bytes actually captured (may be less than `orig_len` under a snaplen).
    pub cap_len: u32,
    /// Length on the wire.
    pub orig_len: u32,
    pub iface_id: u32,
    pub linktype: u16,
    pub data: &'a [u8],
}

impl RawPacket<'_> {
    /// True when the capture was cut short by the snaplen.
    pub fn is_truncated(&self) -> bool {
        self.orig_len > self.cap_len
    }
}

/// Per-interface timestamp parameters from a pcapng IDB.
#[derive(Clone, Copy)]
struct Iface {
    linktype: u16,
    resolution: u64,
    ts_offset: i64,
}

impl Default for Iface {
    fn default() -> Self {
        // Microseconds is the pcapng default when if_tsresol is absent.
        Iface {
            linktype: 1,
            resolution: 1_000_000,
            ts_offset: 0,
        }
    }
}

pub struct CaptureReader {
    inner: Box<dyn PcapReaderIterator + Send>,
    /// Legacy pcap: link type and whether timestamps are nanoseconds.
    legacy_linktype: u16,
    legacy_nanos: bool,
    ifaces: Vec<Iface>,
}

/// Counters describing what the reader saw.
#[derive(Debug, Default, Clone)]
pub struct ReadStats {
    pub packets: u64,
    pub bytes: u64,
    /// Blocks that could not be parsed at all. A non-zero count means the file is damaged.
    pub bad_blocks: u64,
}

const READ_BUFFER: usize = 1 << 20;

impl CaptureReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mut probe = BufReader::new(file);

        // Sniff for gzip so `.pcap.gz` works without the caller decompressing first.
        let mut magic = [0u8; 2];
        let n = read_exact_or_less(&mut probe, &mut magic)?;
        let reader: Box<dyn Read + Send> = {
            let file = File::open(path)?;
            if n == 2 && magic == [0x1f, 0x8b] {
                Box::new(flate2::read::MultiGzDecoder::new(BufReader::new(file)))
            } else {
                Box::new(BufReader::with_capacity(READ_BUFFER, file))
            }
        };

        let inner = create_reader(READ_BUFFER, reader).map_err(|e| {
            Error::Format(format!(
                "{}: not a pcap or pcapng capture ({e:?})",
                path.display()
            ))
        })?;

        Ok(CaptureReader {
            inner,
            legacy_linktype: 1,
            legacy_nanos: false,
            ifaces: Vec::new(),
        })
    }

    /// Call `f` for every packet in the file.
    ///
    /// A block that fails to parse is counted and skipped rather than aborting the run: a
    /// capture truncated by a full disk is common, and the packets before the damage are
    /// still worth extracting.
    pub fn for_each<F>(&mut self, mut f: F) -> Result<ReadStats>
    where
        F: FnMut(RawPacket<'_>),
    {
        let mut stats = ReadStats::default();

        loop {
            match self.inner.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            self.legacy_linktype = hdr.network.0 as u16;
                            // 0xa1b23c4d (and its byte-swapped form) marks nanosecond
                            // timestamps; the classic magic means microseconds.
                            self.legacy_nanos =
                                hdr.magic_number == 0xa1b2_3c4d || hdr.magic_number == 0x4d3c_b2a1;
                        }
                        PcapBlockOwned::Legacy(b) => {
                            let frac = if self.legacy_nanos {
                                b.ts_usec as i64
                            } else {
                                b.ts_usec as i64 * 1_000
                            };
                            let ts_ns = (b.ts_sec as i64).saturating_mul(1_000_000_000) + frac;
                            stats.packets += 1;
                            stats.bytes += b.caplen as u64;
                            f(RawPacket {
                                ts_ns,
                                cap_len: b.caplen,
                                orig_len: b.origlen,
                                iface_id: 0,
                                linktype: self.legacy_linktype,
                                data: b.data,
                            });
                        }
                        PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                            // A new section restarts interface numbering.
                            self.ifaces.clear();
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            self.ifaces.push(Iface {
                                linktype: idb.linktype.0 as u16,
                                resolution: idb.ts_resolution().unwrap_or(1_000_000),
                                ts_offset: idb.if_tsoffset,
                            });
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                            let iface = self
                                .ifaces
                                .get(epb.if_id as usize)
                                .copied()
                                .unwrap_or_default();
                            let raw = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                            stats.packets += 1;
                            stats.bytes += epb.caplen as u64;
                            f(RawPacket {
                                ts_ns: ticks_to_ns(raw, iface.resolution, iface.ts_offset),
                                cap_len: epb.caplen,
                                orig_len: epb.origlen,
                                iface_id: epb.if_id,
                                linktype: iface.linktype,
                                // The block pads packet data to a 4-byte boundary; trim it,
                                // or the padding would be dissected as payload.
                                data: &epb.data[..(epb.caplen as usize).min(epb.data.len())],
                            });
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                            let iface = self.ifaces.first().copied().unwrap_or_default();
                            let len = spb.origlen as usize;
                            stats.packets += 1;
                            stats.bytes += spb.data.len() as u64;
                            f(RawPacket {
                                // Simple packet blocks carry no timestamp at all.
                                ts_ns: 0,
                                cap_len: spb.data.len().min(len) as u32,
                                orig_len: spb.origlen,
                                iface_id: 0,
                                linktype: iface.linktype,
                                data: &spb.data[..len.min(spb.data.len())],
                            });
                        }
                        PcapBlockOwned::NG(_) => {}
                    }
                    self.inner.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    // The block spans the end of the buffer; pull more bytes and retry.
                    if self.inner.refill().is_err() {
                        break;
                    }
                }
                Err(_) => {
                    stats.bad_blocks += 1;
                    // Without a valid block we cannot know how far to skip, so stop here
                    // rather than resynchronising on a guess.
                    break;
                }
            }
        }
        Ok(stats)
    }
}

/// Convert a pcapng tick count to nanoseconds since the epoch.
fn ticks_to_ns(raw: u64, resolution: u64, ts_offset: i64) -> i64 {
    if resolution == 0 {
        return 0;
    }
    // u128 keeps the multiply from overflowing for high-resolution clocks.
    let ns = (raw as u128) * 1_000_000_000u128 / resolution as u128;
    let offset_ns = (ts_offset as i128) * 1_000_000_000i128;
    (ns as i128 + offset_ns).clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn read_exact_or_less<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal legacy pcap with the given link type and records.
    pub fn build_pcap(linktype: u32, nanos: bool, records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        let magic: u32 = if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
        v.extend_from_slice(&magic.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&linktype.to_le_bytes());
        for (sec, frac, data) in records {
            v.extend_from_slice(&sec.to_le_bytes());
            v.extend_from_slice(&frac.to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(data);
        }
        v
    }

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("pcapracer-test-{}-{}", std::process::id(), name));
        let mut f = File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    #[test]
    fn reads_legacy_pcap_records() {
        let data = build_pcap(
            1,
            false,
            &[(100, 500_000, &[0xaa; 60]), (101, 0, &[0xbb; 40])],
        );
        let path = write_temp("legacy.pcap", &data);

        let mut r = CaptureReader::open(&path).unwrap();
        let mut seen = Vec::new();
        let stats = r
            .for_each(|p| seen.push((p.ts_ns, p.cap_len, p.linktype, p.data.len())))
            .unwrap();

        assert_eq!(stats.packets, 2);
        assert_eq!(seen[0], (100_500_000_000, 60, 1, 60));
        assert_eq!(seen[1], (101_000_000_000, 40, 1, 40));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn nanosecond_magic_is_honoured() {
        let data = build_pcap(1, true, &[(100, 500_000, &[0u8; 20])]);
        let path = write_temp("nanos.pcap", &data);
        let mut r = CaptureReader::open(&path).unwrap();
        let mut ts = 0;
        r.for_each(|p| ts = p.ts_ns).unwrap();
        // 500_000 is read as nanoseconds here, not microseconds.
        assert_eq!(ts, 100_000_500_000);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn gzip_captures_are_decompressed_transparently() {
        use flate2::write::GzEncoder;
        let raw = build_pcap(1, false, &[(7, 0, &[0xcc; 32])]);
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(&raw).unwrap();
        let path = write_temp("compressed.pcap.gz", &enc.finish().unwrap());

        let mut r = CaptureReader::open(&path).unwrap();
        let mut n = 0;
        r.for_each(|_| n += 1).unwrap();
        assert_eq!(n, 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_non_capture_file_is_a_clear_error() {
        let path = write_temp("garbage.bin", b"this is not a capture file at all");
        match CaptureReader::open(&path) {
            Err(Error::Format(_)) => {}
            Err(other) => panic!("expected a format error, got {other:?}"),
            Ok(_) => panic!("a garbage file must not open as a capture"),
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn truncation_is_detectable() {
        let p = RawPacket {
            ts_ns: 0,
            cap_len: 96,
            orig_len: 1514,
            iface_id: 0,
            linktype: 1,
            data: &[],
        };
        assert!(p.is_truncated());
    }

    #[test]
    fn tick_conversion() {
        // Microsecond resolution.
        assert_eq!(ticks_to_ns(1_500_000, 1_000_000, 0), 1_500_000_000);
        // Nanosecond resolution.
        assert_eq!(ticks_to_ns(1_500_000_000, 1_000_000_000, 0), 1_500_000_000);
        // A zero resolution would divide by zero.
        assert_eq!(ticks_to_ns(5, 0, 0), 0);
    }
}
