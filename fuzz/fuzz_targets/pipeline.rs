#![no_main]

//! Fuzz the whole read → dissect → flow → reassembly pipeline, not just the frame dissector.
//!
//! Arbitrary bytes are wrapped as a single pcap record and run through `pipeline::run`, which
//! exercises the reader, the panic-isolation boundary, IP-fragment and TCP reassembly, and the
//! flow table — paths `dissect_frame` alone never reaches. The invariant is the same: no
//! panic, no hang, no unbounded memory, whatever the input.

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use pcapracer::pipeline::{run, Config};

/// Wrap arbitrary bytes as a classic little-endian pcap: global header + one record whose
/// payload is the fuzz input.
fn wrap_as_pcap(linktype: u32, frame: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + 16 + frame.len());
    v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    v.extend_from_slice(&2u16.to_le_bytes()); // version major
    v.extend_from_slice(&4u16.to_le_bytes()); // version minor
    v.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    v.extend_from_slice(&0xffffu32.to_le_bytes()); // snaplen
    v.extend_from_slice(&linktype.to_le_bytes()); // network
    // Record header.
    v.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    v.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    v.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
    v.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
    v.extend_from_slice(frame);
    v
}

const LINKTYPES: &[u32] = &[1, 101, 113, 228, 276];

fuzz_target!(|data: &[u8]| {
    let (linktype, frame) = match data.split_first() {
        Some((sel, rest)) => (LINKTYPES[*sel as usize % LINKTYPES.len()], rest),
        None => return,
    };

    let bytes = wrap_as_pcap(linktype, frame);
    let mut path = std::env::temp_dir();
    path.push(format!("pcapracer-fuzz-pipeline-{}.pcap", std::process::id()));
    if let Ok(mut f) = std::fs::File::create(&path) {
        if f.write_all(&bytes).is_err() {
            return;
        }
    } else {
        return;
    }

    // Reassembly on, so the fragment and TCP-stream paths are fuzzed too.
    let _ = run(&path, Config::default(), |_batch| Ok(()));
});
