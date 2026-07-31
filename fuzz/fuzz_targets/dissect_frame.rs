#![no_main]

//! Fuzz the dissect entry point across every supported link type.
//!
//! The invariant: arbitrary bytes must produce an `Ok` or an `Err`, never a panic, a hang,
//! or unbounded memory growth.

use libfuzzer_sys::fuzz_target;
use pcapracer::dissect::{dissect_frame, Ctx};
use pcapracer::schema::Packet;

/// Every link type the dissector claims to handle, so a crash in a rarely used one is not
/// hidden behind Ethernet's coverage.
const LINKTYPES: &[u16] = &[0, 1, 9, 101, 105, 108, 113, 127, 228, 229, 276];

fuzz_target!(|data: &[u8]| {
    // The first byte selects the link type so a single corpus covers all of them.
    let (linktype, frame) = match data.split_first() {
        Some((sel, rest)) => (LINKTYPES[*sel as usize % LINKTYPES.len()], rest),
        None => return,
    };

    let mut pkt = Packet::default();
    let mut ctx = Ctx::new(&mut pkt);
    let _ = dissect_frame(frame, linktype, &mut ctx);
    ctx.finish();
});
