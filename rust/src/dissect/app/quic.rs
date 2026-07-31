//! QUIC long-header packets.
//!
//! Initial packet payloads are encrypted under a key derived from the connection ID, so the
//! ClientHello inside is not readable without doing that derivation. What is available in
//! cleartext — version, packet type, and both connection IDs — is extracted here; those are
//! enough to track a QUIC connection across a NAT rebind, which is the usual reason to want
//! them. `quic_sni` stays null rather than guessing.

use crate::bytes::{hex, Cur};
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

pub fn looks_like_quic(d: &[u8]) -> bool {
    // Long header form: high bit set, fixed bit set, and a version we recognise.
    if d.len() < 5 || d[0] & 0x80 == 0 {
        return false;
    }
    let v = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
    v == 0 || v == 1 || v == 0x6b33_43cf || (v & 0xffff_ff00) == 0xff00_0000
}

pub fn parse(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("quic");
    let mut c = Cur::new(payload);
    let first = c.u8()?;
    ctx.pkt.quic_header_form = Some(first >> 7);

    // Short-header packets carry no version or connection IDs we can locate without
    // connection state, so there is nothing more to extract.
    if first & 0x80 == 0 {
        return Ok(());
    }

    let version = c.be32()?;
    ctx.pkt.quic_version = Some(version);
    // The packet type field is only meaningful for QUIC v1; a version-negotiation packet
    // uses version 0 and has no type.
    if version != 0 {
        ctx.pkt.quic_packet_type = Some((first >> 4) & 0x03);
    }

    let dcid_len = c.u8()? as usize;
    if dcid_len > 20 {
        return Err(DissectError::Malformed);
    }
    ctx.pkt.quic_dcid = Some(hex(c.take(dcid_len)?));

    let scid_len = c.u8()? as usize;
    if scid_len > 20 {
        return Err(DissectError::Malformed);
    }
    ctx.pkt.quic_scid = Some(hex(c.take(scid_len)?));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn run(payload: &[u8]) -> (Packet, Result<(), DissectError>) {
        let mut p = Packet::default();
        let r = {
            let mut ctx = Ctx::new(&mut p);
            parse(payload, &mut ctx)
        };
        (p, r)
    }

    #[test]
    fn initial_packet_connection_ids() {
        let mut v = vec![0xc0]; // long header, Initial
        v.extend_from_slice(&1u32.to_be_bytes()); // QUIC v1
        v.push(4);
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        v.push(2);
        v.extend_from_slice(&[0x01, 0x02]);

        let (p, r) = run(&v);
        r.unwrap();
        assert_eq!(p.quic_version, Some(1));
        assert_eq!(p.quic_packet_type, Some(0));
        assert_eq!(p.quic_dcid.as_deref(), Some("deadbeef"));
        assert_eq!(p.quic_scid.as_deref(), Some("0102"));
        // The encrypted ClientHello is not guessed at.
        assert!(p.quic_sni.is_none());
    }

    #[test]
    fn oversized_connection_id_is_rejected() {
        let mut v = vec![0xc0];
        v.extend_from_slice(&1u32.to_be_bytes());
        v.push(21); // beyond the 20-byte maximum
        v.extend_from_slice(&[0u8; 21]);
        assert_eq!(run(&v).1, Err(DissectError::Malformed));
    }

    #[test]
    fn sniffing() {
        assert!(looks_like_quic(&[0xc0, 0, 0, 0, 1]));
        assert!(!looks_like_quic(b"GET /"));
    }
}
