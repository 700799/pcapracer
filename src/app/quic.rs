//! QUIC long-header detection: extracts version and destination connection ID.

use crate::decode::PacketMeta;
use crate::util::hex_string;

pub fn detect(payload: &[u8], meta: &mut PacketMeta) {
    if payload.len() < 6 {
        return;
    }
    let first = payload[0];
    // Long header form: high bit set. (Short-header packets can't be identified
    // without connection state, so we only report long-header packets.)
    if first & 0x80 == 0 {
        return;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let dcid_len = payload[5] as usize;
    if 6 + dcid_len > payload.len() || dcid_len > 20 {
        return;
    }
    meta.app_proto = Some("quic");
    meta.quic_version = Some(version);
    if dcid_len > 0 {
        meta.quic_dcid = Some(hex_string(&payload[6..6 + dcid_len]));
    }
}
