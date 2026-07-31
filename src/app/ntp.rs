//! Minimal NTP detection (sets the inline `app_proto` column).

use crate::decode::PacketMeta;

pub fn detect(payload: &[u8], meta: &mut PacketMeta) {
    // NTP packets are >= 48 bytes; mode is the low 3 bits of the first byte.
    if payload.len() >= 48 {
        let mode = payload[0] & 0x07;
        if (1..=5).contains(&mode) {
            meta.app_proto = Some("ntp");
        }
    }
}
