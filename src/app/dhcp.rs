//! Minimal DHCP/BOOTP detection (sets the inline `app_proto` column).

use crate::decode::PacketMeta;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

pub fn detect(payload: &[u8], meta: &mut PacketMeta) {
    // BOOTP fixed area is 236 bytes, followed by the DHCP magic cookie.
    if payload.len() >= 240 && payload[236..240] == MAGIC_COOKIE {
        meta.app_proto = Some("dhcp");
    }
}
