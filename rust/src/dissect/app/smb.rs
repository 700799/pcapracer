//! SMB1/SMB2 headers and the NTLM messages that ride inside them.

use crate::bytes::{cap, Cur};
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

const SMB1_MAGIC: &[u8] = b"\xffSMB";
const SMB2_MAGIC: &[u8] = b"\xfeSMB";
const NTLMSSP: &[u8] = b"NTLMSSP\0";

pub fn looks_like_smb(d: &[u8]) -> bool {
    d.len() >= 4 && (d.starts_with(SMB1_MAGIC) || d.starts_with(SMB2_MAGIC))
}

fn smb2_command_name(c: u16) -> &'static str {
    match c {
        0 => "NEGOTIATE",
        1 => "SESSION_SETUP",
        2 => "LOGOFF",
        3 => "TREE_CONNECT",
        4 => "TREE_DISCONNECT",
        5 => "CREATE",
        6 => "CLOSE",
        7 => "FLUSH",
        8 => "READ",
        9 => "WRITE",
        10 => "LOCK",
        11 => "IOCTL",
        12 => "CANCEL",
        13 => "ECHO",
        14 => "QUERY_DIRECTORY",
        15 => "CHANGE_NOTIFY",
        16 => "QUERY_INFO",
        17 => "SET_INFO",
        18 => "OPLOCK_BREAK",
        _ => "UNKNOWN",
    }
}

pub fn parse(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    // Over TCP/445 the message is framed by a four-byte NetBIOS session header.
    let body = if payload.len() > 4 && !looks_like_smb(payload) && payload[0] == 0x00 {
        &payload[4..]
    } else {
        payload
    };

    if body.starts_with(SMB2_MAGIC) {
        return smb2(body, ctx);
    }
    if body.starts_with(SMB1_MAGIC) {
        return smb1(body, ctx);
    }
    Err(DissectError::Malformed)
}

fn smb2(body: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("smb2");
    ctx.pkt.smb_version = Some("SMB2".to_string());

    let mut c = Cur::new(body);
    c.skip(4)?; // magic
    let _structure_size = c.le16()?;
    let _credit_charge = c.le16()?;
    let status = c.le32()?;
    let command = c.le16()?;
    let _credits = c.le16()?;
    let flags = c.le32()?;
    let _next_command = c.le32()?;
    let _message_id = c.le64()?;
    let _reserved = c.le32()?;
    let tree_id = c.le32()?;
    let session_id = c.le64()?;

    ctx.pkt.smb_status = Some(status);
    ctx.pkt.smb_command = Some(command);
    ctx.pkt.smb_command_name = Some(smb2_command_name(command).to_string());
    ctx.pkt.smb_flags = Some(flags);
    ctx.pkt.smb_tree_id = Some(tree_id);
    ctx.pkt.smb_session_id = Some(session_id);

    let rest = c.take_rest();
    match command {
        // TREE_CONNECT: a UTF-16LE share path at an offset given in the request body.
        3 if rest.len() > 8 => {
            let off = u16::from_le_bytes([rest[4], rest[5]]) as usize;
            let len = u16::from_le_bytes([rest[6], rest[7]]) as usize;
            // The offset is measured from the start of the SMB2 header.
            if off >= 64 && off - 64 + len <= rest.len() {
                ctx.pkt.smb_tree = utf16le(&rest[off - 64..off - 64 + len]).map(|s| cap(s, 512));
            }
        }
        // CREATE: the filename lives at a header-relative offset near the end of the body.
        5 if rest.len() > 48 => {
            let off = u16::from_le_bytes([rest[44], rest[45]]) as usize;
            let len = u16::from_le_bytes([rest[46], rest[47]]) as usize;
            if off >= 64 && off - 64 + len <= rest.len() {
                ctx.pkt.smb_filename =
                    utf16le(&rest[off - 64..off - 64 + len]).map(|s| cap(s, 512));
            }
        }
        _ => {}
    }

    if let Some(pos) = find(rest, NTLMSSP) {
        ntlm(&rest[pos..], ctx);
    }
    Ok(())
}

fn smb1(body: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("smb");
    ctx.pkt.smb_version = Some("SMB1".to_string());
    let mut c = Cur::new(body);
    c.skip(4)?;
    let command = c.u8()?;
    ctx.pkt.smb_command = Some(command as u16);
    ctx.pkt.smb_command_name = Some(
        match command {
            0x72 => "NEGOTIATE",
            0x73 => "SESSION_SETUP_ANDX",
            0x75 => "TREE_CONNECT_ANDX",
            0x2d => "OPEN_ANDX",
            0x2e => "READ_ANDX",
            0x2f => "WRITE_ANDX",
            0xa2 => "NT_CREATE_ANDX",
            _ => "OTHER",
        }
        .to_string(),
    );
    ctx.pkt.smb_status = Some(c.le32()?);

    let rest = c.take_rest();
    if let Some(pos) = find(rest, NTLMSSP) {
        ntlm(&rest[pos..], ctx);
    }
    Ok(())
}

/// NTLMSSP messages carry the account, domain and workstation in plain sight — the fields
/// that turn an SMB capture into an identity record.
fn ntlm(data: &[u8], ctx: &mut Ctx) {
    let mut c = Cur::new(data);
    if c.skip(8).is_err() {
        return;
    }
    let msg_type = match c.le32() {
        Ok(t) => t,
        Err(_) => return,
    };
    ctx.pkt.ntlm_message_type = Some(msg_type);

    // Only the Authenticate message (type 3) carries the identity fields.
    if msg_type != 3 {
        return;
    }
    // Each field is a (length, max length, offset) triplet relative to the message start.
    let read_field = |c: &mut Cur| -> Option<(usize, usize)> {
        let len = c.le16().ok()? as usize;
        let _max = c.le16().ok()?;
        let off = c.le32().ok()? as usize;
        Some((off, len))
    };
    let _lm = read_field(&mut c);
    let _nt = read_field(&mut c);
    let domain = read_field(&mut c);
    let user = read_field(&mut c);
    let host = read_field(&mut c);

    let get = |f: Option<(usize, usize)>| -> Option<String> {
        let (off, len) = f?;
        if len == 0 || off + len > data.len() {
            return None;
        }
        utf16le(&data[off..off + len]).map(|s| cap(s, 256))
    };
    ctx.pkt.ntlm_domain = get(domain);
    ctx.pkt.ntlm_user = get(user);
    ctx.pkt.ntlm_host = get(host);
}

/// Decode UTF-16LE, falling back to ASCII when the length is odd (some fields are ASCII when
/// the Unicode negotiation flag is off).
fn utf16le(b: &[u8]) -> Option<String> {
    if b.is_empty() {
        return None;
    }
    if b.len() % 2 != 0 {
        return crate::bytes::ascii_string(b);
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
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

    fn smb2_header(command: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(SMB2_MAGIC);
        v.extend_from_slice(&64u16.to_le_bytes()); // structure size
        v.extend_from_slice(&0u16.to_le_bytes()); // credit charge
        v.extend_from_slice(&0u32.to_le_bytes()); // status
        v.extend_from_slice(&command.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // credits
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // next command
        v.extend_from_slice(&7u64.to_le_bytes()); // message id
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&0x1234u32.to_le_bytes()); // tree id
        v.extend_from_slice(&0xabcdu64.to_le_bytes()); // session id
        v.extend_from_slice(&[0u8; 16]); // signature
        v
    }

    #[test]
    fn smb2_header_fields() {
        let (p, r) = run(&smb2_header(8));
        r.unwrap();
        assert_eq!(p.smb_version.as_deref(), Some("SMB2"));
        assert_eq!(p.smb_command_name.as_deref(), Some("READ"));
        assert_eq!(p.smb_tree_id, Some(0x1234));
        assert_eq!(p.smb_session_id, Some(0xabcd));
    }

    #[test]
    fn netbios_framing_is_stripped() {
        let mut v = vec![0x00, 0x00, 0x00, 0x40];
        v.extend_from_slice(&smb2_header(0));
        let (p, r) = run(&v);
        r.unwrap();
        assert_eq!(p.smb_command_name.as_deref(), Some("NEGOTIATE"));
    }

    #[test]
    fn ntlm_authenticate_yields_the_account() {
        let mut msg = Vec::new();
        msg.extend_from_slice(NTLMSSP);
        msg.extend_from_slice(&3u32.to_le_bytes());

        let domain = "CORP"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();
        let user = "alice"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();
        let host = "WS01"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();

        // Field descriptors start at offset 12; five triplets of 8 bytes each.
        let data_start = 12 + 8 * 5;
        let d_off = data_start;
        let u_off = d_off + domain.len();
        let h_off = u_off + user.len();

        let field = |len: usize, off: usize| {
            let mut f = Vec::new();
            f.extend_from_slice(&(len as u16).to_le_bytes());
            f.extend_from_slice(&(len as u16).to_le_bytes());
            f.extend_from_slice(&(off as u32).to_le_bytes());
            f
        };
        msg.extend_from_slice(&field(0, 0)); // LM
        msg.extend_from_slice(&field(0, 0)); // NT
        msg.extend_from_slice(&field(domain.len(), d_off));
        msg.extend_from_slice(&field(user.len(), u_off));
        msg.extend_from_slice(&field(host.len(), h_off));
        msg.extend_from_slice(&domain);
        msg.extend_from_slice(&user);
        msg.extend_from_slice(&host);

        let mut v = smb2_header(1);
        v.extend_from_slice(&msg);

        let (p, r) = run(&v);
        r.unwrap();
        assert_eq!(p.ntlm_message_type, Some(3));
        assert_eq!(p.ntlm_user.as_deref(), Some("alice"));
        assert_eq!(p.ntlm_domain.as_deref(), Some("CORP"));
        assert_eq!(p.ntlm_host.as_deref(), Some("WS01"));
    }

    #[test]
    fn non_smb_payload_is_rejected() {
        let (_, r) = run(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(r, Err(DissectError::Malformed));
    }

    #[test]
    fn truncated_headers_do_not_panic() {
        let full = smb2_header(5);
        for n in 0..full.len() {
            let _ = run(&full[..n]);
        }
    }
}
