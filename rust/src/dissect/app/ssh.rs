//! SSH: the version banner and the KEXINIT algorithm negotiation, plus HASSH.

use crate::bytes::{cap, Cur};
use crate::dissect::Ctx;
use crate::error::DResult;
use crate::fingerprint::hassh;

pub fn looks_like_ssh(d: &[u8]) -> bool {
    d.starts_with(b"SSH-")
}

const MSG_KEXINIT: u8 = 20;

pub fn parse(payload: &[u8], ctx: &mut Ctx, is_server: bool) -> DResult<()> {
    ctx.layer("ssh");

    // The banner is a bare CR/LF-terminated line, sent before binary packets begin.
    if payload.starts_with(b"SSH-") {
        let line_end = payload
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(payload.len().min(255));
        let banner = String::from_utf8_lossy(&payload[..line_end]).to_string();
        let mut parts = banner.splitn(3, '-');
        parts.next();
        ctx.pkt.ssh_protocol_version = parts.next().map(|s| s.to_string());
        ctx.pkt.ssh_software = parts.next().map(|s| cap(s.to_string(), 256));
        // A banner may be followed by the first binary packet in the same segment.
        if line_end + 1 >= payload.len() {
            return Ok(());
        }
        let rest = &payload[line_end..];
        let start = rest
            .iter()
            .position(|&b| b != b'\r' && b != b'\n')
            .unwrap_or(rest.len());
        return binary(&rest[start..], ctx, is_server);
    }
    binary(payload, ctx, is_server)
}

fn binary(payload: &[u8], ctx: &mut Ctx, is_server: bool) -> DResult<()> {
    if payload.len() < 6 {
        return Ok(());
    }
    let mut c = Cur::new(payload);
    let packet_len = c.be32()? as usize;
    let padding_len = c.u8()? as usize;
    if packet_len < padding_len + 2 {
        return Ok(());
    }
    let msg_type = c.u8()?;
    ctx.pkt.ssh_msg_type = Some(msg_type);
    if msg_type != MSG_KEXINIT {
        return Ok(());
    }

    c.skip(16)?; // cookie

    // Ten name-lists follow, in a fixed order.
    let mut lists: Vec<String> = Vec::with_capacity(10);
    for _ in 0..10 {
        let len = match c.be32() {
            Ok(l) => l as usize,
            Err(_) => break,
        };
        match c.take(len) {
            Ok(v) => lists.push(String::from_utf8_lossy(v).to_string()),
            Err(_) => break,
        }
    }
    if lists.len() < 6 {
        return Ok(());
    }

    let kex = lists[0].clone();
    let host_key = lists[1].clone();
    let enc_c2s = lists[2].clone();
    let enc_s2c = lists[3].clone();
    let mac_c2s = lists[4].clone();
    let comp_c2s = lists[6.min(lists.len() - 1)].clone();

    ctx.pkt.ssh_kex_algs = Some(cap(kex.clone(), 1024));
    ctx.pkt.ssh_host_key_algs = Some(cap(host_key, 512));
    ctx.pkt.ssh_enc_algs_c2s = Some(cap(enc_c2s.clone(), 512));
    ctx.pkt.ssh_enc_algs_s2c = Some(cap(enc_s2c.clone(), 512));
    ctx.pkt.ssh_mac_algs_c2s = Some(cap(mac_c2s.clone(), 512));
    ctx.pkt.ssh_comp_algs_c2s = Some(cap(comp_c2s.clone(), 256));

    // HASSH uses the client's c2s lists; HASSHServer uses the server's s2c lists. Which one
    // applies depends on who sent this KEXINIT.
    if is_server {
        let mac_s2c = lists.get(5).cloned().unwrap_or_default();
        let comp_s2c = lists.get(7).cloned().unwrap_or_default();
        ctx.pkt.hassh_server = Some(hassh(&kex, &enc_s2c, &mac_s2c, &comp_s2c));
    } else {
        ctx.pkt.hassh = Some(hassh(&kex, &enc_c2s, &mac_c2s, &comp_c2s));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn run(payload: &[u8], is_server: bool) -> Packet {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            parse(payload, &mut ctx, is_server).unwrap();
        }
        p
    }

    #[test]
    fn banner_is_split_into_version_and_software() {
        let p = run(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n", false);
        assert_eq!(p.ssh_protocol_version.as_deref(), Some("2.0"));
        assert_eq!(p.ssh_software.as_deref(), Some("OpenSSH_9.6p1 Ubuntu-3"));
    }

    fn kexinit(lists: &[&str]) -> Vec<u8> {
        let mut body = vec![MSG_KEXINIT];
        body.extend_from_slice(&[0xaa; 16]);
        for l in lists {
            body.extend_from_slice(&(l.len() as u32).to_be_bytes());
            body.extend_from_slice(l.as_bytes());
        }
        body.extend_from_slice(&[0, 0, 0, 0, 0]); // first_kex_follows + reserved

        let mut v = Vec::new();
        v.extend_from_slice(&((body.len() + 1) as u32).to_be_bytes());
        v.push(0); // padding length
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn kexinit_yields_hassh() {
        let lists = [
            "curve25519-sha256",
            "ssh-ed25519",
            "aes128-ctr",
            "aes256-ctr",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "none",
            "none",
            "",
            "",
        ];
        let p = run(&kexinit(&lists), false);
        assert_eq!(p.ssh_kex_algs.as_deref(), Some("curve25519-sha256"));
        assert_eq!(p.ssh_enc_algs_c2s.as_deref(), Some("aes128-ctr"));
        let h = p.hassh.unwrap();
        assert_eq!(
            h,
            crate::fingerprint::hassh("curve25519-sha256", "aes128-ctr", "hmac-sha2-256", "none")
        );
        assert!(p.hassh_server.is_none());
    }

    #[test]
    fn server_kexinit_yields_hassh_server_only() {
        let lists = [
            "curve25519-sha256",
            "ssh-ed25519",
            "aes128-ctr",
            "aes256-ctr",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "none",
            "none",
            "",
            "",
        ];
        let p = run(&kexinit(&lists), true);
        assert!(p.hassh.is_none());
        assert_eq!(
            p.hassh_server.unwrap(),
            crate::fingerprint::hassh("curve25519-sha256", "aes256-ctr", "hmac-sha2-512", "none")
        );
    }

    #[test]
    fn truncated_kexinit_does_not_panic() {
        // A short read must surface as an error, never a panic — so this deliberately does
        // not go through `run`, which unwraps.
        let full = kexinit(&["a", "b", "c", "d", "e", "f", "g", "h", "", ""]);
        for n in 0..full.len() {
            let mut p = Packet::default();
            let mut ctx = Ctx::new(&mut p);
            let _ = parse(&full[..n], &mut ctx, false);
        }
    }
}
