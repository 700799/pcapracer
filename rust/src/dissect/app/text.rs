//! Line-oriented plaintext protocols: SMTP, FTP, IMAP, POP3, IRC, Telnet, Syslog, VNC.
//!
//! These all share a shape — a command word, an argument tail, and numeric responses — so
//! they share one module and a couple of helpers.

use crate::bytes::{cap, preview, Cur};
use crate::dissect::Ctx;
use crate::error::DResult;

/// First line of the payload, without its terminator, capped.
fn first_line(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len().min(1024));
    cap(String::from_utf8_lossy(&payload[..end]).to_string(), 1024)
}

fn lines(payload: &[u8], max: usize) -> Vec<String> {
    String::from_utf8_lossy(&payload[..payload.len().min(8192)])
        .split(['\r', '\n'])
        .filter(|l| !l.is_empty())
        .take(max)
        .map(|s| s.to_string())
        .collect()
}

fn split_command(line: &str) -> (String, Option<String>) {
    match line.split_once(' ') {
        Some((c, a)) => (c.to_ascii_uppercase(), Some(cap(a.trim().to_string(), 512))),
        None => (line.to_ascii_uppercase(), None),
    }
}

pub fn smtp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("smtp");
    for line in lines(payload, 32) {
        // A server response opens with a three-digit status code.
        if line.len() >= 3 && line.as_bytes()[..3].iter().all(|b| b.is_ascii_digit()) {
            if ctx.pkt.smtp_response_code.is_none() {
                ctx.pkt.smtp_response_code = line[..3].parse().ok();
                ctx.pkt.smtp_response = Some(cap(line.clone(), 512));
            }
            continue;
        }
        let (cmd, arg) = split_command(&line);
        match cmd.as_str() {
            "MAIL" => {
                ctx.pkt.smtp_mail_from = arg.clone().map(|a| strip_prefix_ci(&a, "FROM:"));
            }
            "RCPT" => {
                ctx.pkt.smtp_rcpt_to = arg.clone().map(|a| strip_prefix_ci(&a, "TO:"));
            }
            _ => {}
        }
        if cmd.starts_with("SUBJECT:") || line.to_ascii_uppercase().starts_with("SUBJECT:") {
            ctx.pkt.smtp_subject = Some(cap(line[8..].trim().to_string(), 512));
            continue;
        }
        if ctx.pkt.smtp_command.is_none() && cmd.chars().all(|c| c.is_ascii_alphabetic()) {
            ctx.pkt.smtp_command = Some(cmd);
            ctx.pkt.smtp_argument = arg;
        }
    }
    Ok(())
}

fn strip_prefix_ci(s: &str, prefix: &str) -> String {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        s[prefix.len()..]
            .trim()
            .trim_matches(['<', '>'])
            .to_string()
    } else {
        s.to_string()
    }
}

pub fn ftp(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("ftp");
    let line = first_line(payload);
    if line.len() >= 3 && line.as_bytes()[..3].iter().all(|b| b.is_ascii_digit()) {
        ctx.pkt.ftp_response_code = line[..3].parse().ok();
        ctx.pkt.ftp_response = Some(line);
        return Ok(());
    }
    let (cmd, arg) = split_command(&line);
    ctx.pkt.ftp_command = Some(cmd);
    ctx.pkt.ftp_argument = arg;
    Ok(())
}

pub fn imap(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("imap");
    let line = first_line(payload);
    // IMAP commands are prefixed with a client-chosen tag: `a001 LOGIN user pass`.
    let mut it = line.splitn(3, ' ');
    ctx.pkt.imap_tag = it.next().map(|s| s.to_string());
    ctx.pkt.imap_command = it.next().map(|s| s.to_ascii_uppercase());
    ctx.pkt.imap_argument = it.next().map(|s| cap(s.to_string(), 512));
    Ok(())
}

pub fn pop3(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("pop3");
    let line = first_line(payload);
    let (cmd, arg) = split_command(&line);
    ctx.pkt.pop3_command = Some(cmd);
    ctx.pkt.pop3_argument = arg;
    Ok(())
}

pub fn irc(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("irc");
    let mut line = first_line(payload);
    // A server message may be prefixed with `:nick!user@host`.
    if line.starts_with(':') {
        if let Some((prefix, rest)) = line[1..].split_once(' ') {
            ctx.pkt.irc_nick = Some(prefix.split('!').next().unwrap_or(prefix).to_string());
            line = rest.to_string();
        }
    }
    let (cmd, params) = split_command(&line);
    ctx.pkt.irc_command = Some(cmd);
    ctx.pkt.irc_params = params;
    Ok(())
}

pub fn telnet(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("telnet");
    // Strip IAC negotiation sequences so the column shows the session text, not the option
    // handshake; 0xff introduces a two- or three-byte command.
    let mut out = Vec::with_capacity(payload.len());
    let mut c = Cur::new(payload);
    while let Ok(b) = c.u8() {
        if b == 0xff {
            match c.u8() {
                Ok(0xfa) => {
                    // Subnegotiation runs until IAC SE.
                    while let Ok(x) = c.u8() {
                        if x == 0xff && c.u8() == Ok(0xf0) {
                            break;
                        }
                    }
                }
                Ok(cmd) if (0xfb..=0xfe).contains(&cmd) => {
                    let _ = c.u8();
                }
                _ => {}
            }
            continue;
        }
        out.push(b);
    }
    if !out.is_empty() {
        ctx.pkt.telnet_data = Some(preview(&out, 512));
    }
    Ok(())
}

pub fn syslog(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("syslog");
    let text = first_line(payload);
    let mut rest = text.as_str();

    // The priority is `<N>` where N = facility * 8 + severity.
    if let Some(stripped) = rest.strip_prefix('<') {
        if let Some((num, tail)) = stripped.split_once('>') {
            if let Ok(pri) = num.parse::<u8>() {
                ctx.pkt.syslog_priority = Some(pri);
                ctx.pkt.syslog_facility = Some(pri >> 3);
                ctx.pkt.syslog_severity = Some(pri & 0x7);
            }
            rest = tail;
        }
    }

    // RFC 5424: `1 TIMESTAMP HOST APP ...`. RFC 3164 has no version digit; in that case the
    // structured fields are not reliably positioned, so only the message is recorded.
    let parts: Vec<&str> = rest.splitn(5, ' ').collect();
    if parts.len() >= 4 && parts[0] == "1" {
        ctx.pkt.syslog_hostname = Some(parts[2].to_string());
        ctx.pkt.syslog_appname = Some(parts[3].to_string());
    }
    ctx.pkt.syslog_message = Some(cap(rest.trim().to_string(), 1024));
    Ok(())
}

pub fn vnc(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("vnc");
    if payload.starts_with(b"RFB ") {
        ctx.pkt.vnc_version = Some(first_line(payload));
    }
    Ok(())
}

pub fn looks_like_vnc(d: &[u8]) -> bool {
    d.starts_with(b"RFB ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn run<F: FnOnce(&mut Ctx) -> DResult<()>>(f: F) -> Packet {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            f(&mut ctx).unwrap();
        }
        p
    }

    #[test]
    fn smtp_envelope_addresses() {
        let p = run(|ctx| {
            smtp(
                b"MAIL FROM:<alice@example.com>\r\nRCPT TO:<bob@example.net>\r\n",
                ctx,
            )
        });
        assert_eq!(p.smtp_mail_from.as_deref(), Some("alice@example.com"));
        assert_eq!(p.smtp_rcpt_to.as_deref(), Some("bob@example.net"));
    }

    #[test]
    fn smtp_response_code() {
        let p = run(|ctx| smtp(b"250 OK\r\n", ctx));
        assert_eq!(p.smtp_response_code, Some(250));
        assert!(p.smtp_command.is_none());
    }

    #[test]
    fn ftp_command_and_response() {
        let p = run(|ctx| ftp(b"USER anonymous\r\n", ctx));
        assert_eq!(p.ftp_command.as_deref(), Some("USER"));
        assert_eq!(p.ftp_argument.as_deref(), Some("anonymous"));

        let p = run(|ctx| ftp(b"530 Login incorrect.\r\n", ctx));
        assert_eq!(p.ftp_response_code, Some(530));
    }

    #[test]
    fn imap_tag_is_separated_from_the_command() {
        let p = run(|ctx| imap(b"a001 LOGIN alice secret\r\n", ctx));
        assert_eq!(p.imap_tag.as_deref(), Some("a001"));
        assert_eq!(p.imap_command.as_deref(), Some("LOGIN"));
        assert_eq!(p.imap_argument.as_deref(), Some("alice secret"));
    }

    #[test]
    fn irc_prefix_is_stripped() {
        let p = run(|ctx| irc(b":nick!user@host PRIVMSG #chan :hello\r\n", ctx));
        assert_eq!(p.irc_nick.as_deref(), Some("nick"));
        assert_eq!(p.irc_command.as_deref(), Some("PRIVMSG"));
    }

    #[test]
    fn telnet_negotiation_is_removed() {
        let p = run(|ctx| telnet(b"\xff\xfb\x01\xff\xfd\x03login:", ctx));
        assert_eq!(p.telnet_data.as_deref(), Some("login:"));
    }

    #[test]
    fn syslog_priority_decodes_to_facility_and_severity() {
        let p = run(|ctx| syslog(b"<34>1 2024-01-01T00:00:00Z host su - - - failed", ctx));
        assert_eq!(p.syslog_priority, Some(34));
        assert_eq!(p.syslog_facility, Some(4)); // auth
        assert_eq!(p.syslog_severity, Some(2)); // critical
        assert_eq!(p.syslog_hostname.as_deref(), Some("host"));
        assert_eq!(p.syslog_appname.as_deref(), Some("su"));
    }

    #[test]
    fn syslog_without_version_digit_keeps_only_the_message() {
        let p = run(|ctx| syslog(b"<13>Jan  1 00:00:00 host sshd: hello", ctx));
        assert_eq!(p.syslog_facility, Some(1));
        assert!(p.syslog_appname.is_none());
        assert!(p.syslog_message.unwrap().contains("sshd"));
    }
}
