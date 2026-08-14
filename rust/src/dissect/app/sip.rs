//! SIP — request/response line plus the headers that identify the call and its endpoints.

use crate::bytes::cap;
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

const METHODS: &[&str] = &[
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "OPTIONS",
    "REGISTER",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE",
];

pub fn looks_like_sip(d: &[u8]) -> bool {
    if d.starts_with(b"SIP/2.0") {
        return true;
    }
    let head = String::from_utf8_lossy(&d[..d.len().min(12)]);
    METHODS
        .iter()
        .any(|m| head.starts_with(m) && head.as_bytes().get(m.len()) == Some(&b' '))
}

pub fn parse(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("sip");
    let text = String::from_utf8_lossy(&payload[..payload.len().min(8192)]);
    let mut lines = text.split("\r\n");

    let first = lines.next().ok_or(DissectError::Malformed)?;
    if first.starts_with("SIP/2.0") {
        let mut it = first.splitn(3, ' ');
        it.next();
        ctx.pkt.sip_status_code = it.next().and_then(|c| c.parse().ok());
    } else {
        let mut it = first.splitn(3, ' ');
        let method = it.next().unwrap_or_default();
        if !METHODS.contains(&method) {
            return Err(DissectError::Malformed);
        }
        ctx.pkt.sip_method = Some(method.to_string());
        ctx.pkt.sip_uri = it.next().map(|s| cap(s.to_string(), 512));
    }

    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n.trim().to_ascii_lowercase(), v.trim()),
            None => continue,
        };
        let v = cap(value.to_string(), 512);
        // SIP allows single-letter compact header forms, which are common in the wild.
        match name.as_str() {
            "from" | "f" => ctx.pkt.sip_from = Some(v),
            "to" | "t" => ctx.pkt.sip_to = Some(v),
            "call-id" | "i" => ctx.pkt.sip_call_id = Some(v),
            "user-agent" => ctx.pkt.sip_user_agent = Some(v),
            _ => {}
        }
    }
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
    fn parses_an_invite() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                    From: <sip:alice@example.com>;tag=1928\r\n\
                    To: <sip:bob@example.com>\r\n\
                    Call-ID: a84b4c76e66710\r\n\
                    User-Agent: LinphoneAndroid/5.0\r\n\r\n";
        let (p, r) = run(msg);
        r.unwrap();
        assert_eq!(p.sip_method.as_deref(), Some("INVITE"));
        assert_eq!(p.sip_uri.as_deref(), Some("sip:bob@example.com"));
        assert_eq!(p.sip_call_id.as_deref(), Some("a84b4c76e66710"));
        assert_eq!(p.sip_user_agent.as_deref(), Some("LinphoneAndroid/5.0"));
    }

    #[test]
    fn parses_a_response_and_compact_headers() {
        let msg = b"SIP/2.0 200 OK\r\nf: <sip:alice@example.com>\r\ni: xyz123\r\n\r\n";
        let (p, r) = run(msg);
        r.unwrap();
        assert_eq!(p.sip_status_code, Some(200));
        assert_eq!(p.sip_call_id.as_deref(), Some("xyz123"));
    }

    #[test]
    fn rejects_non_sip() {
        assert!(!looks_like_sip(b"INVITEX sip:x"));
        let (_, r) = run(b"GET / HTTP/1.1\r\n\r\n");
        assert!(r.is_err());
    }
}
