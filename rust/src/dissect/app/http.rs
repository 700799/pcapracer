//! HTTP/1.x, plus frame-level HTTP/2.

use crate::bytes::{cap, preview, Cur};
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

const KNOWN_METHODS: &[&str] = &[
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "OPTIONS",
    "TRACE",
    "CONNECT",
    "PATCH",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "SEARCH",
    "REPORT",
];

/// True if the payload plausibly starts an HTTP/1.x message, used by the sniffing fallback
/// so HTTP on a non-standard port is still recognised.
pub fn looks_like_http(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP/1.") {
        return true;
    }
    let head = &data[..data.len().min(10)];
    let s = String::from_utf8_lossy(head);
    KNOWN_METHODS
        .iter()
        .any(|m| s.starts_with(m) && s.as_bytes().get(m.len()) == Some(&b' '))
}

pub fn parse(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("http");

    // Split head from body at the first blank line. A message whose headers were cut off by
    // the snaplen still yields whatever header lines did arrive.
    let (head, body) = match find_header_end(payload) {
        Some(i) => (&payload[..i], &payload[i + 4..]),
        None => (payload, &payload[payload.len()..]),
    };
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n").filter(|l| !l.is_empty());

    let first = lines.next().ok_or(DissectError::Malformed)?;

    if first.starts_with("HTTP/") {
        ctx.pkt.http_is_request = Some(false);
        let mut it = first.splitn(3, ' ');
        ctx.pkt.http_version = it.next().map(|s| s.to_string());
        if let Some(code) = it.next() {
            ctx.pkt.http_status_code = code.parse().ok();
        }
        ctx.pkt.http_status_msg = it.next().map(|s| s.to_string());
    } else {
        let mut it = first.splitn(3, ' ');
        let method = it.next().unwrap_or_default();
        if !KNOWN_METHODS.contains(&method) {
            return Err(DissectError::Malformed);
        }
        ctx.pkt.http_is_request = Some(true);
        ctx.pkt.http_method = Some(method.to_string());
        if let Some(uri) = it.next() {
            ctx.pkt.http_uri = Some(cap(uri.to_string(), 2048));
            // Splitting path from query up front saves a string operation in every
            // downstream query looking for parameter-based exfiltration.
            match uri.split_once('?') {
                Some((p, q)) => {
                    ctx.pkt.http_uri_path = Some(cap(p.to_string(), 1024));
                    ctx.pkt.http_uri_query = Some(cap(q.to_string(), 1024));
                }
                None => ctx.pkt.http_uri_path = Some(cap(uri.to_string(), 1024)),
            }
        }
        ctx.pkt.http_version = it.next().map(|s| s.to_string());
    }

    let mut names: Vec<String> = Vec::new();
    let mut count = 0u16;
    for line in lines {
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n.trim(), v.trim()),
            None => continue,
        };
        count += 1;
        let lower = name.to_ascii_lowercase();
        names.push(lower.clone());
        let v = || cap(value.to_string(), 1024);
        match lower.as_str() {
            "host" => ctx.pkt.http_host = Some(v()),
            "user-agent" => ctx.pkt.http_user_agent = Some(v()),
            "referer" => ctx.pkt.http_referer = Some(v()),
            "cookie" => ctx.pkt.http_cookie = Some(v()),
            "set-cookie" => ctx.pkt.http_set_cookie = Some(v()),
            "content-type" => ctx.pkt.http_content_type = Some(v()),
            "content-length" => ctx.pkt.http_content_length = value.parse().ok(),
            "content-encoding" => ctx.pkt.http_content_encoding = Some(v()),
            "transfer-encoding" => ctx.pkt.http_transfer_encoding = Some(v()),
            "accept" => ctx.pkt.http_accept = Some(v()),
            "accept-language" => ctx.pkt.http_accept_language = Some(v()),
            "authorization" => ctx.pkt.http_authorization = Some(v()),
            "x-forwarded-for" => ctx.pkt.http_x_forwarded_for = Some(v()),
            "server" => ctx.pkt.http_server = Some(v()),
            "location" => ctx.pkt.http_location = Some(v()),
            _ => {}
        }
    }
    ctx.pkt.http_header_count = Some(count);
    if !names.is_empty() {
        // Header ordering is a client fingerprint in its own right, so preserve the sequence.
        ctx.pkt.http_header_names = Some(cap(names.join(","), 1024));
    }
    if !body.is_empty() {
        ctx.pkt.http_body_preview = Some(preview(body, 256));
    }
    Ok(())
}

fn find_header_end(d: &[u8]) -> Option<usize> {
    d.windows(4).position(|w| w == b"\r\n\r\n")
}

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub fn looks_like_http2(data: &[u8]) -> bool {
    data.starts_with(H2_PREFACE)
}

/// HPACK static table entries that carry a value, indexed as in RFC 7541 Appendix A.
fn static_entry(idx: u8) -> Option<(&'static str, &'static str)> {
    Some(match idx {
        2 => (":method", "GET"),
        3 => (":method", "POST"),
        4 => (":path", "/"),
        5 => (":path", "/index.html"),
        6 => (":scheme", "http"),
        7 => (":scheme", "https"),
        8 => (":status", "200"),
        9 => (":status", "204"),
        10 => (":status", "206"),
        11 => (":status", "304"),
        12 => (":status", "400"),
        13 => (":status", "404"),
        14 => (":status", "500"),
        _ => return None,
    })
}

fn static_name(idx: u8) -> Option<&'static str> {
    Some(match idx {
        1 => ":authority",
        2 | 3 => ":method",
        4 | 5 => ":path",
        6 | 7 => ":scheme",
        8..=14 => ":status",
        15 => "accept-charset",
        16 => "accept-encoding",
        17 => "accept-language",
        31 => "content-type",
        58 => "user-agent",
        _ => return None,
    })
}

/// Dissect HTTP/2 at the frame level, with best-effort HPACK for the pseudo-headers.
///
/// Full HPACK needs the connection's dynamic table and the Huffman alphabet, neither of
/// which is available when decoding a frame in isolation. What is reliably recoverable —
/// frame framing, stream IDs, and headers encoded against the static table without Huffman —
/// is extracted; anything else leaves the `http2_*` value columns null rather than guessing.
pub fn parse_h2(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("http2");
    let mut c = Cur::new(payload);
    if c.peek(H2_PREFACE.len()) == Some(H2_PREFACE) {
        c.skip(H2_PREFACE.len())?;
    }

    let mut frames = 0;
    while c.remaining() >= 9 && frames < 16 {
        frames += 1;
        let len = c.be24()? as usize;
        let ftype = c.u8()?;
        let _flags = c.u8()?;
        let stream_id = c.be32()? & 0x7fff_ffff;

        if ctx.pkt.http2_frame_type.is_none() {
            ctx.pkt.http2_frame_type = Some(ftype);
            ctx.pkt.http2_stream_id = Some(stream_id);
        }
        let body = match c.take(len.min(c.remaining())) {
            Ok(b) => b,
            Err(_) => break,
        };
        if ftype == 0x1 {
            decode_headers(body, ctx);
        }
    }
    Ok(())
}

fn decode_headers(body: &[u8], ctx: &mut Ctx) {
    let mut c = Cur::new(body);
    let mut guard = 0;
    while let Ok(b) = c.u8() {
        guard += 1;
        if guard > 64 {
            return;
        }
        if b & 0x80 != 0 {
            // Indexed header field: fully resolved only for static-table entries.
            if let Some((n, v)) = static_entry(b & 0x7f) {
                set_pseudo(n, v.to_string(), ctx);
            }
            continue;
        }

        // Literal header field. The name is either a static index or a literal string.
        let (name_idx, prefix_bits) = if b & 0x40 != 0 {
            (b & 0x3f, 6)
        } else {
            (b & 0x0f, 4)
        };
        let _ = prefix_bits;

        let name = if name_idx != 0 {
            static_name(name_idx).map(|s| s.to_string())
        } else {
            match read_string(&mut c) {
                Some(s) => Some(s),
                None => return,
            }
        };
        let value = match read_string(&mut c) {
            Some(v) => v,
            None => return,
        };
        if let Some(n) = name {
            set_pseudo(&n, value, ctx);
        }
    }
}

/// Read an HPACK string literal. Huffman-coded strings are skipped rather than decoded.
fn read_string(c: &mut Cur) -> Option<String> {
    let b = c.u8().ok()?;
    let huffman = b & 0x80 != 0;
    let len = (b & 0x7f) as usize;
    // A 7-bit prefix of 127 means a multi-byte varint follows; those strings are longer than
    // anything we want to store, so stop rather than mis-parse the rest of the block.
    if len == 127 {
        return None;
    }
    let raw = c.take(len).ok()?;
    if huffman {
        return Some(String::new());
    }
    Some(String::from_utf8_lossy(raw).to_string())
}

fn set_pseudo(name: &str, value: String, ctx: &mut Ctx) {
    if value.is_empty() {
        return;
    }
    let v = cap(value, 1024);
    match name {
        ":method" => ctx.pkt.http2_method = Some(v),
        ":path" => ctx.pkt.http2_path = Some(v),
        ":authority" => ctx.pkt.http2_authority = Some(v),
        ":scheme" => ctx.pkt.http2_scheme = Some(v),
        ":status" => ctx.pkt.http2_status = Some(v),
        "user-agent" => ctx.pkt.http_user_agent = Some(v),
        "content-type" => ctx.pkt.http_content_type = Some(v),
        _ => {}
    }
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
    fn parses_a_request() {
        let req = b"GET /admin/login?next=%2Fhome HTTP/1.1\r\n\
                    Host: intranet.example.com\r\n\
                    User-Agent: curl/8.4.0\r\n\
                    Cookie: session=abc123\r\n\
                    \r\n";
        let (p, r) = run(req);
        r.unwrap();
        assert_eq!(p.http_method.as_deref(), Some("GET"));
        assert_eq!(p.http_uri_path.as_deref(), Some("/admin/login"));
        assert_eq!(p.http_uri_query.as_deref(), Some("next=%2Fhome"));
        assert_eq!(p.http_host.as_deref(), Some("intranet.example.com"));
        assert_eq!(p.http_user_agent.as_deref(), Some("curl/8.4.0"));
        assert_eq!(p.http_header_count, Some(3));
        assert_eq!(
            p.http_header_names.as_deref(),
            Some("host,user-agent,cookie")
        );
    }

    #[test]
    fn parses_a_response_with_a_body() {
        let resp = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 5\r\n\r\nhello";
        let (p, r) = run(resp);
        r.unwrap();
        assert_eq!(p.http_is_request, Some(false));
        assert_eq!(p.http_status_code, Some(404));
        assert_eq!(p.http_status_msg.as_deref(), Some("Not Found"));
        assert_eq!(p.http_server.as_deref(), Some("nginx"));
        assert_eq!(p.http_content_length, Some(5));
        assert_eq!(p.http_body_preview.as_deref(), Some("hello"));
    }

    #[test]
    fn non_http_payload_is_rejected() {
        let (_, r) = run(b"\x16\x03\x01\x00\x50 not http at all");
        assert!(r.is_err());
    }

    #[test]
    fn sniffing_accepts_methods_and_rejects_lookalikes() {
        assert!(looks_like_http(b"POST /x HTTP/1.1\r\n"));
        assert!(looks_like_http(b"HTTP/1.0 200 OK\r\n"));
        assert!(!looks_like_http(b"GETTING started"));
        assert!(!looks_like_http(b"\x00\x01\x02"));
    }

    #[test]
    fn headers_without_a_terminator_still_parse() {
        let (p, r) = run(b"GET / HTTP/1.1\r\nHost: a.example\r\n");
        r.unwrap();
        assert_eq!(p.http_host.as_deref(), Some("a.example"));
    }
}
