//! HTTP/1.x request and response parsing via `httparse`.

use super::AppCtx;
use crate::schema::http::HttpRow;

pub enum HttpOutcome {
    Row(HttpRow),
    NeedMore,
    No,
}

const MAX_HEADERS: usize = 64;

/// True if the buffer plausibly begins an HTTP/1.x request line.
pub fn looks_like_request(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m))
}

/// True if the buffer plausibly begins an HTTP/1.x response.
pub fn looks_like_response(buf: &[u8]) -> bool {
    buf.starts_with(b"HTTP/")
}

fn version_str(v: Option<u8>) -> Option<String> {
    v.map(|n| format!("HTTP/1.{n}"))
}

fn header_value<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|s| s.to_string())
}

fn has_header(headers: &[httparse::Header], name: &str) -> bool {
    headers.iter().any(|h| h.name.eq_ignore_ascii_case(name))
}

pub fn parse_request(buf: &[u8], ctx: &AppCtx) -> HttpOutcome {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            let hdrs = &req.headers[..];
            let content_length = header_value(hdrs, "content-length")
                .and_then(|s| s.trim().parse::<i64>().ok());
            let row = HttpRow {
                ts_ns: ctx.ts_ns,
                src_ip: Some(ctx.src_ip),
                dst_ip: Some(ctx.dst_ip),
                src_port: ctx.src_port,
                dst_port: ctx.dst_port,
                is_request: true,
                method: req.method.map(|s| s.to_string()),
                uri: req.path.map(|s| s.to_string()),
                version: version_str(req.version),
                host: header_value(hdrs, "host"),
                user_agent: header_value(hdrs, "user-agent"),
                referer: header_value(hdrs, "referer"),
                content_type: header_value(hdrs, "content-type"),
                content_length,
                transfer_encoding: header_value(hdrs, "transfer-encoding"),
                cookie_present: has_header(hdrs, "cookie"),
                auth_present: has_header(hdrs, "authorization"),
                x_forwarded_for: header_value(hdrs, "x-forwarded-for"),
                header_count: count_headers(hdrs) as u16,
                header_len: n as u32,
                ..Default::default()
            };
            HttpOutcome::Row(row)
        }
        Ok(httparse::Status::Partial) => HttpOutcome::NeedMore,
        Err(_) => HttpOutcome::No,
    }
}

pub fn parse_response(buf: &[u8], ctx: &AppCtx) -> HttpOutcome {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut headers);
    match res.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            let hdrs = &res.headers[..];
            let content_length = header_value(hdrs, "content-length")
                .and_then(|s| s.trim().parse::<i64>().ok());
            let row = HttpRow {
                ts_ns: ctx.ts_ns,
                src_ip: Some(ctx.src_ip),
                dst_ip: Some(ctx.dst_ip),
                src_port: ctx.src_port,
                dst_port: ctx.dst_port,
                is_request: false,
                version: version_str(res.version),
                content_type: header_value(hdrs, "content-type"),
                content_length,
                transfer_encoding: header_value(hdrs, "transfer-encoding"),
                cookie_present: has_header(hdrs, "set-cookie"),
                status: res.code,
                reason: res.reason.map(|s| s.to_string()),
                server: header_value(hdrs, "server"),
                location: header_value(hdrs, "location"),
                connection: header_value(hdrs, "connection"),
                header_count: count_headers(hdrs) as u16,
                header_len: n as u32,
                ..Default::default()
            };
            HttpOutcome::Row(row)
        }
        Ok(httparse::Status::Partial) => HttpOutcome::NeedMore,
        Err(_) => HttpOutcome::No,
    }
}

fn count_headers(headers: &[httparse::Header]) -> usize {
    headers.iter().filter(|h| !h.name.is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::IpRepr;

    fn ctx() -> AppCtx {
        AppCtx {
            ts_ns: 0,
            src_ip: IpRepr::V4([1, 2, 3, 4]),
            dst_ip: IpRepr::V4([5, 6, 7, 8]),
            src_port: 40000,
            dst_port: 80,
            proto: 6,
        }
    }

    #[test]
    fn request_parsed() {
        let buf = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n";
        match parse_request(buf, &ctx()) {
            HttpOutcome::Row(r) => {
                assert_eq!(r.method.as_deref(), Some("GET"));
                assert_eq!(r.uri.as_deref(), Some("/index.html"));
                assert_eq!(r.host.as_deref(), Some("example.com"));
                assert_eq!(r.user_agent.as_deref(), Some("curl/8.0"));
            }
            _ => panic!("expected row"),
        }
    }

    #[test]
    fn partial_needs_more() {
        let buf = b"GET / HTTP/1.1\r\nHost: exa";
        assert!(matches!(parse_request(buf, &ctx()), HttpOutcome::NeedMore));
    }

    #[test]
    fn response_parsed() {
        let buf = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n";
        match parse_response(buf, &ctx()) {
            HttpOutcome::Row(r) => {
                assert_eq!(r.status, Some(404));
                assert_eq!(r.reason.as_deref(), Some("Not Found"));
                assert_eq!(r.server.as_deref(), Some("nginx"));
                assert_eq!(r.content_length, Some(0));
            }
            _ => panic!("expected row"),
        }
    }
}
