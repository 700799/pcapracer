//! Application-layer dispatch.
//!
//! A payload is matched against the registered port first, then — if no port matched, or the
//! matched dissector rejected the bytes — against a set of content signatures. The fallback
//! is what catches protocols deliberately moved off their standard port, which is a common
//! enough evasion that port-only dispatch would leave real traffic unlabelled.

pub mod ber;
pub mod dhcp;
pub mod directory;
pub mod dns;
pub mod http;
pub mod ics;
pub mod misc;
pub mod quic;
pub mod sip;
pub mod smb;
pub mod ssh;
pub mod text;
pub mod tls;

use crate::dissect::Ctx;
use crate::error::DResult;

/// Try the registered protocol for `port`.
///
/// `port_is_source` tells a dissector which side of the conversation sent these bytes —
/// SSH's HASSH, for instance, is a different fingerprint depending on the direction.
fn by_port(
    payload: &[u8],
    port: u16,
    is_tcp: bool,
    port_is_source: bool,
    ctx: &mut Ctx,
) -> Option<DResult<()>> {
    let server = port_is_source;
    Some(match (port, is_tcp) {
        (21, true) | (20, true) => text::ftp(payload, ctx),
        (22, true) => ssh::parse(payload, ctx, server),
        (23, true) => text::telnet(payload, ctx),
        (25, true) | (587, true) | (465, true) => text::smtp(payload, ctx),
        (53, true) => dns::parse_tcp(payload, ctx),
        (53, false) => dns::parse(payload, ctx, false, false, false),
        (5353, false) => dns::parse(payload, ctx, true, false, false),
        (5355, _) => dns::parse(payload, ctx, false, true, false),
        (67, false) | (68, false) => dhcp::parse(payload, ctx),
        (546, false) | (547, false) => dhcp::parse_v6(payload, ctx),
        (69, false) => misc::tftp(payload, ctx),
        (80, true) | (8080, true) | (8000, true) | (8888, true) | (3128, true) => {
            if http::looks_like_http2(payload) {
                http::parse_h2(payload, ctx)
            } else {
                http::parse(payload, ctx)
            }
        }
        (88, true) => directory::kerberos(payload, ctx, true),
        (88, false) => directory::kerberos(payload, ctx, false),
        (102, true) => ics::s7comm(payload, ctx),
        (110, true) => text::pop3(payload, ctx),
        (123, false) => misc::ntp(payload, ctx),
        (137, false) => misc::nbns(payload, ctx),
        (139, true) => {
            // Port 139 is SMB over a NetBIOS session; record the session type, then let the
            // SMB dissector take the message if one is present.
            let _ = misc::nbss(payload, ctx);
            smb::parse(payload, ctx)
        }
        (143, true) | (993, true) => text::imap(payload, ctx),
        (161, false) | (162, false) => misc::snmp(payload, ctx),
        (389, true) | (3268, true) => directory::ldap(payload, ctx),
        (443, true) | (8443, true) | (993, false) => tls::parse(payload, ctx, false),
        (443, false) => quic::parse(payload, ctx),
        (445, true) => smb::parse(payload, ctx),
        (500, false) | (4500, false) => misc::ike(payload, ctx),
        (502, true) => ics::modbus(payload, ctx),
        (514, false) => text::syslog(payload, ctx),
        (1812, false) | (1813, false) | (1645, false) | (1646, false) => misc::radius(payload, ctx),
        (1883, true) | (8883, true) => misc::mqtt(payload, ctx),
        (2404, true) => ics::iec104(payload, ctx),
        (3389, true) => misc::rdp(payload, ctx),
        (5060, _) | (5061, _) => sip::parse(payload, ctx),
        (5900, true) | (5901, true) => text::vnc(payload, ctx),
        (6667, true) | (6697, true) | (6660..=6669, true) => text::irc(payload, ctx),
        (20000, true) => ics::dnp3(payload, ctx),
        (44818, true) => ics::enip(payload, ctx),
        (47808, false) => ics::bacnet(payload, ctx),
        (51820, false) => misc::wireguard(payload, ctx),
        _ => return None,
    })
}

/// Content-based identification, tried when the ports say nothing useful.
fn sniff(payload: &[u8], is_tcp: bool, ctx: &mut Ctx) -> Option<DResult<()>> {
    if payload.is_empty() {
        return None;
    }
    Some(if http::looks_like_http2(payload) {
        http::parse_h2(payload, ctx)
    } else if http::looks_like_http(payload) {
        http::parse(payload, ctx)
    } else if tls::looks_like_tls(payload) {
        tls::parse(payload, ctx, false)
    } else if tls::looks_like_dtls(payload) {
        tls::parse(payload, ctx, true)
    } else if ssh::looks_like_ssh(payload) {
        ssh::parse(payload, ctx, false)
    } else if sip::looks_like_sip(payload) {
        sip::parse(payload, ctx)
    } else if smb::looks_like_smb(payload) {
        smb::parse(payload, ctx)
    } else if text::looks_like_vnc(payload) {
        text::vnc(payload, ctx)
    } else if ics::looks_like_dnp3(payload) {
        ics::dnp3(payload, ctx)
    } else if !is_tcp && quic::looks_like_quic(payload) {
        quic::parse(payload, ctx)
    } else if !is_tcp && misc::looks_like_rtcp(payload) {
        misc::rtcp(payload, ctx)
    } else if !is_tcp && misc::looks_like_rtp(payload) {
        misc::rtp(payload, ctx)
    } else {
        return None;
    })
}

/// Identify and dissect the application payload.
///
/// Dissector failures are swallowed: a payload that looked like DNS because of its port but
/// turned out not to be is a labelling miss, not a reason to mark the packet malformed. The
/// layer name it pushed stays on the stack, which is how you find these cases afterwards.
pub fn dispatch(payload: &[u8], sport: u16, dport: u16, is_tcp: bool, ctx: &mut Ctx) {
    if ctx.app_done || payload.is_empty() {
        return;
    }
    ctx.app_done = true;

    // The destination port names the service for a request, the source port for a response.
    let depth_before = ctx.stack.len();
    if let Some(r) = by_port(payload, dport, is_tcp, false, ctx) {
        if r.is_ok() {
            return;
        }
        ctx.stack.truncate(depth_before);
    }
    if sport != dport {
        if let Some(r) = by_port(payload, sport, is_tcp, true, ctx) {
            if r.is_ok() {
                return;
            }
            ctx.stack.truncate(depth_before);
        }
    }
    if let Some(r) = sniff(payload, is_tcp, ctx) {
        if r.is_err() {
            ctx.stack.truncate(depth_before);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn run(payload: &[u8], sport: u16, dport: u16, is_tcp: bool) -> Packet {
        let mut p = Packet::default();
        {
            let mut ctx = Ctx::new(&mut p);
            dispatch(payload, sport, dport, is_tcp, &mut ctx);
            ctx.finish();
        }
        p
    }

    #[test]
    fn dispatches_by_destination_port() {
        let p = run(
            b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
            40000,
            80,
            true,
        );
        assert_eq!(p.http_host.as_deref(), Some("a.example"));
        assert_eq!(p.highest_layer.as_deref(), Some("http"));
    }

    #[test]
    fn dispatches_by_source_port_for_responses() {
        let p = run(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", 80, 40000, true);
        assert_eq!(p.http_server.as_deref(), Some("nginx"));
    }

    #[test]
    fn sniffing_finds_http_on_an_unregistered_port() {
        let p = run(
            b"GET /x HTTP/1.1\r\nHost: b.example\r\n\r\n",
            12345,
            31337,
            true,
        );
        assert_eq!(p.http_host.as_deref(), Some("b.example"));
    }

    #[test]
    fn a_wrong_port_guess_does_not_leave_a_stale_layer() {
        // TLS bytes on port 80: the HTTP dissector must reject them, and the stack must not
        // claim "http" — the sniffer should land on TLS instead.
        let p = run(
            &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0],
            5555,
            80,
            true,
        );
        let stack = p.proto_stack.unwrap_or_default();
        assert!(!stack.contains("http"), "stack was {stack}");
        assert!(stack.contains("tls"), "stack was {stack}");
    }

    #[test]
    fn unrecognised_payloads_leave_the_stack_clean() {
        let p = run(&[0x9f, 0x41, 0x00, 0xde, 0xad], 33333, 44444, true);
        assert_eq!(p.proto_stack.as_deref(), Some(""));
    }

    #[test]
    fn empty_payload_is_a_no_op() {
        let p = run(b"", 1234, 80, true);
        assert!(p.http_method.is_none());
    }
}
