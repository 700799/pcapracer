//! LDAP and Kerberos — the two protocols that carry account names in cleartext on a
//! typical enterprise network, and therefore the two most worth extracting.

use crate::bytes::{cap, Cur};
use crate::dissect::app::ber;
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

// ---------------------------------------------------------------------------
// LDAP
// ---------------------------------------------------------------------------

fn ldap_op_name(tag: u8) -> &'static str {
    match tag {
        0 => "bindRequest",
        1 => "bindResponse",
        2 => "unbindRequest",
        3 => "searchRequest",
        4 => "searchResEntry",
        5 => "searchResDone",
        6 => "modifyRequest",
        7 => "modifyResponse",
        8 => "addRequest",
        9 => "addResponse",
        10 => "delRequest",
        11 => "delResponse",
        12 => "modDNRequest",
        13 => "modDNResponse",
        14 => "compareRequest",
        15 => "compareResponse",
        16 => "abandonRequest",
        23 => "extendedReq",
        24 => "extendedResp",
        _ => "unknown",
    }
}

pub fn ldap(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("ldap");
    let mut c = Cur::new(payload);
    let msg = ber::read_in(&mut c)?;
    if !msg.constructed || msg.tag != ber::TAG_SEQUENCE {
        return Err(DissectError::Malformed);
    }
    let mut m = msg.cur();

    let id = ber::read_in(&mut m)?;
    ctx.pkt.ldap_message_id = id.as_u64().map(|v| v as u32);

    let op = ber::read_in(&mut m)?;
    if op.class != ber::CLASS_APPLICATION {
        return Ok(());
    }
    ctx.pkt.ldap_operation = Some(ldap_op_name(op.tag).to_string());
    let mut o = op.cur();

    match op.tag {
        // bindRequest ::= { version INTEGER, name LDAPDN, authentication CHOICE }
        0 => {
            let _version = ber::read_in(&mut o)?;
            if let Ok(name) = ber::read_in(&mut o) {
                ctx.pkt.ldap_dn = name.as_str().map(|s| cap(s, 512));
            }
            // A SASL bind is [3]-tagged and names its mechanism; a simple bind is [0] and
            // carries the password, which is deliberately not recorded.
            if let Ok(auth) = ber::read_in(&mut o) {
                if auth.class == ber::CLASS_CONTEXT && auth.tag == 3 {
                    let mut a = auth.cur();
                    if let Ok(mech) = ber::read_in(&mut a) {
                        ctx.pkt.ldap_sasl_mechanism = mech.as_str();
                    }
                }
            }
        }
        // searchRequest ::= { baseObject LDAPDN, scope, derefAliases, sizeLimit, timeLimit,
        //   typesOnly, filter, attributes }
        3 => {
            if let Ok(base) = ber::read_in(&mut o) {
                ctx.pkt.ldap_dn = base.as_str().map(|s| cap(s, 512));
            }
            for _ in 0..5 {
                if ber::read_in(&mut o).is_err() {
                    return Ok(());
                }
            }
            if let Ok(filter) = ber::read_in(&mut o) {
                ctx.pkt.ldap_filter = Some(cap(render_filter(&filter, 6), 512));
            }
            if let Ok(attrs) = ber::read_in(&mut o) {
                let mut list: Vec<ber::Tlv> = Vec::new();
                ber::collect(attrs.val, 3, 32, &|t: &ber::Tlv| !t.constructed, &mut list);
                let names: Vec<String> = list.iter().filter_map(|t| t.as_str()).collect();
                if !names.is_empty() {
                    ctx.pkt.ldap_attributes = Some(cap(names.join(","), 512));
                }
            }
        }
        // Result-bearing responses open with an enumerated result code.
        1 | 5 | 7 | 9 | 11 | 13 | 15 | 24 => {
            if let Ok(code) = ber::read_in(&mut o) {
                ctx.pkt.ldap_result_code = code.as_u64().map(|v| v as u32);
            }
            if let Ok(dn) = ber::read_in(&mut o) {
                if let Some(s) = dn.as_str() {
                    ctx.pkt.ldap_dn = Some(cap(s, 512));
                }
            }
        }
        4 => {
            if let Ok(dn) = ber::read_in(&mut o) {
                ctx.pkt.ldap_dn = dn.as_str().map(|s| cap(s, 512));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Render an LDAP filter back into its familiar `(attr=value)` string form.
fn render_filter(t: &ber::Tlv, depth: u8) -> String {
    if depth == 0 {
        return "...".to_string();
    }
    let children = |op: &str| -> String {
        let mut c = t.cur();
        let mut parts = Vec::new();
        while let Ok(child) = ber::read_in(&mut c) {
            parts.push(render_filter(&child, depth - 1));
            if parts.len() >= 8 {
                break;
            }
        }
        format!("({}{})", op, parts.join(""))
    };
    let pair = |sep: &str| -> String {
        let mut c = t.cur();
        let a = ber::read_in(&mut c)
            .ok()
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        let v = ber::read_in(&mut c)
            .ok()
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        format!("({a}{sep}{v})")
    };

    match t.tag {
        0 => children("&"),
        1 => children("|"),
        2 => children("!"),
        3 => pair("="),
        5 => pair(">="),
        6 => pair("<="),
        7 => format!("({}=*)", t.as_str().unwrap_or_default()),
        8 => pair("~="),
        // Substring match: attribute followed by a sequence of typed fragments.
        4 => {
            let mut c = t.cur();
            let a = ber::read_in(&mut c)
                .ok()
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            format!("({a}=*)")
        }
        _ => "(?)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Kerberos
// ---------------------------------------------------------------------------

fn krb_msg_name(t: u8) -> &'static str {
    match t {
        10 => "AS-REQ",
        11 => "AS-REP",
        12 => "TGS-REQ",
        13 => "TGS-REP",
        14 => "AP-REQ",
        15 => "AP-REP",
        30 => "KRB-ERROR",
        _ => "unknown",
    }
}

const KRB_TAG_REALM: u8 = 3;

/// Kerberos over TCP is length-prefixed; over UDP it is not.
pub fn kerberos(payload: &[u8], ctx: &mut Ctx, over_tcp: bool) -> DResult<()> {
    ctx.layer("kerberos");
    let body = if over_tcp {
        let mut c = Cur::new(payload);
        let len = c.be32()? as usize;
        c.take(len.min(c.remaining()))?
    } else {
        payload
    };

    let mut c = Cur::new(body);
    let msg = ber::read_in(&mut c)?;
    if msg.class != ber::CLASS_APPLICATION {
        return Err(DissectError::Malformed);
    }
    ctx.pkt.krb_msg_type = Some(msg.tag);
    ctx.pkt.krb_msg_type_name = Some(krb_msg_name(msg.tag).to_string());

    // The application wrapper contains one SEQUENCE of context-tagged fields.
    let mut m = msg.cur();
    let seq = match ber::read_in(&mut m) {
        Ok(s) if s.constructed => s,
        _ => return Ok(()),
    };
    let mut s = seq.cur();
    while let Ok(field) = ber::read_in(&mut s) {
        if field.class != ber::CLASS_CONTEXT {
            continue;
        }
        let mut f = field.cur();
        let inner = match ber::read_in(&mut f) {
            Ok(i) => i,
            Err(_) => continue,
        };
        // The realm is recorded from the first field that carries it; later ones in the same
        // message repeat it.
        if field.tag == KRB_TAG_REALM && ctx.pkt.krb_realm.is_none() {
            ctx.pkt.krb_realm = inner.as_str().map(|s| cap(s, 256));
        }
    }

    // Principal names, encryption types and the error code live at varying depths depending
    // on the message type, so they are located by shape rather than by a per-type walk.
    collect_principals(seq.val, ctx);
    if msg.tag == 30 {
        ctx.pkt.krb_error_code = find_error_code(seq.val);
    }
    Ok(())
}

/// PrincipalName ::= SEQUENCE { name-type [0] INTEGER, name-string [1] SEQUENCE OF String }.
/// The first principal found is the client, the second the service — which matches the field
/// order in AS-REQ and TGS-REQ.
fn collect_principals(data: &[u8], ctx: &mut Ctx) {
    let mut names: Vec<String> = Vec::new();
    let mut seqs: Vec<ber::Tlv> = Vec::new();
    ber::collect(
        data,
        8,
        64,
        &|t: &ber::Tlv| t.class == ber::CLASS_UNIVERSAL && t.tag == ber::TAG_SEQUENCE,
        &mut seqs,
    );

    for s in &seqs {
        let mut c = s.cur();
        let first = match ber::read_in(&mut c) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if !(first.class == ber::CLASS_CONTEXT && first.tag == 0) {
            continue;
        }
        let second = match ber::read_in(&mut c) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !(second.class == ber::CLASS_CONTEXT && second.tag == 1) {
            continue;
        }
        let mut parts: Vec<ber::Tlv> = Vec::new();
        ber::collect(
            second.val,
            4,
            8,
            &|t: &ber::Tlv| !t.constructed && t.class == ber::CLASS_UNIVERSAL,
            &mut parts,
        );
        let joined: Vec<String> = parts.iter().filter_map(|t| t.as_str()).collect();
        if !joined.is_empty() {
            names.push(joined.join("/"));
        }
        if names.len() >= 2 {
            break;
        }
    }

    if let Some(c) = names.first() {
        ctx.pkt.krb_cname = Some(cap(c.clone(), 256));
    }
    if let Some(s) = names.get(1) {
        ctx.pkt.krb_sname = Some(cap(s.clone(), 256));
    }

    // Requested encryption types: the etype list is a SEQUENCE of small INTEGERs, and a
    // downgrade to RC4 (23) or DES is exactly what Kerberoasting looks like.
    for s in &seqs {
        let mut c = s.cur();
        let mut ints = Vec::new();
        let mut all_int = true;
        while let Ok(t) = ber::read_in(&mut c) {
            if t.class == ber::CLASS_UNIVERSAL && t.tag == ber::TAG_INTEGER {
                if let Some(v) = t.as_i64() {
                    ints.push(v.to_string());
                }
            } else {
                all_int = false;
                break;
            }
        }
        if all_int && ints.len() >= 2 {
            ctx.pkt.krb_etypes = Some(cap(ints.join(","), 128));
            break;
        }
    }
}

fn find_error_code(data: &[u8]) -> Option<u32> {
    // error-code is context tag [6] in KRB-ERROR.
    let mut c = Cur::new(data);
    while let Ok(f) = ber::read_in(&mut c) {
        if f.class == ber::CLASS_CONTEXT && f.tag == 6 {
            let mut i = f.cur();
            return ber::read_in(&mut i)
                .ok()
                .and_then(|t| t.as_u64())
                .map(|v| v as u32);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Packet;

    fn run<F: FnOnce(&mut Ctx) -> DResult<()>>(f: F) -> (Packet, Result<(), DissectError>) {
        let mut p = Packet::default();
        let r = {
            let mut ctx = Ctx::new(&mut p);
            f(&mut ctx)
        };
        (p, r)
    }

    /// LDAP bindRequest for cn=admin,dc=example,dc=com with a simple password.
    fn bind_request() -> Vec<u8> {
        let dn = b"cn=admin,dc=example,dc=com";
        let mut op = vec![0x02, 0x01, 0x03]; // version 3
        op.push(0x04);
        op.push(dn.len() as u8);
        op.extend_from_slice(dn);
        op.extend_from_slice(&[0x80, 0x06]); // [0] simple auth
        op.extend_from_slice(b"secret");

        let mut msg = vec![0x02, 0x01, 0x01]; // messageID 1
        msg.push(0x60); // [APPLICATION 0] bindRequest
        msg.push(op.len() as u8);
        msg.extend_from_slice(&op);

        let mut v = vec![0x30, msg.len() as u8];
        v.extend_from_slice(&msg);
        v
    }

    #[test]
    fn ldap_bind_yields_dn_but_not_the_password() {
        let (p, r) = run(|ctx| ldap(&bind_request(), ctx));
        r.unwrap();
        assert_eq!(p.ldap_message_id, Some(1));
        assert_eq!(p.ldap_operation.as_deref(), Some("bindRequest"));
        assert_eq!(p.ldap_dn.as_deref(), Some("cn=admin,dc=example,dc=com"));
        // The credential must never reach a column.
        let all = format!("{p:?}");
        assert!(!all.contains("secret"), "password leaked into the record");
    }

    #[test]
    fn ldap_rejects_non_ber_payloads() {
        let (_, r) = run(|ctx| ldap(b"not ldap at all", ctx));
        assert!(r.is_err());
    }

    #[test]
    fn ldap_truncation_never_panics() {
        let full = bind_request();
        for n in 0..full.len() {
            let _ = run(|ctx| ldap(&full[..n], ctx));
        }
    }

    /// A minimal AS-REQ carrying a realm and a client principal.
    fn as_req() -> Vec<u8> {
        // PrincipalName ::= SEQUENCE { [0] INTEGER 1, [1] SEQUENCE OF GeneralString }
        let name_string = {
            let mut s = vec![0x1b, 0x05];
            s.extend_from_slice(b"alice");
            let mut seq = vec![0x30, s.len() as u8];
            seq.extend_from_slice(&s);
            let mut tagged = vec![0xa1, seq.len() as u8];
            tagged.extend_from_slice(&seq);
            tagged
        };
        let mut principal = vec![0xa0, 0x03, 0x02, 0x01, 0x01];
        principal.extend_from_slice(&name_string);
        let mut principal_seq = vec![0x30, principal.len() as u8];
        principal_seq.extend_from_slice(&principal);

        let mut fields = vec![0xa2, 0x03, 0x02, 0x01, 0x0a]; // [2] msg-type = 10
        let realm = {
            let mut r = vec![0x1b, 0x0b];
            r.extend_from_slice(b"EXAMPLE.COM");
            let mut t = vec![0xa3, r.len() as u8];
            t.extend_from_slice(&r);
            t
        };
        fields.extend_from_slice(&realm);
        fields.extend_from_slice(&principal_seq);

        let mut seq = vec![0x30, fields.len() as u8];
        seq.extend_from_slice(&fields);
        let mut app = vec![0x6a, seq.len() as u8]; // [APPLICATION 10] AS-REQ
        app.extend_from_slice(&seq);
        app
    }

    #[test]
    fn kerberos_as_req_yields_realm_and_principal() {
        let (p, r) = run(|ctx| kerberos(&as_req(), ctx, false));
        r.unwrap();
        assert_eq!(p.krb_msg_type_name.as_deref(), Some("AS-REQ"));
        assert_eq!(p.krb_realm.as_deref(), Some("EXAMPLE.COM"));
        assert_eq!(p.krb_cname.as_deref(), Some("alice"));
    }

    #[test]
    fn kerberos_over_tcp_strips_the_length_prefix() {
        let body = as_req();
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(&body);
        let (p, r) = run(|ctx| kerberos(&v, ctx, true));
        r.unwrap();
        assert_eq!(p.krb_msg_type_name.as_deref(), Some("AS-REQ"));
    }
}
