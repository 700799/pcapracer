//! Industrial control protocols: Modbus/TCP, DNP3, S7comm, EtherNet/IP + CIP, IEC 60870-5-104
//! and BACnet.
//!
//! On an OT network these carry the operations that actually move physical equipment, so the
//! function code is the field that matters — a write to a coil register is a different event
//! from a read, and the difference is one byte.

use crate::bytes::Cur;
use crate::dissect::Ctx;
use crate::error::{DResult, DissectError};

// ---------------------------------------------------------------------------
// Modbus/TCP
// ---------------------------------------------------------------------------

fn modbus_function_name(f: u8) -> &'static str {
    match f {
        1 => "read-coils",
        2 => "read-discrete-inputs",
        3 => "read-holding-registers",
        4 => "read-input-registers",
        5 => "write-single-coil",
        6 => "write-single-register",
        7 => "read-exception-status",
        8 => "diagnostics",
        15 => "write-multiple-coils",
        16 => "write-multiple-registers",
        17 => "report-server-id",
        20 => "read-file-record",
        21 => "write-file-record",
        22 => "mask-write-register",
        23 => "read-write-multiple-registers",
        43 => "encapsulated-interface-transport",
        _ => "other",
    }
}

pub fn modbus(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("modbus");
    let mut c = Cur::new(payload);
    let txid = c.be16()?;
    let proto_id = c.be16()?;
    // The protocol identifier is always zero for Modbus/TCP; anything else is a different
    // protocol that happens to be on port 502.
    if proto_id != 0 {
        return Err(DissectError::Malformed);
    }
    let _len = c.be16()?;
    let unit = c.u8()?;
    let func = c.u8()?;

    ctx.pkt.modbus_transaction_id = Some(txid);
    ctx.pkt.modbus_protocol_id = Some(proto_id);
    ctx.pkt.modbus_unit_id = Some(unit);

    // The high bit of the function code marks an exception response.
    if func & 0x80 != 0 {
        ctx.pkt.modbus_function_code = Some(func & 0x7f);
        ctx.pkt.modbus_function_name =
            Some(format!("{}-exception", modbus_function_name(func & 0x7f)));
        ctx.pkt.modbus_exception_code = c.u8().ok();
        return Ok(());
    }

    ctx.pkt.modbus_function_code = Some(func);
    ctx.pkt.modbus_function_name = Some(modbus_function_name(func).to_string());
    // Read and write requests open with a starting address and a quantity.
    if matches!(func, 1..=6 | 15 | 16 | 23) {
        ctx.pkt.modbus_reference_number = c.be16().ok();
        ctx.pkt.modbus_word_count = c.be16().ok();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNP3
// ---------------------------------------------------------------------------

pub fn looks_like_dnp3(d: &[u8]) -> bool {
    d.len() >= 10 && d[0] == 0x05 && d[1] == 0x64
}

pub fn dnp3(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("dnp3");
    let mut c = Cur::new(payload);
    if c.be16()? != 0x0564 {
        return Err(DissectError::Malformed);
    }
    let _len = c.u8()?;
    let control = c.u8()?;
    // Addresses are little-endian in the DNP3 link layer.
    let dest = c.le16()?;
    let src = c.le16()?;

    ctx.pkt.dnp3_control = Some(control);
    ctx.pkt.dnp3_destination = Some(dest);
    ctx.pkt.dnp3_source = Some(src);

    c.skip(2)?; // link-layer CRC
                // Transport and application headers follow; the application function code is what
                // identifies the operation.
    if c.remaining() >= 3 {
        c.skip(2)?; // transport header + application control
        let func = c.u8()?;
        ctx.pkt.dnp3_function_code = Some(func);
        ctx.pkt.dnp3_function_name = Some(
            match func {
                0 => "confirm",
                1 => "read",
                2 => "write",
                3 => "select",
                4 => "operate",
                5 => "direct-operate",
                13 => "cold-restart",
                14 => "warm-restart",
                129 => "response",
                130 => "unsolicited-response",
                _ => "other",
            }
            .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// S7comm
// ---------------------------------------------------------------------------

pub fn s7comm(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("s7comm");
    let mut c = Cur::new(payload);
    // S7 rides on COTP inside TPKT: skip the 4-byte TPKT header and the COTP header, whose
    // first byte is its own length.
    if c.peek_u8()? == 3 {
        c.skip(4)?;
        let cotp_len = c.u8()? as usize;
        c.skip(cotp_len)?;
    }
    if c.u8()? != 0x32 {
        return Err(DissectError::Malformed);
    }
    let rosctr = c.u8()?;
    ctx.pkt.s7comm_rosctr = Some(rosctr);
    c.skip(2)?; // redundancy identification
    ctx.pkt.s7comm_pdu_ref = Some(c.be16()?);
    let param_len = c.be16()?;
    let _data_len = c.be16()?;
    // Job and Ack_Data have an error class/code pair before the parameters.
    if rosctr == 2 || rosctr == 3 {
        c.skip(2)?;
    }
    if param_len > 0 {
        let func = c.u8()?;
        ctx.pkt.s7comm_function = Some(func);
        ctx.pkt.s7comm_function_name = Some(
            match func {
                0x00 => "cpu-services",
                0x04 => "read-var",
                0x05 => "write-var",
                0x1a => "request-download",
                0x1b => "download-block",
                0x1c => "download-ended",
                0x1d => "start-upload",
                0x1e => "upload",
                0x1f => "end-upload",
                0x28 => "plc-control",
                0x29 => "plc-stop",
                0xf0 => "setup-communication",
                _ => "other",
            }
            .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EtherNet/IP + CIP
// ---------------------------------------------------------------------------

pub fn enip(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("enip");
    let mut c = Cur::new(payload);
    // The ENIP encapsulation header is little-endian throughout.
    let command = c.le16()?;
    let _length = c.le16()?;
    let session = c.le32()?;
    ctx.pkt.enip_command = Some(command);
    ctx.pkt.enip_session_handle = Some(session);

    c.skip(4 + 8 + 4)?; // status, sender context, options

    // SendRRData / SendUnitData carry a CPF-wrapped CIP message.
    if matches!(command, 0x6f | 0x70) && c.remaining() > 12 {
        c.skip(6)?; // interface handle + timeout
        let item_count = c.le16()?;
        for _ in 0..item_count.min(4) {
            let _type_id = c.le16()?;
            let len = c.le16()? as usize;
            let item = match c.take(len.min(c.remaining())) {
                Ok(i) => i,
                Err(_) => break,
            };
            if item.len() >= 2 && ctx.pkt.cip_service.is_none() {
                let service = item[0];
                ctx.pkt.cip_service = Some(service & 0x7f);
                // The path is a word count followed by segments; an 8-bit logical class
                // segment is 0x20 followed by the class code.
                if item.len() >= 4 && item[2] == 0x20 {
                    ctx.pkt.cip_class = Some(item[3] as u16);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IEC 60870-5-104
// ---------------------------------------------------------------------------

pub fn looks_like_iec104(d: &[u8]) -> bool {
    d.len() >= 6 && d[0] == 0x68
}

pub fn iec104(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("iec104");
    let mut c = Cur::new(payload);
    if c.u8()? != 0x68 {
        return Err(DissectError::Malformed);
    }
    let _len = c.u8()?;
    let ctrl1 = c.u8()?;
    c.skip(3)?; // remaining control fields

    // Only I-format frames (low bit of the first control octet clear) carry an ASDU.
    if ctrl1 & 0x01 != 0 {
        return Ok(());
    }
    ctx.pkt.iec104_type_id = Some(c.u8()?);
    let _vsq = c.u8()?;
    ctx.pkt.iec104_cause = Some(c.u8()?);
    let _cause_hi = c.u8()?;
    ctx.pkt.iec104_asdu_address = Some(c.le16()?);
    Ok(())
}

// ---------------------------------------------------------------------------
// BACnet/IP
// ---------------------------------------------------------------------------

pub fn bacnet(payload: &[u8], ctx: &mut Ctx) -> DResult<()> {
    ctx.layer("bacnet");
    let mut c = Cur::new(payload);
    // BVLC header: type 0x81 for BACnet/IP.
    if c.u8()? != 0x81 {
        return Err(DissectError::Malformed);
    }
    let _function = c.u8()?;
    let _len = c.be16()?;

    // NPDU: version 1, then control flags.
    if c.u8()? != 1 {
        return Err(DissectError::Malformed);
    }
    let control = c.u8()?;
    // A network-layer message has no APDU to describe.
    if control & 0x80 != 0 {
        return Ok(());
    }
    // Skip optional destination/source addressing before the APDU.
    if control & 0x20 != 0 {
        c.skip(2)?;
        let dlen = c.u8()? as usize;
        c.skip(dlen)?;
    }
    if control & 0x08 != 0 {
        c.skip(2)?;
        let slen = c.u8()? as usize;
        c.skip(slen)?;
    }
    if control & 0x20 != 0 {
        c.skip(1)?; // hop count
    }

    let apdu_type = c.u8()?;
    ctx.pkt.bacnet_type = Some(apdu_type >> 4);
    // Confirmed requests carry an invoke ID before the service choice.
    match apdu_type >> 4 {
        0 => {
            c.skip(1)?; // max segments / max APDU
            c.skip(1)?; // invoke ID
            ctx.pkt.bacnet_service = c.u8().ok();
        }
        1 => ctx.pkt.bacnet_service = c.u8().ok(),
        _ => {}
    }
    Ok(())
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

    #[test]
    fn modbus_write_single_coil() {
        // txid 1, proto 0, len 6, unit 1, func 5, addr 0x000a, value 0xff00
        let v = [0, 1, 0, 0, 0, 6, 1, 5, 0, 0x0a, 0xff, 0x00];
        let (p, r) = run(|ctx| modbus(&v, ctx));
        r.unwrap();
        assert_eq!(p.modbus_function_code, Some(5));
        assert_eq!(p.modbus_function_name.as_deref(), Some("write-single-coil"));
        assert_eq!(p.modbus_reference_number, Some(10));
        assert_eq!(p.modbus_unit_id, Some(1));
    }

    #[test]
    fn modbus_exception_response() {
        let v = [0, 1, 0, 0, 0, 3, 1, 0x83, 0x02];
        let (p, r) = run(|ctx| modbus(&v, ctx));
        r.unwrap();
        assert_eq!(p.modbus_function_code, Some(3));
        assert_eq!(
            p.modbus_function_name.as_deref(),
            Some("read-holding-registers-exception")
        );
        assert_eq!(p.modbus_exception_code, Some(2));
    }

    #[test]
    fn modbus_rejects_a_nonzero_protocol_id() {
        let v = [0, 1, 0, 9, 0, 6, 1, 3, 0, 0, 0, 1];
        assert_eq!(run(|ctx| modbus(&v, ctx)).1, Err(DissectError::Malformed));
    }

    #[test]
    fn dnp3_operate_request() {
        // start bytes, len, control, dest 4 (LE), src 1 (LE), crc, transport, app ctrl, func
        let v = [
            0x05, 0x64, 0x0b, 0xc4, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc1, 0xc1, 0x04,
        ];
        let (p, r) = run(|ctx| dnp3(&v, ctx));
        r.unwrap();
        assert_eq!(p.dnp3_destination, Some(4));
        assert_eq!(p.dnp3_source, Some(1));
        assert_eq!(p.dnp3_function_name.as_deref(), Some("operate"));
    }

    #[test]
    fn iec104_i_format_asdu() {
        // APCI: 0x68, len, then four control octets with the low bit clear (I-format)
        let v = [
            0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x01, 0x06, 0x00, 0x01, 0x00, 0, 0, 0, 0,
        ];
        let (p, r) = run(|ctx| iec104(&v, ctx));
        r.unwrap();
        assert_eq!(p.iec104_type_id, Some(45)); // single command
        assert_eq!(p.iec104_cause, Some(6)); // activation
        assert_eq!(p.iec104_asdu_address, Some(1));
    }

    #[test]
    fn iec104_s_format_has_no_asdu() {
        let v = [0x68, 0x04, 0x01, 0x00, 0x02, 0x00];
        let (p, r) = run(|ctx| iec104(&v, ctx));
        r.unwrap();
        assert!(p.iec104_type_id.is_none());
    }

    #[test]
    fn s7comm_read_var() {
        let mut v = vec![0x03, 0x00, 0x00, 0x1f]; // TPKT
        v.extend_from_slice(&[0x02, 0xf0, 0x80]); // COTP: length 2, DT data
        v.extend_from_slice(&[0x32, 0x01, 0x00, 0x00, 0x00, 0x01]); // S7 header
        v.extend_from_slice(&[0x00, 0x0e, 0x00, 0x00]); // param len 14, data len 0
        v.push(0x04); // read-var
        let (p, r) = run(|ctx| s7comm(&v, ctx));
        r.unwrap();
        assert_eq!(p.s7comm_rosctr, Some(1));
        assert_eq!(p.s7comm_function_name.as_deref(), Some("read-var"));
    }

    #[test]
    fn truncated_ics_payloads_never_panic() {
        let modbus_pkt = [0u8, 1, 0, 0, 0, 6, 1, 5, 0, 0x0a, 0xff, 0x00];
        for n in 0..modbus_pkt.len() {
            let _ = run(|ctx| modbus(&modbus_pkt[..n], ctx));
        }
        let dnp3_pkt = [0x05u8, 0x64, 0x0b, 0xc4, 4, 0, 1, 0, 0, 0, 0xc1, 0xc1, 4];
        for n in 0..dnp3_pkt.len() {
            let _ = run(|ctx| dnp3(&dnp3_pkt[..n], ctx));
        }
    }
}
