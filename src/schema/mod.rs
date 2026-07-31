//! Arrow schemas and column builders for each output table.

pub mod flows;
pub mod packets;

use arrow_array::builder::StringBuilder;
use crate::util::{write_ipv4, write_mac, IpRepr};

/// Append an optional MAC address as a formatted string.
#[inline]
pub(crate) fn push_mac(b: &mut StringBuilder, scratch: &mut String, mac: Option<[u8; 6]>) {
    match mac {
        Some(m) => {
            scratch.clear();
            write_mac(scratch, m);
            b.append_value(&*scratch);
        }
        None => b.append_null(),
    }
}

/// Append an optional IP address (v4 or v6) as a formatted string.
#[inline]
pub(crate) fn push_ip(b: &mut StringBuilder, scratch: &mut String, ip: Option<IpRepr>) {
    match ip {
        Some(r) => {
            scratch.clear();
            r.write(scratch);
            b.append_value(&*scratch);
        }
        None => b.append_null(),
    }
}

/// Append an optional IPv4 (4-byte) address as a formatted string.
#[inline]
pub(crate) fn push_ipv4(b: &mut StringBuilder, scratch: &mut String, ip: Option<[u8; 4]>) {
    match ip {
        Some(o) => {
            scratch.clear();
            write_ipv4(scratch, o);
            b.append_value(&*scratch);
        }
        None => b.append_null(),
    }
}
