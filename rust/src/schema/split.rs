//! Split output mode: derive a core packet table plus one narrow table per protocol.
//!
//! Rather than maintaining a second set of builders, split mode is a pure projection of the
//! wide batch. A protocol's table is "the core columns, plus every column named `<prefix>_*`,
//! for the rows where at least one of those columns is non-null". One schema to maintain,
//! and the two modes cannot drift apart.

use std::sync::Arc;

use arrow::array::BooleanArray;
use arrow::compute::kernels::boolean::or;
use arrow::compute::{filter_record_batch, is_not_null};
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;

/// Columns copied into every per-protocol table so a sidecar is useful without a join,
/// and joinable on `packet_id` when it isn't.
pub const CORE_COLUMNS: &[&str] = &[
    "packet_id",
    "frame_number",
    "ts",
    "ts_epoch_ns",
    "frame_len",
    "cap_len",
    "proto_stack",
    "highest_layer",
    "eth_src",
    "eth_dst",
    "ip_version",
    "ip_src",
    "ip_dst",
    "ip_proto",
    "l4_proto",
    "src_port",
    "dst_port",
    "flow_id",
    "community_id",
    "direction",
    "payload_len",
];

/// A protocol table: the output file stem and the wide-schema column prefixes that feed it.
///
/// A few tables draw from more than one prefix — the TLS fingerprints are named `ja3`/`ja4`
/// rather than `tls_*`, and NetBIOS splits across `nbns_`/`nbss_` — so the mapping is a list
/// of prefixes rather than a single string.
pub struct ProtoTable {
    pub name: &'static str,
    pub prefixes: &'static [&'static str],
}

pub const PROTO_TABLES: &[ProtoTable] = &[
    ProtoTable {
        name: "arp",
        prefixes: &["arp_"],
    },
    ProtoTable {
        name: "icmp",
        prefixes: &["icmp_", "icmp6_"],
    },
    ProtoTable {
        name: "igmp",
        prefixes: &["igmp_"],
    },
    ProtoTable {
        name: "dns",
        prefixes: &["dns_"],
    },
    ProtoTable {
        name: "http",
        prefixes: &["http_", "http2_"],
    },
    ProtoTable {
        name: "tls",
        prefixes: &["tls_", "ja3", "ja4"],
    },
    ProtoTable {
        name: "quic",
        prefixes: &["quic_"],
    },
    ProtoTable {
        name: "dhcp",
        prefixes: &["dhcp_", "dhcp6_"],
    },
    ProtoTable {
        name: "smb",
        prefixes: &["smb_", "ntlm_"],
    },
    ProtoTable {
        name: "ssh",
        prefixes: &["ssh_", "hassh"],
    },
    ProtoTable {
        name: "ntp",
        prefixes: &["ntp_"],
    },
    ProtoTable {
        name: "snmp",
        prefixes: &["snmp_"],
    },
    ProtoTable {
        name: "smtp",
        prefixes: &["smtp_"],
    },
    ProtoTable {
        name: "ftp",
        prefixes: &["ftp_"],
    },
    ProtoTable {
        name: "imap",
        prefixes: &["imap_"],
    },
    ProtoTable {
        name: "pop3",
        prefixes: &["pop3_"],
    },
    ProtoTable {
        name: "irc",
        prefixes: &["irc_"],
    },
    ProtoTable {
        name: "telnet",
        prefixes: &["telnet_"],
    },
    ProtoTable {
        name: "tftp",
        prefixes: &["tftp_"],
    },
    ProtoTable {
        name: "vnc",
        prefixes: &["vnc_"],
    },
    ProtoTable {
        name: "ldap",
        prefixes: &["ldap_"],
    },
    ProtoTable {
        name: "kerberos",
        prefixes: &["krb_"],
    },
    ProtoTable {
        name: "radius",
        prefixes: &["radius_"],
    },
    ProtoTable {
        name: "rdp",
        prefixes: &["rdp_"],
    },
    ProtoTable {
        name: "mqtt",
        prefixes: &["mqtt_"],
    },
    ProtoTable {
        name: "sip",
        prefixes: &["sip_"],
    },
    ProtoTable {
        name: "rtp",
        prefixes: &["rtp_", "rtcp_"],
    },
    ProtoTable {
        name: "netbios",
        prefixes: &["nbns_", "nbss_"],
    },
    ProtoTable {
        name: "syslog",
        prefixes: &["syslog_"],
    },
    ProtoTable {
        name: "wireguard",
        prefixes: &["wireguard_"],
    },
    ProtoTable {
        name: "ipsec",
        prefixes: &["esp_", "ike_"],
    },
    ProtoTable {
        name: "modbus",
        prefixes: &["modbus_"],
    },
    ProtoTable {
        name: "dnp3",
        prefixes: &["dnp3_"],
    },
    ProtoTable {
        name: "s7comm",
        prefixes: &["s7comm_"],
    },
    ProtoTable {
        name: "enip",
        prefixes: &["enip_", "cip_"],
    },
    ProtoTable {
        name: "iec104",
        prefixes: &["iec104_"],
    },
    ProtoTable {
        name: "bacnet",
        prefixes: &["bacnet_"],
    },
    ProtoTable {
        name: "tunnel",
        prefixes: &[
            "tunnel_", "gre_", "vxlan_", "geneve_", "gtp_", "erspan_", "l2tp_", "teredo_",
        ],
    },
];

fn column_indices(batch: &RecordBatch, table: &ProtoTable) -> (Vec<usize>, Vec<usize>) {
    let fields = batch.schema();
    let mut core = Vec::with_capacity(CORE_COLUMNS.len());
    for name in CORE_COLUMNS {
        if let Ok(i) = fields.index_of(name) {
            core.push(i);
        }
    }
    let mut proto = Vec::new();
    for (i, f) in fields.fields().iter().enumerate() {
        if table.prefixes.iter().any(|p| f.name().starts_with(p)) {
            proto.push(i);
        }
    }
    (core, proto)
}

/// The core packet table for split mode: identity, addressing and the protocol stack.
pub fn core_table(batch: &RecordBatch) -> Result<RecordBatch, ArrowError> {
    let schema = batch.schema();
    let idx: Vec<usize> = CORE_COLUMNS
        .iter()
        .filter_map(|n| schema.index_of(n).ok())
        .collect();
    batch.project(&idx)
}

/// Project and filter a wide batch down to one protocol's rows and columns.
///
/// Returns `Ok(None)` when no row in this batch carried the protocol — the caller skips the
/// file entirely rather than writing an empty Parquet.
pub fn proto_table(
    batch: &RecordBatch,
    table: &ProtoTable,
) -> Result<Option<RecordBatch>, ArrowError> {
    let (core, proto) = column_indices(batch, table);
    if proto.is_empty() {
        return Ok(None);
    }

    // A row belongs to this protocol if any of its columns is set.
    let mut mask: Option<BooleanArray> = None;
    for &i in &proto {
        let present = is_not_null(batch.column(i).as_ref())?;
        mask = Some(match mask {
            None => present,
            Some(m) => or(&m, &present)?,
        });
    }
    let mask = match mask {
        Some(m) => m,
        None => return Ok(None),
    };
    if mask.true_count() == 0 {
        return Ok(None);
    }

    let mut idx = core;
    idx.extend_from_slice(&proto);
    let projected = batch.project(&idx)?;
    let filtered = filter_record_batch(&projected, &mask)?;
    if filtered.num_rows() == 0 {
        Ok(None)
    } else {
        Ok(Some(filtered))
    }
}

/// All non-empty protocol tables for a batch, in `PROTO_TABLES` order.
pub fn all_proto_tables(
    batch: &RecordBatch,
) -> Result<Vec<(&'static str, RecordBatch)>, ArrowError> {
    let mut out = Vec::new();
    for t in PROTO_TABLES {
        if let Some(b) = proto_table(batch, t)? {
            out.push((t.name, b));
        }
    }
    Ok(out)
}

/// Verify at startup that every declared prefix actually matches at least one wide column.
/// A typo here would otherwise produce a silently missing sidecar table.
pub fn validate_prefixes(field_names: &[&str]) -> Result<(), String> {
    for t in PROTO_TABLES {
        for p in t.prefixes {
            if !field_names.iter().any(|n| n.starts_with(p)) {
                return Err(format!(
                    "protocol table `{}` declares prefix `{}` which matches no schema column",
                    t.name, p
                ));
            }
        }
    }
    Ok(())
}

/// Debug helper: the shared Arrow schema reference, used to keep clippy from flagging the
/// unused `Arc` import in builds where only projections are exercised.
pub fn schema_of(batch: &RecordBatch) -> Arc<arrow::datatypes::Schema> {
    batch.schema()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::wide::{Packet, WideBuilder, FIELD_NAMES};

    #[test]
    fn every_prefix_matches_a_column() {
        validate_prefixes(FIELD_NAMES).unwrap();
    }

    #[test]
    fn proto_table_selects_only_matching_rows() {
        let mut b = WideBuilder::new();

        let mut p1 = Packet {
            packet_id: Some(1),
            dns_qname: Some("example.com".into()),
            ..Default::default()
        };
        b.append(&mut p1);

        let mut p2 = Packet {
            packet_id: Some(2),
            tcp_seq: Some(42),
            ..Default::default()
        };
        b.append(&mut p2);

        let batch = b.finish().unwrap();

        let dns = PROTO_TABLES.iter().find(|t| t.name == "dns").unwrap();
        let t = proto_table(&batch, dns).unwrap().expect("one DNS row");
        assert_eq!(t.num_rows(), 1);

        // A protocol absent from the batch yields no table at all.
        let sip = PROTO_TABLES.iter().find(|t| t.name == "sip").unwrap();
        assert!(proto_table(&batch, sip).unwrap().is_none());
    }
}
