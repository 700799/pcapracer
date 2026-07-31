//! `packets` table: one row per packet with a wide, mostly-nullable schema.

use super::{push_ip, push_ipv4, push_mac};
use crate::decode::PacketMeta;
use crate::reader::RecMeta;
use arrow_array::builder::{
    BooleanBuilder, Float32Builder, StringBuilder, TimestampNanosecondBuilder, UInt16Builder,
    UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

macro_rules! fields {
    ($($name:literal : $dt:expr, $null:literal);* $(;)?) => {
        vec![ $( Field::new($name, $dt, $null) ),* ]
    };
}

pub fn schema() -> Arc<Schema> {
    use DataType::*;
    let ts = Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
    let f = fields![
        "pkt_id": UInt64, false;
        "ts": ts, false;
        "cap_len": UInt32, false;
        "wire_len": UInt32, false;
        "linktype": UInt16, false;
        "iface_id": UInt32, false;
        "eth_src": Utf8, true;
        "eth_dst": Utf8, true;
        "eth_type": UInt16, true;
        "vlan1_id": UInt16, true;
        "vlan1_pcp": UInt8, true;
        "vlan2_id": UInt16, true;
        "mpls_top_label": UInt32, true;
        "mpls_depth": UInt8, true;
        "arp_op": UInt16, true;
        "arp_hw_type": UInt16, true;
        "arp_sender_mac": Utf8, true;
        "arp_sender_ip": Utf8, true;
        "arp_target_mac": Utf8, true;
        "arp_target_ip": Utf8, true;
        "tunnel_depth": UInt8, false;
        "tunnel_stack": Utf8, true;
        "vxlan_vni": UInt32, true;
        "gre_protocol": UInt16, true;
        "outer_src_ip": Utf8, true;
        "outer_dst_ip": Utf8, true;
        "ip_version": UInt8, true;
        "src_ip": Utf8, true;
        "dst_ip": Utf8, true;
        "ip_proto": UInt8, true;
        "ip_ttl": UInt8, true;
        "ip_dscp": UInt8, true;
        "ip_ecn": UInt8, true;
        "ip_len": UInt32, true;
        "is_fragment": Boolean, true;
        "ipv4_ihl": UInt8, true;
        "ipv4_id": UInt16, true;
        "ipv4_df": Boolean, true;
        "ipv4_mf": Boolean, true;
        "ipv4_frag_offset": UInt16, true;
        "ipv4_checksum": UInt16, true;
        "ipv4_options_len": UInt8, true;
        "ipv6_flow_label": UInt32, true;
        "ipv6_next_header": UInt8, true;
        "ipv6_ext_headers": Utf8, true;
        "icmp_type": UInt8, true;
        "icmp_code": UInt8, true;
        "icmp_echo_id": UInt16, true;
        "icmp_echo_seq": UInt16, true;
        "icmp_mtu": UInt16, true;
        "src_port": UInt16, true;
        "dst_port": UInt16, true;
        "tcp_seq": UInt32, true;
        "tcp_ack": UInt32, true;
        "tcp_header_len": UInt8, true;
        "tcp_flags": UInt16, true;
        "tcp_flag_fin": Boolean, true;
        "tcp_flag_syn": Boolean, true;
        "tcp_flag_rst": Boolean, true;
        "tcp_flag_psh": Boolean, true;
        "tcp_flag_ack": Boolean, true;
        "tcp_flag_urg": Boolean, true;
        "tcp_flag_ece": Boolean, true;
        "tcp_flag_cwr": Boolean, true;
        "tcp_window": UInt16, true;
        "tcp_checksum": UInt16, true;
        "tcp_urgent_ptr": UInt16, true;
        "tcp_mss": UInt16, true;
        "tcp_wscale": UInt8, true;
        "tcp_sack_permitted": Boolean, true;
        "tcp_sack_count": UInt8, true;
        "tcp_ts_val": UInt32, true;
        "tcp_ts_ecr": UInt32, true;
        "tcp_payload_len": UInt32, true;
        "udp_len": UInt16, true;
        "udp_checksum": UInt16, true;
        "payload_len": UInt32, true;
        "payload_entropy": Float32, true;
        "payload_printable_ratio": Float32, true;
        "payload_hex_prefix": Utf8, true;
        "app_proto": Utf8, true;
        "dns_qname": Utf8, true;
        "dns_qtype": UInt16, true;
        "dns_is_response": Boolean, true;
        "tls_sni": Utf8, true;
        "tls_version": UInt16, true;
        "tls_ja3": Utf8, true;
        "tls_ja4": Utf8, true;
        "http_method": Utf8, true;
        "http_host": Utf8, true;
        "http_uri": Utf8, true;
        "http_status": UInt16, true;
        "http_user_agent": Utf8, true;
        "quic_version": UInt32, true;
        "quic_dcid": Utf8, true;
        "banner": Utf8, true;
        "sctp_verification_tag": UInt32, true;
        "sctp_chunk_type": UInt8, true;
        "igmp_type": UInt8, true;
        "snmp_version": UInt8, true;
        "snmp_community": Utf8, true;
        "modbus_function": UInt8, true;
        "modbus_unit_id": UInt8, true;
        "sip_method": Utf8, true;
        "sip_uri": Utf8, true;
        "smb_dialect": Utf8, true;
        "tftp_opcode": UInt8, true;
        "syslog_severity": UInt8, true;
        "syslog_facility": UInt8, true;
    ];
    Arc::new(Schema::new(f))
}

/// Column-oriented builder for the `packets` table.
pub struct PacketsBuilder {
    schema: Arc<Schema>,
    scratch: String,
    n: usize,

    pkt_id: UInt64Builder,
    ts: TimestampNanosecondBuilder,
    cap_len: UInt32Builder,
    wire_len: UInt32Builder,
    linktype: UInt16Builder,
    iface_id: UInt32Builder,

    eth_src: StringBuilder,
    eth_dst: StringBuilder,
    eth_type: UInt16Builder,
    vlan1_id: UInt16Builder,
    vlan1_pcp: UInt8Builder,
    vlan2_id: UInt16Builder,
    mpls_top_label: UInt32Builder,
    mpls_depth: UInt8Builder,

    arp_op: UInt16Builder,
    arp_hw_type: UInt16Builder,
    arp_sender_mac: StringBuilder,
    arp_sender_ip: StringBuilder,
    arp_target_mac: StringBuilder,
    arp_target_ip: StringBuilder,

    tunnel_depth: UInt8Builder,
    tunnel_stack: StringBuilder,
    vxlan_vni: UInt32Builder,
    gre_protocol: UInt16Builder,
    outer_src_ip: StringBuilder,
    outer_dst_ip: StringBuilder,

    ip_version: UInt8Builder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    ip_proto: UInt8Builder,
    ip_ttl: UInt8Builder,
    ip_dscp: UInt8Builder,
    ip_ecn: UInt8Builder,
    ip_len: UInt32Builder,
    is_fragment: BooleanBuilder,
    ipv4_ihl: UInt8Builder,
    ipv4_id: UInt16Builder,
    ipv4_df: BooleanBuilder,
    ipv4_mf: BooleanBuilder,
    ipv4_frag_offset: UInt16Builder,
    ipv4_checksum: UInt16Builder,
    ipv4_options_len: UInt8Builder,
    ipv6_flow_label: UInt32Builder,
    ipv6_next_header: UInt8Builder,
    ipv6_ext_headers: StringBuilder,

    icmp_type: UInt8Builder,
    icmp_code: UInt8Builder,
    icmp_echo_id: UInt16Builder,
    icmp_echo_seq: UInt16Builder,
    icmp_mtu: UInt16Builder,

    src_port: UInt16Builder,
    dst_port: UInt16Builder,

    tcp_seq: UInt32Builder,
    tcp_ack: UInt32Builder,
    tcp_header_len: UInt8Builder,
    tcp_flags: UInt16Builder,
    tcp_flag_fin: BooleanBuilder,
    tcp_flag_syn: BooleanBuilder,
    tcp_flag_rst: BooleanBuilder,
    tcp_flag_psh: BooleanBuilder,
    tcp_flag_ack: BooleanBuilder,
    tcp_flag_urg: BooleanBuilder,
    tcp_flag_ece: BooleanBuilder,
    tcp_flag_cwr: BooleanBuilder,
    tcp_window: UInt16Builder,
    tcp_checksum: UInt16Builder,
    tcp_urgent_ptr: UInt16Builder,
    tcp_mss: UInt16Builder,
    tcp_wscale: UInt8Builder,
    tcp_sack_permitted: BooleanBuilder,
    tcp_sack_count: UInt8Builder,
    tcp_ts_val: UInt32Builder,
    tcp_ts_ecr: UInt32Builder,
    tcp_payload_len: UInt32Builder,

    udp_len: UInt16Builder,
    udp_checksum: UInt16Builder,

    payload_len: UInt32Builder,
    payload_entropy: Float32Builder,
    payload_printable_ratio: Float32Builder,
    payload_hex_prefix: StringBuilder,

    app_proto: StringBuilder,
    dns_qname: StringBuilder,
    dns_qtype: UInt16Builder,
    dns_is_response: BooleanBuilder,
    tls_sni: StringBuilder,
    tls_version: UInt16Builder,
    tls_ja3: StringBuilder,
    tls_ja4: StringBuilder,
    http_method: StringBuilder,
    http_host: StringBuilder,
    http_uri: StringBuilder,
    http_status: UInt16Builder,
    http_user_agent: StringBuilder,
    quic_version: UInt32Builder,
    quic_dcid: StringBuilder,
    banner: StringBuilder,
    sctp_verification_tag: UInt32Builder,
    sctp_chunk_type: UInt8Builder,
    igmp_type: UInt8Builder,
    snmp_version: UInt8Builder,
    snmp_community: StringBuilder,
    modbus_function: UInt8Builder,
    modbus_unit_id: UInt8Builder,
    sip_method: StringBuilder,
    sip_uri: StringBuilder,
    smb_dialect: StringBuilder,
    tftp_opcode: UInt8Builder,
    syslog_severity: UInt8Builder,
    syslog_facility: UInt8Builder,
}

impl PacketsBuilder {
    pub fn new(cap: usize) -> PacketsBuilder {
        macro_rules! p {
            () => {
                Default::default()
            };
        }
        PacketsBuilder {
            schema: schema(),
            scratch: String::with_capacity(48),
            n: 0,
            pkt_id: UInt64Builder::with_capacity(cap),
            ts: TimestampNanosecondBuilder::with_capacity(cap),
            cap_len: UInt32Builder::with_capacity(cap),
            wire_len: UInt32Builder::with_capacity(cap),
            linktype: UInt16Builder::with_capacity(cap),
            iface_id: UInt32Builder::with_capacity(cap),
            eth_src: StringBuilder::new(),
            eth_dst: StringBuilder::new(),
            eth_type: p!(),
            vlan1_id: p!(),
            vlan1_pcp: p!(),
            vlan2_id: p!(),
            mpls_top_label: p!(),
            mpls_depth: p!(),
            arp_op: p!(),
            arp_hw_type: p!(),
            arp_sender_mac: StringBuilder::new(),
            arp_sender_ip: StringBuilder::new(),
            arp_target_mac: StringBuilder::new(),
            arp_target_ip: StringBuilder::new(),
            tunnel_depth: p!(),
            tunnel_stack: StringBuilder::new(),
            vxlan_vni: p!(),
            gre_protocol: p!(),
            outer_src_ip: StringBuilder::new(),
            outer_dst_ip: StringBuilder::new(),
            ip_version: p!(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            ip_proto: p!(),
            ip_ttl: p!(),
            ip_dscp: p!(),
            ip_ecn: p!(),
            ip_len: p!(),
            is_fragment: p!(),
            ipv4_ihl: p!(),
            ipv4_id: p!(),
            ipv4_df: p!(),
            ipv4_mf: p!(),
            ipv4_frag_offset: p!(),
            ipv4_checksum: p!(),
            ipv4_options_len: p!(),
            ipv6_flow_label: p!(),
            ipv6_next_header: p!(),
            ipv6_ext_headers: StringBuilder::new(),
            icmp_type: p!(),
            icmp_code: p!(),
            icmp_echo_id: p!(),
            icmp_echo_seq: p!(),
            icmp_mtu: p!(),
            src_port: p!(),
            dst_port: p!(),
            tcp_seq: p!(),
            tcp_ack: p!(),
            tcp_header_len: p!(),
            tcp_flags: p!(),
            tcp_flag_fin: p!(),
            tcp_flag_syn: p!(),
            tcp_flag_rst: p!(),
            tcp_flag_psh: p!(),
            tcp_flag_ack: p!(),
            tcp_flag_urg: p!(),
            tcp_flag_ece: p!(),
            tcp_flag_cwr: p!(),
            tcp_window: p!(),
            tcp_checksum: p!(),
            tcp_urgent_ptr: p!(),
            tcp_mss: p!(),
            tcp_wscale: p!(),
            tcp_sack_permitted: p!(),
            tcp_sack_count: p!(),
            tcp_ts_val: p!(),
            tcp_ts_ecr: p!(),
            tcp_payload_len: p!(),
            udp_len: p!(),
            udp_checksum: p!(),
            payload_len: p!(),
            payload_entropy: p!(),
            payload_printable_ratio: p!(),
            payload_hex_prefix: StringBuilder::new(),
            app_proto: StringBuilder::new(),
            dns_qname: StringBuilder::new(),
            dns_qtype: p!(),
            dns_is_response: p!(),
            tls_sni: StringBuilder::new(),
            tls_version: p!(),
            tls_ja3: StringBuilder::new(),
            tls_ja4: StringBuilder::new(),
            http_method: StringBuilder::new(),
            http_host: StringBuilder::new(),
            http_uri: StringBuilder::new(),
            http_status: p!(),
            http_user_agent: StringBuilder::new(),
            quic_version: p!(),
            quic_dcid: StringBuilder::new(),
            banner: StringBuilder::new(),
            sctp_verification_tag: p!(),
            sctp_chunk_type: p!(),
            igmp_type: p!(),
            snmp_version: p!(),
            snmp_community: StringBuilder::new(),
            modbus_function: p!(),
            modbus_unit_id: p!(),
            sip_method: StringBuilder::new(),
            sip_uri: StringBuilder::new(),
            smb_dialect: StringBuilder::new(),
            tftp_opcode: p!(),
            syslog_severity: p!(),
            syslog_facility: p!(),
        }
    }

    pub fn schema(&self) -> Arc<Schema> {
        Arc::clone(&self.schema)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn append(&mut self, pkt_id: u64, rec: &RecMeta, m: &PacketMeta) {
        self.n += 1;
        self.pkt_id.append_value(pkt_id);
        self.ts.append_value(rec.ts_ns);
        self.cap_len.append_value(rec.caplen);
        self.wire_len.append_value(rec.wirelen);
        self.linktype.append_value(rec.linktype);
        self.iface_id.append_value(rec.iface);

        push_mac(&mut self.eth_src, &mut self.scratch, m.eth_src);
        push_mac(&mut self.eth_dst, &mut self.scratch, m.eth_dst);
        self.eth_type.append_option(m.eth_type);
        self.vlan1_id.append_option(m.vlan1_id);
        self.vlan1_pcp.append_option(m.vlan1_pcp);
        self.vlan2_id.append_option(m.vlan2_id);
        self.mpls_top_label.append_option(m.mpls_top_label);
        self.mpls_depth.append_option(m.mpls_depth);

        self.arp_op.append_option(m.arp_op);
        self.arp_hw_type.append_option(m.arp_hw_type);
        push_mac(&mut self.arp_sender_mac, &mut self.scratch, m.arp_sender_mac);
        push_ipv4(&mut self.arp_sender_ip, &mut self.scratch, m.arp_sender_ip);
        push_mac(&mut self.arp_target_mac, &mut self.scratch, m.arp_target_mac);
        push_ipv4(&mut self.arp_target_ip, &mut self.scratch, m.arp_target_ip);

        self.tunnel_depth.append_value(m.tunnel_depth);
        self.tunnel_stack
            .append_option(m.tunnel_stack.as_deref());
        self.vxlan_vni.append_option(m.vxlan_vni);
        self.gre_protocol.append_option(m.gre_protocol);
        push_ip(&mut self.outer_src_ip, &mut self.scratch, m.outer_src_ip);
        push_ip(&mut self.outer_dst_ip, &mut self.scratch, m.outer_dst_ip);

        self.ip_version.append_option(m.ip_version);
        push_ip(&mut self.src_ip, &mut self.scratch, m.src_ip);
        push_ip(&mut self.dst_ip, &mut self.scratch, m.dst_ip);
        self.ip_proto.append_option(m.ip_proto);
        self.ip_ttl.append_option(m.ip_ttl);
        self.ip_dscp.append_option(m.ip_dscp);
        self.ip_ecn.append_option(m.ip_ecn);
        self.ip_len.append_option(m.ip_len);
        self.is_fragment.append_option(m.is_fragment);
        self.ipv4_ihl.append_option(m.ipv4_ihl);
        self.ipv4_id.append_option(m.ipv4_id);
        self.ipv4_df.append_option(m.ipv4_df);
        self.ipv4_mf.append_option(m.ipv4_mf);
        self.ipv4_frag_offset.append_option(m.ipv4_frag_offset);
        self.ipv4_checksum.append_option(m.ipv4_checksum);
        self.ipv4_options_len.append_option(m.ipv4_options_len);
        self.ipv6_flow_label.append_option(m.ipv6_flow_label);
        self.ipv6_next_header.append_option(m.ipv6_next_header);
        self.ipv6_ext_headers
            .append_option(m.ipv6_ext_headers.as_deref());

        self.icmp_type.append_option(m.icmp_type);
        self.icmp_code.append_option(m.icmp_code);
        self.icmp_echo_id.append_option(m.icmp_echo_id);
        self.icmp_echo_seq.append_option(m.icmp_echo_seq);
        self.icmp_mtu.append_option(m.icmp_mtu);

        self.src_port.append_option(m.src_port);
        self.dst_port.append_option(m.dst_port);

        self.tcp_seq.append_option(m.tcp_seq);
        self.tcp_ack.append_option(m.tcp_ack);
        self.tcp_header_len.append_option(m.tcp_header_len);
        self.tcp_flags.append_option(m.tcp_flags);
        let fl = m.tcp_flags.map(|f| f as u8);
        self.tcp_flag_fin.append_option(fl.map(|f| f & 0x01 != 0));
        self.tcp_flag_syn.append_option(fl.map(|f| f & 0x02 != 0));
        self.tcp_flag_rst.append_option(fl.map(|f| f & 0x04 != 0));
        self.tcp_flag_psh.append_option(fl.map(|f| f & 0x08 != 0));
        self.tcp_flag_ack.append_option(fl.map(|f| f & 0x10 != 0));
        self.tcp_flag_urg.append_option(fl.map(|f| f & 0x20 != 0));
        self.tcp_flag_ece.append_option(fl.map(|f| f & 0x40 != 0));
        self.tcp_flag_cwr.append_option(fl.map(|f| f & 0x80 != 0));
        self.tcp_window.append_option(m.tcp_window);
        self.tcp_checksum.append_option(m.tcp_checksum);
        self.tcp_urgent_ptr.append_option(m.tcp_urgent_ptr);
        self.tcp_mss.append_option(m.tcp_mss);
        self.tcp_wscale.append_option(m.tcp_wscale);
        self.tcp_sack_permitted.append_option(m.tcp_sack_permitted);
        self.tcp_sack_count.append_option(m.tcp_sack_count);
        self.tcp_ts_val.append_option(m.tcp_ts_val);
        self.tcp_ts_ecr.append_option(m.tcp_ts_ecr);
        self.tcp_payload_len.append_option(m.tcp_payload_len);

        self.udp_len.append_option(m.udp_len);
        self.udp_checksum.append_option(m.udp_checksum);

        self.payload_len.append_option(m.payload_len);
        self.payload_entropy.append_option(m.payload_entropy);
        self.payload_printable_ratio
            .append_option(m.payload_printable_ratio);
        self.payload_hex_prefix
            .append_option(m.payload_hex_prefix.as_deref());

        self.app_proto.append_option(m.app_proto);
        self.dns_qname.append_option(m.dns_qname.as_deref());
        self.dns_qtype.append_option(m.dns_qtype);
        self.dns_is_response.append_option(m.dns_is_response);
        self.tls_sni.append_option(m.tls_sni.as_deref());
        self.tls_version.append_option(m.tls_version);
        self.tls_ja3.append_option(m.tls_ja3.as_deref());
        self.tls_ja4.append_option(m.tls_ja4.as_deref());
        self.http_method.append_option(m.http_method.as_deref());
        self.http_host.append_option(m.http_host.as_deref());
        self.http_uri.append_option(m.http_uri.as_deref());
        self.http_status.append_option(m.http_status);
        self.http_user_agent
            .append_option(m.http_user_agent.as_deref());
        self.quic_version.append_option(m.quic_version);
        self.quic_dcid.append_option(m.quic_dcid.as_deref());
        self.banner.append_option(m.banner.as_deref());
        self.sctp_verification_tag
            .append_option(m.sctp_verification_tag);
        self.sctp_chunk_type.append_option(m.sctp_chunk_type);
        self.igmp_type.append_option(m.igmp_type);
        self.snmp_version.append_option(m.snmp_version);
        self.snmp_community.append_option(m.snmp_community.as_deref());
        self.modbus_function.append_option(m.modbus_function);
        self.modbus_unit_id.append_option(m.modbus_unit_id);
        self.sip_method.append_option(m.sip_method.as_deref());
        self.sip_uri.append_option(m.sip_uri.as_deref());
        self.smb_dialect.append_option(m.smb_dialect);
        self.tftp_opcode.append_option(m.tftp_opcode);
        self.syslog_severity.append_option(m.syslog_severity);
        self.syslog_facility.append_option(m.syslog_facility);
    }

    pub fn finish(&mut self) -> Result<RecordBatch, arrow_schema::ArrowError> {
        let ts = self.ts.finish().with_timezone("UTC");
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(self.pkt_id.finish()),
            Arc::new(ts),
            Arc::new(self.cap_len.finish()),
            Arc::new(self.wire_len.finish()),
            Arc::new(self.linktype.finish()),
            Arc::new(self.iface_id.finish()),
            Arc::new(self.eth_src.finish()),
            Arc::new(self.eth_dst.finish()),
            Arc::new(self.eth_type.finish()),
            Arc::new(self.vlan1_id.finish()),
            Arc::new(self.vlan1_pcp.finish()),
            Arc::new(self.vlan2_id.finish()),
            Arc::new(self.mpls_top_label.finish()),
            Arc::new(self.mpls_depth.finish()),
            Arc::new(self.arp_op.finish()),
            Arc::new(self.arp_hw_type.finish()),
            Arc::new(self.arp_sender_mac.finish()),
            Arc::new(self.arp_sender_ip.finish()),
            Arc::new(self.arp_target_mac.finish()),
            Arc::new(self.arp_target_ip.finish()),
            Arc::new(self.tunnel_depth.finish()),
            Arc::new(self.tunnel_stack.finish()),
            Arc::new(self.vxlan_vni.finish()),
            Arc::new(self.gre_protocol.finish()),
            Arc::new(self.outer_src_ip.finish()),
            Arc::new(self.outer_dst_ip.finish()),
            Arc::new(self.ip_version.finish()),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.ip_proto.finish()),
            Arc::new(self.ip_ttl.finish()),
            Arc::new(self.ip_dscp.finish()),
            Arc::new(self.ip_ecn.finish()),
            Arc::new(self.ip_len.finish()),
            Arc::new(self.is_fragment.finish()),
            Arc::new(self.ipv4_ihl.finish()),
            Arc::new(self.ipv4_id.finish()),
            Arc::new(self.ipv4_df.finish()),
            Arc::new(self.ipv4_mf.finish()),
            Arc::new(self.ipv4_frag_offset.finish()),
            Arc::new(self.ipv4_checksum.finish()),
            Arc::new(self.ipv4_options_len.finish()),
            Arc::new(self.ipv6_flow_label.finish()),
            Arc::new(self.ipv6_next_header.finish()),
            Arc::new(self.ipv6_ext_headers.finish()),
            Arc::new(self.icmp_type.finish()),
            Arc::new(self.icmp_code.finish()),
            Arc::new(self.icmp_echo_id.finish()),
            Arc::new(self.icmp_echo_seq.finish()),
            Arc::new(self.icmp_mtu.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.tcp_seq.finish()),
            Arc::new(self.tcp_ack.finish()),
            Arc::new(self.tcp_header_len.finish()),
            Arc::new(self.tcp_flags.finish()),
            Arc::new(self.tcp_flag_fin.finish()),
            Arc::new(self.tcp_flag_syn.finish()),
            Arc::new(self.tcp_flag_rst.finish()),
            Arc::new(self.tcp_flag_psh.finish()),
            Arc::new(self.tcp_flag_ack.finish()),
            Arc::new(self.tcp_flag_urg.finish()),
            Arc::new(self.tcp_flag_ece.finish()),
            Arc::new(self.tcp_flag_cwr.finish()),
            Arc::new(self.tcp_window.finish()),
            Arc::new(self.tcp_checksum.finish()),
            Arc::new(self.tcp_urgent_ptr.finish()),
            Arc::new(self.tcp_mss.finish()),
            Arc::new(self.tcp_wscale.finish()),
            Arc::new(self.tcp_sack_permitted.finish()),
            Arc::new(self.tcp_sack_count.finish()),
            Arc::new(self.tcp_ts_val.finish()),
            Arc::new(self.tcp_ts_ecr.finish()),
            Arc::new(self.tcp_payload_len.finish()),
            Arc::new(self.udp_len.finish()),
            Arc::new(self.udp_checksum.finish()),
            Arc::new(self.payload_len.finish()),
            Arc::new(self.payload_entropy.finish()),
            Arc::new(self.payload_printable_ratio.finish()),
            Arc::new(self.payload_hex_prefix.finish()),
            Arc::new(self.app_proto.finish()),
            Arc::new(self.dns_qname.finish()),
            Arc::new(self.dns_qtype.finish()),
            Arc::new(self.dns_is_response.finish()),
            Arc::new(self.tls_sni.finish()),
            Arc::new(self.tls_version.finish()),
            Arc::new(self.tls_ja3.finish()),
            Arc::new(self.tls_ja4.finish()),
            Arc::new(self.http_method.finish()),
            Arc::new(self.http_host.finish()),
            Arc::new(self.http_uri.finish()),
            Arc::new(self.http_status.finish()),
            Arc::new(self.http_user_agent.finish()),
            Arc::new(self.quic_version.finish()),
            Arc::new(self.quic_dcid.finish()),
            Arc::new(self.banner.finish()),
            Arc::new(self.sctp_verification_tag.finish()),
            Arc::new(self.sctp_chunk_type.finish()),
            Arc::new(self.igmp_type.finish()),
            Arc::new(self.snmp_version.finish()),
            Arc::new(self.snmp_community.finish()),
            Arc::new(self.modbus_function.finish()),
            Arc::new(self.modbus_unit_id.finish()),
            Arc::new(self.sip_method.finish()),
            Arc::new(self.sip_uri.finish()),
            Arc::new(self.smb_dialect.finish()),
            Arc::new(self.tftp_opcode.finish()),
            Arc::new(self.syslog_severity.finish()),
            Arc::new(self.syslog_facility.finish()),
        ];
        self.n = 0;
        RecordBatch::try_new(Arc::clone(&self.schema), arrays)
    }
}
