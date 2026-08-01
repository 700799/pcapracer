//! The wide packet schema.
//!
//! Every extracted field is declared exactly once in the `packet_schema!` invocation at
//! the bottom of this file. The macro derives, from that single list:
//!
//!   * `Packet`   — the mutable record a dissector fills in
//!   * `schema()` — the Arrow `Schema`
//!   * `WideBuilder` — column-wise Arrow builders plus `append`/`finish`
//!
//! Keeping the three in lockstep matters: a field added to the struct but forgotten in the
//! builder would silently shift every column after it.

use std::sync::Arc;

use arrow::array::{
    ArrayRef, BinaryBuilder, BooleanBuilder, Float64Builder, Int64Builder, StringBuilder,
    TimestampNanosecondBuilder, UInt16Builder, UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;

// ---------------------------------------------------------------------------
// Token -> (rust type, arrow DataType, builder type, push expression)
// ---------------------------------------------------------------------------

macro_rules! pr_rty {
    (u8) => { u8 };
    (u16) => { u16 };
    (u32) => { u32 };
    (u64) => { u64 };
    (i64) => { i64 };
    (f64) => { f64 };
    (bool) => { bool };
    (str) => { String };
    (bin) => { Vec<u8> };
    (ts) => { i64 };
}

macro_rules! pr_dt {
    (u8) => {
        DataType::UInt8
    };
    (u16) => {
        DataType::UInt16
    };
    (u32) => {
        DataType::UInt32
    };
    (u64) => {
        DataType::UInt64
    };
    (i64) => {
        DataType::Int64
    };
    (f64) => {
        DataType::Float64
    };
    (bool) => {
        DataType::Boolean
    };
    (str) => {
        DataType::Utf8
    };
    (bin) => {
        DataType::Binary
    };
    (ts) => {
        DataType::Timestamp(TimeUnit::Nanosecond, None)
    };
}

macro_rules! pr_bld {
    (u8) => {
        UInt8Builder
    };
    (u16) => {
        UInt16Builder
    };
    (u32) => {
        UInt32Builder
    };
    (u64) => {
        UInt64Builder
    };
    (i64) => {
        Int64Builder
    };
    (f64) => {
        Float64Builder
    };
    (bool) => {
        BooleanBuilder
    };
    (str) => {
        StringBuilder
    };
    (bin) => {
        BinaryBuilder
    };
    (ts) => {
        TimestampNanosecondBuilder
    };
}

/// Owned values (String/Vec<u8>) must be borrowed for the Arrow builder; scalars move.
macro_rules! pr_push {
    (str, $b:expr, $v:expr) => {
        $b.append_option($v.as_deref())
    };
    (bin, $b:expr, $v:expr) => {
        $b.append_option($v.as_deref())
    };
    ($t:ident, $b:expr, $v:expr) => {
        $b.append_option($v)
    };
}

macro_rules! packet_schema {
    ($($name:ident : $ty:ident),* $(,)?) => {
        /// One packet's extracted features. All fields are optional: a field is `Some` only
        /// when the corresponding protocol was present and parsed successfully.
        #[derive(Debug, Default, Clone)]
        pub struct Packet {
            $(pub $name: Option<pr_rty!($ty)>,)*
        }

        impl Packet {
            /// Reset in place so the record can be reused across packets without reallocating
            /// the `String`/`Vec` field buffers' capacity being re-requested from the allocator
            /// on every packet. Cheaper than `Packet::default()` in the hot loop.
            pub fn clear(&mut self) {
                $(self.$name = None;)*
            }
        }

        /// Column names in schema order. Used by split mode to group columns by prefix.
        pub const FIELD_NAMES: &[&str] = &[$(stringify!($name),)*];

        pub fn schema() -> Arc<Schema> {
            Arc::new(Schema::new(vec![
                $(Field::new(stringify!($name), pr_dt!($ty), true),)*
            ]))
        }

        /// Column-wise Arrow builders for the wide schema.
        pub struct WideBuilder {
            schema: Arc<Schema>,
            rows: usize,
            $($name: pr_bld!($ty),)*
        }

        impl WideBuilder {
            pub fn new() -> Self {
                Self {
                    schema: schema(),
                    rows: 0,
                    $($name: <pr_bld!($ty)>::new(),)*
                }
            }

            /// Append a record, draining its owned fields so the `Packet` can be reused.
            pub fn append(&mut self, p: &mut Packet) {
                $({
                    let v = p.$name.take();
                    pr_push!($ty, self.$name, v);
                })*
                self.rows += 1;
            }

            pub fn len(&self) -> usize {
                self.rows
            }

            pub fn is_empty(&self) -> bool {
                self.rows == 0
            }

            pub fn schema(&self) -> Arc<Schema> {
                Arc::clone(&self.schema)
            }

            pub fn finish(&mut self) -> Result<RecordBatch, arrow::error::ArrowError> {
                let columns: Vec<ArrayRef> = vec![
                    $(Arc::new(self.$name.finish()) as ArrayRef,)*
                ];
                self.rows = 0;
                RecordBatch::try_new(Arc::clone(&self.schema), columns)
            }
        }

        impl Default for WideBuilder {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

packet_schema! {
    // ---- frame ------------------------------------------------------------
    packet_id: u64,
    frame_number: u64,
    ts: ts,
    ts_epoch_ns: i64,
    frame_len: u32,
    cap_len: u32,
    iface_id: u32,
    link_type: u16,
    proto_stack: str,
    highest_layer: str,
    malformed: bool,
    panicked: bool,
    truncated: bool,
    tunnel_depth: u8,

    // ---- L2 ---------------------------------------------------------------
    eth_src: str,
    eth_dst: str,
    eth_type: u16,
    eth_src_oui: str,
    eth_is_broadcast: bool,
    eth_is_multicast: bool,
    vlan_id: u16,
    vlan_pcp: u8,
    vlan_dei: bool,
    vlan_inner_id: u16,
    mpls_label: u32,
    mpls_tc: u8,
    mpls_ttl: u8,
    pppoe_session_id: u16,
    ppp_protocol: u16,
    llc_dsap: u8,
    llc_ssap: u8,
    llc_control: u8,
    snap_oui: u32,
    snap_pid: u16,
    arp_hw_type: u16,
    arp_proto_type: u16,
    arp_opcode: u16,
    arp_opcode_name: str,
    arp_sender_mac: str,
    arp_sender_ip: str,
    arp_target_mac: str,
    arp_target_ip: str,
    arp_is_gratuitous: bool,
    wlan_type: u8,
    wlan_subtype: u8,
    wlan_bssid: str,
    wlan_ssid: str,
    wlan_channel: u16,
    wlan_signal_dbm: i64,

    // ---- L3 ---------------------------------------------------------------
    ip_version: u8,
    ip_src: str,
    ip_dst: str,
    ip_src_is_private: bool,
    ip_dst_is_private: bool,
    ip_proto: u8,
    ip_proto_name: str,
    ip_ttl: u8,
    ip_tos: u8,
    ip_dscp: u8,
    ip_ecn: u8,
    ip_id: u32,
    ip_flag_df: bool,
    ip_flag_mf: bool,
    ip_frag_offset: u16,
    ip_hdr_len: u8,
    ip_total_len: u32,
    ip_checksum: u16,
    ip_options: str,
    ip6_flow_label: u32,
    ip6_traffic_class: u8,
    ip6_next_header: u8,
    ip6_hop_limit: u8,
    ip6_payload_len: u16,
    ip6_ext_headers: str,
    icmp_type: u8,
    icmp_code: u8,
    icmp_type_name: str,
    icmp_id: u16,
    icmp_seq: u16,
    icmp_gateway: str,
    icmp_mtu: u16,
    icmp6_type: u8,
    icmp6_code: u8,
    icmp6_type_name: str,
    icmp6_nd_target: str,
    icmp6_nd_option_mac: str,
    igmp_type: u8,
    igmp_max_resp: u8,
    igmp_group: str,

    // ---- L4 ---------------------------------------------------------------
    l4_proto: str,
    src_port: u16,
    dst_port: u16,
    tcp_seq: u32,
    tcp_ack: u32,
    tcp_flags: u16,
    tcp_flags_str: str,
    tcp_flag_syn: bool,
    tcp_flag_ack: bool,
    tcp_flag_fin: bool,
    tcp_flag_rst: bool,
    tcp_flag_psh: bool,
    tcp_flag_urg: bool,
    tcp_flag_ece: bool,
    tcp_flag_cwr: bool,
    tcp_window: u16,
    tcp_urgent_ptr: u16,
    tcp_checksum: u16,
    tcp_hdr_len: u8,
    tcp_mss: u16,
    tcp_window_scale: u8,
    tcp_sack_permitted: bool,
    tcp_sack_blocks: str,
    tcp_ts_val: u32,
    tcp_ts_ecr: u32,
    tcp_option_kinds: str,
    tcp_payload_len: u32,
    udp_len: u16,
    udp_checksum: u16,
    udp_payload_len: u32,
    sctp_verification_tag: u32,
    sctp_checksum: u32,
    sctp_chunk_types: str,
    sctp_num_chunks: u16,

    // ---- tunnels ----------------------------------------------------------
    tunnel_type: str,
    outer_ip_src: str,
    outer_ip_dst: str,
    outer_src_port: u16,
    outer_dst_port: u16,
    gre_protocol: u16,
    gre_key: u32,
    gre_seq: u32,
    vxlan_vni: u32,
    geneve_vni: u32,
    geneve_protocol: u16,
    gtp_teid: u32,
    gtp_msg_type: u8,
    gtp_version: u8,
    erspan_span_id: u16,
    erspan_version: u8,
    l2tp_tunnel_id: u16,
    l2tp_session_id: u16,
    teredo_present: bool,

    // ---- flow linkage -----------------------------------------------------
    flow_id: u64,
    community_id: str,
    direction: str,

    // ---- DNS / mDNS / LLMNR ----------------------------------------------
    dns_is_response: bool,
    dns_transaction_id: u16,
    dns_opcode: u8,
    dns_rcode: u8,
    dns_rcode_name: str,
    dns_flags: u16,
    dns_flag_aa: bool,
    dns_flag_tc: bool,
    dns_flag_rd: bool,
    dns_flag_ra: bool,
    dns_qname: str,
    dns_qname_len: u32,
    dns_qname_entropy: f64,
    dns_tld: str,
    dns_qtype: u16,
    dns_qtype_name: str,
    dns_qclass: u16,
    dns_qdcount: u16,
    dns_ancount: u16,
    dns_nscount: u16,
    dns_arcount: u16,
    dns_answers: str,
    dns_answer_ips: str,
    dns_cnames: str,
    dns_ns_names: str,
    dns_mx_names: str,
    dns_txt_data: str,
    dns_ttl_min: u32,
    dns_is_mdns: bool,
    dns_is_llmnr: bool,
    dns_over_tcp: bool,

    // ---- HTTP -------------------------------------------------------------
    http_is_request: bool,
    http_method: str,
    http_uri: str,
    http_uri_path: str,
    http_uri_query: str,
    http_version: str,
    http_host: str,
    http_user_agent: str,
    http_referer: str,
    http_cookie: str,
    http_content_type: str,
    http_content_length: u64,
    http_content_encoding: str,
    http_transfer_encoding: str,
    http_accept: str,
    http_accept_language: str,
    http_authorization: str,
    http_x_forwarded_for: str,
    http_status_code: u16,
    http_status_msg: str,
    http_server: str,
    http_location: str,
    http_set_cookie: str,
    http_header_names: str,
    http_header_count: u16,
    http_body_preview: str,
    http2_stream_id: u32,
    http2_frame_type: u8,
    http2_method: str,
    http2_path: str,
    http2_authority: str,
    http2_scheme: str,
    http2_status: str,

    // ---- TLS / DTLS -------------------------------------------------------
    tls_record_type: u8,
    tls_record_version: str,
    tls_handshake_type: u8,
    tls_handshake_type_name: str,
    tls_version: str,
    tls_supported_versions: str,
    tls_sni: str,
    tls_alpn: str,
    tls_cipher_suites: str,
    tls_cipher_suite_count: u16,
    tls_cipher_selected: str,
    tls_compression_methods: str,
    tls_extensions: str,
    tls_extension_count: u16,
    tls_supported_groups: str,
    tls_sig_algs: str,
    tls_ec_point_formats: str,
    tls_session_id_len: u16,
    tls_cert_subject: str,
    tls_cert_issuer: str,
    tls_cert_sans: str,
    tls_cert_serial: str,
    tls_cert_not_before: str,
    tls_cert_not_after: str,
    tls_cert_chain_len: u8,
    tls_cert_self_signed: bool,
    tls_alert_level: u8,
    tls_alert_description: u8,
    tls_is_dtls: bool,
    ja3: str,
    ja3_full: str,
    ja3s: str,
    ja3s_full: str,
    ja4: str,
    ja4s: str,

    // ---- QUIC -------------------------------------------------------------
    quic_version: u32,
    quic_packet_type: u8,
    quic_header_form: u8,
    quic_dcid: str,
    quic_scid: str,
    quic_sni: str,

    // ---- DHCP -------------------------------------------------------------
    dhcp_msg_type: u8,
    dhcp_msg_type_name: str,
    dhcp_op: u8,
    dhcp_transaction_id: u32,
    dhcp_client_mac: str,
    dhcp_client_ip: str,
    dhcp_your_ip: str,
    dhcp_requested_ip: str,
    dhcp_server_id: str,
    dhcp_hostname: str,
    dhcp_domain: str,
    dhcp_vendor_class: str,
    dhcp_param_req_list: str,
    dhcp_lease_time: u32,
    dhcp_fingerprint: str,
    dhcp6_msg_type: u8,
    dhcp6_transaction_id: u32,

    // ---- SMB / NTLM -------------------------------------------------------
    smb_version: str,
    smb_command: u16,
    smb_command_name: str,
    smb_status: u32,
    smb_flags: u32,
    smb_session_id: u64,
    smb_tree_id: u32,
    smb_tree: str,
    smb_filename: str,
    smb_dialect: str,
    smb_security_mode: u16,
    ntlm_user: str,
    ntlm_domain: str,
    ntlm_host: str,
    ntlm_message_type: u32,

    // ---- SSH --------------------------------------------------------------
    ssh_protocol_version: str,
    ssh_software: str,
    ssh_msg_type: u8,
    ssh_kex_algs: str,
    ssh_host_key_algs: str,
    ssh_enc_algs_c2s: str,
    ssh_enc_algs_s2c: str,
    ssh_mac_algs_c2s: str,
    ssh_comp_algs_c2s: str,
    hassh: str,
    hassh_server: str,

    // ---- NTP / SNMP -------------------------------------------------------
    ntp_leap: u8,
    ntp_version: u8,
    ntp_mode: u8,
    ntp_mode_name: str,
    ntp_stratum: u8,
    ntp_poll: i64,
    ntp_precision: i64,
    ntp_ref_id: str,
    snmp_version: u8,
    snmp_community: str,
    snmp_pdu_type: u8,
    snmp_pdu_type_name: str,
    snmp_request_id: i64,
    snmp_error_status: u8,
    snmp_oids: str,

    // ---- mail / file transfer / shell text protocols ----------------------
    smtp_command: str,
    smtp_argument: str,
    smtp_response_code: u16,
    smtp_response: str,
    smtp_mail_from: str,
    smtp_rcpt_to: str,
    smtp_subject: str,
    ftp_command: str,
    ftp_argument: str,
    ftp_response_code: u16,
    ftp_response: str,
    imap_tag: str,
    imap_command: str,
    imap_argument: str,
    pop3_command: str,
    pop3_argument: str,
    irc_command: str,
    irc_params: str,
    irc_nick: str,
    telnet_data: str,
    tftp_opcode: u16,
    tftp_filename: str,
    tftp_mode: str,
    vnc_version: str,

    // ---- directory / auth -------------------------------------------------
    ldap_message_id: u32,
    ldap_operation: str,
    ldap_dn: str,
    ldap_filter: str,
    ldap_attributes: str,
    ldap_result_code: u32,
    ldap_sasl_mechanism: str,
    krb_msg_type: u8,
    krb_msg_type_name: str,
    krb_realm: str,
    krb_cname: str,
    krb_sname: str,
    krb_etypes: str,
    krb_error_code: u32,
    radius_code: u8,
    radius_code_name: str,
    radius_identifier: u8,
    radius_username: str,
    radius_nas_ip: str,
    radius_called_station: str,
    radius_calling_station: str,

    // ---- remote access / messaging / VoIP ---------------------------------
    rdp_type: str,
    rdp_cookie: str,
    rdp_requested_protocols: u32,
    mqtt_msg_type: u8,
    mqtt_msg_type_name: str,
    mqtt_topic: str,
    mqtt_client_id: str,
    mqtt_username: str,
    mqtt_qos: u8,
    mqtt_payload_len: u32,
    sip_method: str,
    sip_uri: str,
    sip_from: str,
    sip_to: str,
    sip_call_id: str,
    sip_status_code: u16,
    sip_user_agent: str,
    rtp_version: u8,
    rtp_payload_type: u8,
    rtp_ssrc: u32,
    rtp_seq: u16,
    rtp_timestamp: u32,
    rtp_marker: bool,
    rtcp_type: u8,
    rtcp_ssrc: u32,

    // ---- name services / logging ------------------------------------------
    nbns_name: str,
    nbns_opcode: u8,
    nbss_type: u8,
    syslog_priority: u8,
    syslog_facility: u8,
    syslog_severity: u8,
    syslog_hostname: str,
    syslog_appname: str,
    syslog_message: str,

    // ---- VPN / crypto transports ------------------------------------------
    wireguard_type: u8,
    wireguard_sender: u32,
    wireguard_receiver: u32,
    esp_spi: u32,
    esp_seq: u32,
    ike_initiator_spi: str,
    ike_responder_spi: str,
    ike_exchange_type: u8,
    ike_version: str,
    ike_message_id: u32,

    // ---- ICS / OT ---------------------------------------------------------
    modbus_transaction_id: u16,
    modbus_protocol_id: u16,
    modbus_unit_id: u8,
    modbus_function_code: u8,
    modbus_function_name: str,
    modbus_reference_number: u16,
    modbus_word_count: u16,
    modbus_exception_code: u8,
    dnp3_source: u16,
    dnp3_destination: u16,
    dnp3_function_code: u8,
    dnp3_function_name: str,
    dnp3_control: u8,
    s7comm_rosctr: u8,
    s7comm_function: u8,
    s7comm_function_name: str,
    s7comm_pdu_ref: u16,
    enip_command: u16,
    enip_session_handle: u32,
    cip_service: u8,
    cip_class: u16,
    iec104_type_id: u8,
    iec104_cause: u8,
    iec104_asdu_address: u16,
    bacnet_type: u8,
    bacnet_service: u8,

    // ---- payload ----------------------------------------------------------
    payload_len: u32,
    payload_entropy: f64,
    payload_preview: str,
    payload_first_bytes: bin,
    payload_is_printable: bool,

    // ---- reassembly -------------------------------------------------------
    reassembled: bool,
    reassembly_partial: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_builder_agree() {
        let s = schema();
        assert_eq!(s.fields().len(), FIELD_NAMES.len());

        let mut b = WideBuilder::new();
        let mut p = Packet {
            packet_id: Some(1),
            ip_src: Some("10.0.0.1".into()),
            tcp_flag_syn: Some(true),
            ..Default::default()
        };
        b.append(&mut p);

        // `append` drains owned fields so the record can be reused.
        assert!(p.ip_src.is_none());

        let batch = b.finish().expect("column count must match the schema");
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), FIELD_NAMES.len());
    }

    #[test]
    fn clear_resets_every_field() {
        let mut p = Packet {
            dns_qname: Some("example.com".into()),
            frame_len: Some(74),
            ..Default::default()
        };
        p.clear();
        assert!(p.dns_qname.is_none());
        assert!(p.frame_len.is_none());
    }
}
