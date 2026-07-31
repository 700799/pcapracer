//! `tls` table: one row per interesting TLS handshake message
//! (ClientHello / ServerHello / Certificate).

use super::push_ip;
use crate::util::IpRepr;
use arrow_array::builder::{
    StringBuilder, TimestampNanosecondBuilder, UInt16Builder, UInt8Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TlsRow {
    pub ts_ns: i64,
    pub src_ip: Option<IpRepr>,
    pub dst_ip: Option<IpRepr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub msg: &'static str,
    pub record_version: Option<u16>,
    pub legacy_version: Option<u16>,
    pub version_max: Option<u16>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub cipher_count: Option<u16>,
    pub ciphers: Option<String>,
    pub extensions: Option<String>,
    pub groups: Option<String>,
    pub ec_point_formats: Option<String>,
    pub sig_algs: Option<String>,
    pub ja3: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja4: Option<String>,
    pub cipher: Option<u16>,
    pub ja3s: Option<String>,
    pub ja3s_raw: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_not_before: Option<i64>,
    pub cert_not_after: Option<i64>,
    pub cert_serial: Option<String>,
    pub cert_san: Option<String>,
    pub cert_chain_len: Option<u8>,
}

pub fn schema() -> Arc<Schema> {
    use DataType::*;
    let ts = || Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
    let fields = vec![
        Field::new("ts", ts(), false),
        Field::new("src_ip", Utf8, true),
        Field::new("dst_ip", Utf8, true),
        Field::new("src_port", UInt16, false),
        Field::new("dst_port", UInt16, false),
        Field::new("msg", Utf8, false),
        Field::new("record_version", UInt16, true),
        Field::new("legacy_version", UInt16, true),
        Field::new("version_max", UInt16, true),
        Field::new("sni", Utf8, true),
        Field::new("alpn", Utf8, true),
        Field::new("cipher_count", UInt16, true),
        Field::new("ciphers", Utf8, true),
        Field::new("extensions", Utf8, true),
        Field::new("groups", Utf8, true),
        Field::new("ec_point_formats", Utf8, true),
        Field::new("sig_algs", Utf8, true),
        Field::new("ja3", Utf8, true),
        Field::new("ja3_raw", Utf8, true),
        Field::new("ja4", Utf8, true),
        Field::new("cipher", UInt16, true),
        Field::new("ja3s", Utf8, true),
        Field::new("ja3s_raw", Utf8, true),
        Field::new("cert_subject", Utf8, true),
        Field::new("cert_issuer", Utf8, true),
        Field::new("cert_not_before", ts(), true),
        Field::new("cert_not_after", ts(), true),
        Field::new("cert_serial", Utf8, true),
        Field::new("cert_san", Utf8, true),
        Field::new("cert_chain_len", UInt8, true),
    ];
    Arc::new(Schema::new(fields))
}

pub struct TlsBuilder {
    schema: Arc<Schema>,
    scratch: String,
    n: usize,
    ts: TimestampNanosecondBuilder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    msg: StringBuilder,
    record_version: UInt16Builder,
    legacy_version: UInt16Builder,
    version_max: UInt16Builder,
    sni: StringBuilder,
    alpn: StringBuilder,
    cipher_count: UInt16Builder,
    ciphers: StringBuilder,
    extensions: StringBuilder,
    groups: StringBuilder,
    ec_point_formats: StringBuilder,
    sig_algs: StringBuilder,
    ja3: StringBuilder,
    ja3_raw: StringBuilder,
    ja4: StringBuilder,
    cipher: UInt16Builder,
    ja3s: StringBuilder,
    ja3s_raw: StringBuilder,
    cert_subject: StringBuilder,
    cert_issuer: StringBuilder,
    cert_not_before: TimestampNanosecondBuilder,
    cert_not_after: TimestampNanosecondBuilder,
    cert_serial: StringBuilder,
    cert_san: StringBuilder,
    cert_chain_len: UInt8Builder,
}

impl TlsBuilder {
    pub fn new() -> TlsBuilder {
        TlsBuilder {
            schema: schema(),
            scratch: String::with_capacity(48),
            n: 0,
            ts: Default::default(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: Default::default(),
            dst_port: Default::default(),
            msg: StringBuilder::new(),
            record_version: Default::default(),
            legacy_version: Default::default(),
            version_max: Default::default(),
            sni: StringBuilder::new(),
            alpn: StringBuilder::new(),
            cipher_count: Default::default(),
            ciphers: StringBuilder::new(),
            extensions: StringBuilder::new(),
            groups: StringBuilder::new(),
            ec_point_formats: StringBuilder::new(),
            sig_algs: StringBuilder::new(),
            ja3: StringBuilder::new(),
            ja3_raw: StringBuilder::new(),
            ja4: StringBuilder::new(),
            cipher: Default::default(),
            ja3s: StringBuilder::new(),
            ja3s_raw: StringBuilder::new(),
            cert_subject: StringBuilder::new(),
            cert_issuer: StringBuilder::new(),
            cert_not_before: Default::default(),
            cert_not_after: Default::default(),
            cert_serial: StringBuilder::new(),
            cert_san: StringBuilder::new(),
            cert_chain_len: Default::default(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn append(&mut self, r: &TlsRow) {
        self.n += 1;
        self.ts.append_value(r.ts_ns);
        push_ip(&mut self.src_ip, &mut self.scratch, r.src_ip);
        push_ip(&mut self.dst_ip, &mut self.scratch, r.dst_ip);
        self.src_port.append_value(r.src_port);
        self.dst_port.append_value(r.dst_port);
        self.msg.append_value(r.msg);
        self.record_version.append_option(r.record_version);
        self.legacy_version.append_option(r.legacy_version);
        self.version_max.append_option(r.version_max);
        self.sni.append_option(r.sni.as_deref());
        self.alpn.append_option(r.alpn.as_deref());
        self.cipher_count.append_option(r.cipher_count);
        self.ciphers.append_option(r.ciphers.as_deref());
        self.extensions.append_option(r.extensions.as_deref());
        self.groups.append_option(r.groups.as_deref());
        self.ec_point_formats
            .append_option(r.ec_point_formats.as_deref());
        self.sig_algs.append_option(r.sig_algs.as_deref());
        self.ja3.append_option(r.ja3.as_deref());
        self.ja3_raw.append_option(r.ja3_raw.as_deref());
        self.ja4.append_option(r.ja4.as_deref());
        self.cipher.append_option(r.cipher);
        self.ja3s.append_option(r.ja3s.as_deref());
        self.ja3s_raw.append_option(r.ja3s_raw.as_deref());
        self.cert_subject.append_option(r.cert_subject.as_deref());
        self.cert_issuer.append_option(r.cert_issuer.as_deref());
        self.cert_not_before.append_option(r.cert_not_before);
        self.cert_not_after.append_option(r.cert_not_after);
        self.cert_serial.append_option(r.cert_serial.as_deref());
        self.cert_san.append_option(r.cert_san.as_deref());
        self.cert_chain_len.append_option(r.cert_chain_len);
    }

    pub fn finish(&mut self) -> Result<RecordBatch, arrow_schema::ArrowError> {
        let ts = self.ts.finish().with_timezone("UTC");
        let cnb = self.cert_not_before.finish().with_timezone("UTC");
        let cna = self.cert_not_after.finish().with_timezone("UTC");
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ts),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.msg.finish()),
            Arc::new(self.record_version.finish()),
            Arc::new(self.legacy_version.finish()),
            Arc::new(self.version_max.finish()),
            Arc::new(self.sni.finish()),
            Arc::new(self.alpn.finish()),
            Arc::new(self.cipher_count.finish()),
            Arc::new(self.ciphers.finish()),
            Arc::new(self.extensions.finish()),
            Arc::new(self.groups.finish()),
            Arc::new(self.ec_point_formats.finish()),
            Arc::new(self.sig_algs.finish()),
            Arc::new(self.ja3.finish()),
            Arc::new(self.ja3_raw.finish()),
            Arc::new(self.ja4.finish()),
            Arc::new(self.cipher.finish()),
            Arc::new(self.ja3s.finish()),
            Arc::new(self.ja3s_raw.finish()),
            Arc::new(self.cert_subject.finish()),
            Arc::new(self.cert_issuer.finish()),
            Arc::new(cnb),
            Arc::new(cna),
            Arc::new(self.cert_serial.finish()),
            Arc::new(self.cert_san.finish()),
            Arc::new(self.cert_chain_len.finish()),
        ];
        self.n = 0;
        RecordBatch::try_new(Arc::clone(&self.schema), arrays)
    }
}

impl Default for TlsBuilder {
    fn default() -> Self {
        Self::new()
    }
}
