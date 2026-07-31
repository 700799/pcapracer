//! `http` table: one row per HTTP/1.x request or response.

use super::push_ip;
use crate::util::IpRepr;
use arrow_array::builder::{
    BooleanBuilder, Int64Builder, StringBuilder, TimestampNanosecondBuilder, UInt16Builder,
    UInt32Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct HttpRow {
    pub ts_ns: i64,
    pub src_ip: Option<IpRepr>,
    pub dst_ip: Option<IpRepr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub is_request: bool,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub transfer_encoding: Option<String>,
    pub cookie_present: bool,
    pub auth_present: bool,
    pub x_forwarded_for: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub server: Option<String>,
    pub location: Option<String>,
    pub connection: Option<String>,
    pub header_count: u16,
    pub header_len: u32,
}

pub fn schema() -> Arc<Schema> {
    use DataType::*;
    let ts = Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
    let fields = vec![
        Field::new("ts", ts, false),
        Field::new("src_ip", Utf8, true),
        Field::new("dst_ip", Utf8, true),
        Field::new("src_port", UInt16, false),
        Field::new("dst_port", UInt16, false),
        Field::new("is_request", Boolean, false),
        Field::new("method", Utf8, true),
        Field::new("uri", Utf8, true),
        Field::new("version", Utf8, true),
        Field::new("host", Utf8, true),
        Field::new("user_agent", Utf8, true),
        Field::new("referer", Utf8, true),
        Field::new("content_type", Utf8, true),
        Field::new("content_length", Int64, true),
        Field::new("transfer_encoding", Utf8, true),
        Field::new("cookie_present", Boolean, false),
        Field::new("auth_present", Boolean, false),
        Field::new("x_forwarded_for", Utf8, true),
        Field::new("status", UInt16, true),
        Field::new("reason", Utf8, true),
        Field::new("server", Utf8, true),
        Field::new("location", Utf8, true),
        Field::new("connection", Utf8, true),
        Field::new("header_count", UInt16, false),
        Field::new("header_len", UInt32, false),
    ];
    Arc::new(Schema::new(fields))
}

pub struct HttpBuilder {
    schema: Arc<Schema>,
    scratch: String,
    n: usize,
    ts: TimestampNanosecondBuilder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    is_request: BooleanBuilder,
    method: StringBuilder,
    uri: StringBuilder,
    version: StringBuilder,
    host: StringBuilder,
    user_agent: StringBuilder,
    referer: StringBuilder,
    content_type: StringBuilder,
    content_length: Int64Builder,
    transfer_encoding: StringBuilder,
    cookie_present: BooleanBuilder,
    auth_present: BooleanBuilder,
    x_forwarded_for: StringBuilder,
    status: UInt16Builder,
    reason: StringBuilder,
    server: StringBuilder,
    location: StringBuilder,
    connection: StringBuilder,
    header_count: UInt16Builder,
    header_len: UInt32Builder,
}

impl HttpBuilder {
    pub fn new() -> HttpBuilder {
        HttpBuilder {
            schema: schema(),
            scratch: String::with_capacity(48),
            n: 0,
            ts: Default::default(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: Default::default(),
            dst_port: Default::default(),
            is_request: Default::default(),
            method: StringBuilder::new(),
            uri: StringBuilder::new(),
            version: StringBuilder::new(),
            host: StringBuilder::new(),
            user_agent: StringBuilder::new(),
            referer: StringBuilder::new(),
            content_type: StringBuilder::new(),
            content_length: Default::default(),
            transfer_encoding: StringBuilder::new(),
            cookie_present: Default::default(),
            auth_present: Default::default(),
            x_forwarded_for: StringBuilder::new(),
            status: Default::default(),
            reason: StringBuilder::new(),
            server: StringBuilder::new(),
            location: StringBuilder::new(),
            connection: StringBuilder::new(),
            header_count: Default::default(),
            header_len: Default::default(),
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

    pub fn append(&mut self, r: &HttpRow) {
        self.n += 1;
        self.ts.append_value(r.ts_ns);
        push_ip(&mut self.src_ip, &mut self.scratch, r.src_ip);
        push_ip(&mut self.dst_ip, &mut self.scratch, r.dst_ip);
        self.src_port.append_value(r.src_port);
        self.dst_port.append_value(r.dst_port);
        self.is_request.append_value(r.is_request);
        self.method.append_option(r.method.as_deref());
        self.uri.append_option(r.uri.as_deref());
        self.version.append_option(r.version.as_deref());
        self.host.append_option(r.host.as_deref());
        self.user_agent.append_option(r.user_agent.as_deref());
        self.referer.append_option(r.referer.as_deref());
        self.content_type.append_option(r.content_type.as_deref());
        self.content_length.append_option(r.content_length);
        self.transfer_encoding
            .append_option(r.transfer_encoding.as_deref());
        self.cookie_present.append_value(r.cookie_present);
        self.auth_present.append_value(r.auth_present);
        self.x_forwarded_for
            .append_option(r.x_forwarded_for.as_deref());
        self.status.append_option(r.status);
        self.reason.append_option(r.reason.as_deref());
        self.server.append_option(r.server.as_deref());
        self.location.append_option(r.location.as_deref());
        self.connection.append_option(r.connection.as_deref());
        self.header_count.append_value(r.header_count);
        self.header_len.append_value(r.header_len);
    }

    pub fn finish(&mut self) -> Result<RecordBatch, arrow_schema::ArrowError> {
        let ts = self.ts.finish().with_timezone("UTC");
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ts),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.is_request.finish()),
            Arc::new(self.method.finish()),
            Arc::new(self.uri.finish()),
            Arc::new(self.version.finish()),
            Arc::new(self.host.finish()),
            Arc::new(self.user_agent.finish()),
            Arc::new(self.referer.finish()),
            Arc::new(self.content_type.finish()),
            Arc::new(self.content_length.finish()),
            Arc::new(self.transfer_encoding.finish()),
            Arc::new(self.cookie_present.finish()),
            Arc::new(self.auth_present.finish()),
            Arc::new(self.x_forwarded_for.finish()),
            Arc::new(self.status.finish()),
            Arc::new(self.reason.finish()),
            Arc::new(self.server.finish()),
            Arc::new(self.location.finish()),
            Arc::new(self.connection.finish()),
            Arc::new(self.header_count.finish()),
            Arc::new(self.header_len.finish()),
        ];
        self.n = 0;
        RecordBatch::try_new(Arc::clone(&self.schema), arrays)
    }
}

impl Default for HttpBuilder {
    fn default() -> Self {
        Self::new()
    }
}
