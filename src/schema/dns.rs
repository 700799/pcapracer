//! `dns` table: one row per DNS-family message (DNS/mDNS/LLMNR/NBNS).

use super::push_ip;
use crate::util::IpRepr;
use arrow_array::builder::{
    BooleanBuilder, ListBuilder, StringBuilder, TimestampNanosecondBuilder, UInt16Builder,
    UInt32Builder, UInt8Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

/// One decoded answer/record rendered for output.
#[derive(Clone, Debug)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: String,
}

/// A fully parsed DNS-family message ready for the `dns` table.
#[derive(Debug)]
pub struct DnsRow {
    pub ts_ns: i64,
    pub src_ip: IpRepr,
    pub dst_ip: IpRepr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub service: &'static str,
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub qname: Option<String>,
    pub qtype: Option<u16>,
    pub qtype_name: Option<&'static str>,
    pub qclass: Option<u16>,
    pub answers: Vec<DnsAnswer>,
}

pub fn schema() -> Arc<Schema> {
    use DataType::*;
    let ts = Timestamp(TimeUnit::Nanosecond, Some("UTC".into()));
    let item_str = || Arc::new(Field::new("item", Utf8, true));
    let item_u16 = || Arc::new(Field::new("item", UInt16, true));
    let item_u32 = || Arc::new(Field::new("item", UInt32, true));
    let fields = vec![
        Field::new("ts", ts, false),
        Field::new("src_ip", Utf8, false),
        Field::new("dst_ip", Utf8, false),
        Field::new("src_port", UInt16, false),
        Field::new("dst_port", UInt16, false),
        Field::new("proto", UInt8, false),
        Field::new("service", Utf8, false),
        Field::new("dns_id", UInt16, false),
        Field::new("is_response", Boolean, false),
        Field::new("opcode", UInt8, false),
        Field::new("rcode", UInt8, false),
        Field::new("flag_aa", Boolean, false),
        Field::new("flag_tc", Boolean, false),
        Field::new("flag_rd", Boolean, false),
        Field::new("flag_ra", Boolean, false),
        Field::new("flag_ad", Boolean, false),
        Field::new("flag_cd", Boolean, false),
        Field::new("qdcount", UInt16, false),
        Field::new("ancount", UInt16, false),
        Field::new("nscount", UInt16, false),
        Field::new("arcount", UInt16, false),
        Field::new("qname", Utf8, true),
        Field::new("qtype", UInt16, true),
        Field::new("qtype_name", Utf8, true),
        Field::new("qclass", UInt16, true),
        Field::new("answer_name", List(item_str()), true),
        Field::new("answer_type", List(item_u16()), true),
        Field::new("answer_ttl", List(item_u32()), true),
        Field::new("answer_rdata", List(item_str()), true),
    ];
    Arc::new(Schema::new(fields))
}

pub struct DnsBuilder {
    schema: Arc<Schema>,
    scratch: String,
    n: usize,
    ts: TimestampNanosecondBuilder,
    src_ip: StringBuilder,
    dst_ip: StringBuilder,
    src_port: UInt16Builder,
    dst_port: UInt16Builder,
    proto: UInt8Builder,
    service: StringBuilder,
    dns_id: UInt16Builder,
    is_response: BooleanBuilder,
    opcode: UInt8Builder,
    rcode: UInt8Builder,
    flag_aa: BooleanBuilder,
    flag_tc: BooleanBuilder,
    flag_rd: BooleanBuilder,
    flag_ra: BooleanBuilder,
    flag_ad: BooleanBuilder,
    flag_cd: BooleanBuilder,
    qdcount: UInt16Builder,
    ancount: UInt16Builder,
    nscount: UInt16Builder,
    arcount: UInt16Builder,
    qname: StringBuilder,
    qtype: UInt16Builder,
    qtype_name: StringBuilder,
    qclass: UInt16Builder,
    answer_name: ListBuilder<StringBuilder>,
    answer_type: ListBuilder<UInt16Builder>,
    answer_ttl: ListBuilder<UInt32Builder>,
    answer_rdata: ListBuilder<StringBuilder>,
}

impl DnsBuilder {
    pub fn new() -> DnsBuilder {
        DnsBuilder {
            schema: schema(),
            scratch: String::with_capacity(48),
            n: 0,
            ts: Default::default(),
            src_ip: StringBuilder::new(),
            dst_ip: StringBuilder::new(),
            src_port: Default::default(),
            dst_port: Default::default(),
            proto: Default::default(),
            service: StringBuilder::new(),
            dns_id: Default::default(),
            is_response: Default::default(),
            opcode: Default::default(),
            rcode: Default::default(),
            flag_aa: Default::default(),
            flag_tc: Default::default(),
            flag_rd: Default::default(),
            flag_ra: Default::default(),
            flag_ad: Default::default(),
            flag_cd: Default::default(),
            qdcount: Default::default(),
            ancount: Default::default(),
            nscount: Default::default(),
            arcount: Default::default(),
            qname: StringBuilder::new(),
            qtype: Default::default(),
            qtype_name: StringBuilder::new(),
            qclass: Default::default(),
            answer_name: ListBuilder::new(StringBuilder::new()),
            answer_type: ListBuilder::new(UInt16Builder::new()),
            answer_ttl: ListBuilder::new(UInt32Builder::new()),
            answer_rdata: ListBuilder::new(StringBuilder::new()),
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

    pub fn append(&mut self, r: &DnsRow) {
        self.n += 1;
        self.ts.append_value(r.ts_ns);
        push_ip(&mut self.src_ip, &mut self.scratch, Some(r.src_ip));
        push_ip(&mut self.dst_ip, &mut self.scratch, Some(r.dst_ip));
        self.src_port.append_value(r.src_port);
        self.dst_port.append_value(r.dst_port);
        self.proto.append_value(r.proto);
        self.service.append_value(r.service);
        self.dns_id.append_value(r.id);
        self.is_response.append_value(r.is_response);
        self.opcode.append_value(r.opcode);
        self.rcode.append_value(r.rcode);
        self.flag_aa.append_value(r.aa);
        self.flag_tc.append_value(r.tc);
        self.flag_rd.append_value(r.rd);
        self.flag_ra.append_value(r.ra);
        self.flag_ad.append_value(r.ad);
        self.flag_cd.append_value(r.cd);
        self.qdcount.append_value(r.qdcount);
        self.ancount.append_value(r.ancount);
        self.nscount.append_value(r.nscount);
        self.arcount.append_value(r.arcount);
        self.qname.append_option(r.qname.as_deref());
        self.qtype.append_option(r.qtype);
        self.qtype_name.append_option(r.qtype_name);
        self.qclass.append_option(r.qclass);

        for a in &r.answers {
            self.answer_name.values().append_value(&a.name);
            self.answer_type.values().append_value(a.rtype);
            self.answer_ttl.values().append_value(a.ttl);
            self.answer_rdata.values().append_value(&a.rdata);
        }
        self.answer_name.append(true);
        self.answer_type.append(true);
        self.answer_ttl.append(true);
        self.answer_rdata.append(true);
    }

    pub fn finish(&mut self) -> Result<RecordBatch, arrow_schema::ArrowError> {
        let ts = self.ts.finish().with_timezone("UTC");
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(ts),
            Arc::new(self.src_ip.finish()),
            Arc::new(self.dst_ip.finish()),
            Arc::new(self.src_port.finish()),
            Arc::new(self.dst_port.finish()),
            Arc::new(self.proto.finish()),
            Arc::new(self.service.finish()),
            Arc::new(self.dns_id.finish()),
            Arc::new(self.is_response.finish()),
            Arc::new(self.opcode.finish()),
            Arc::new(self.rcode.finish()),
            Arc::new(self.flag_aa.finish()),
            Arc::new(self.flag_tc.finish()),
            Arc::new(self.flag_rd.finish()),
            Arc::new(self.flag_ra.finish()),
            Arc::new(self.flag_ad.finish()),
            Arc::new(self.flag_cd.finish()),
            Arc::new(self.qdcount.finish()),
            Arc::new(self.ancount.finish()),
            Arc::new(self.nscount.finish()),
            Arc::new(self.arcount.finish()),
            Arc::new(self.qname.finish()),
            Arc::new(self.qtype.finish()),
            Arc::new(self.qtype_name.finish()),
            Arc::new(self.qclass.finish()),
            Arc::new(self.answer_name.finish()),
            Arc::new(self.answer_type.finish()),
            Arc::new(self.answer_ttl.finish()),
            Arc::new(self.answer_rdata.finish()),
        ];
        self.n = 0;
        RecordBatch::try_new(Arc::clone(&self.schema), arrays)
    }
}

impl Default for DnsBuilder {
    fn default() -> Self {
        Self::new()
    }
}
