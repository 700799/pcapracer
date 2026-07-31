//! Protocol dissection.
//!
//! `dissect_frame` walks a frame from the link layer down, filling in a [`Packet`]. Each
//! layer decides the next one and appends its name to the protocol stack. Every dissector
//! returns `DResult` and reads through [`Cur`], so malformed input unwinds cleanly with the
//! layers parsed so far already recorded.

#![forbid(unsafe_code)]

pub mod app;
pub mod l2;
pub mod l3;
pub mod l4;
pub mod tunnel;

use std::net::IpAddr;

use crate::bytes::Cur;
use crate::error::DResult;
use crate::schema::Packet;

/// Tunnel nesting cap. Real traffic rarely exceeds three (e.g. eth:ip:gre:ip:udp:vxlan:eth);
/// the limit exists so a crafted capture with a self-referential tunnel cannot recurse until
/// the stack overflows.
pub const MAX_DEPTH: u8 = 8;

/// The transport-layer identity of a packet, used to key the flow table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl Tuple {
    /// Order-independent form, so both directions of a conversation hash to one flow.
    /// Returns the canonical tuple and whether the packet ran in the canonical direction.
    pub fn normalized(&self) -> (Tuple, bool) {
        let forward = (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port);
        if forward {
            (*self, true)
        } else {
            (
                Tuple {
                    src_ip: self.dst_ip,
                    dst_ip: self.src_ip,
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    proto: self.proto,
                },
                false,
            )
        }
    }
}

/// Mutable state threaded through a single frame's dissection.
pub struct Ctx<'a> {
    pub pkt: &'a mut Packet,
    /// Layer names in traversal order, joined into `proto_stack` at the end.
    pub stack: Vec<&'static str>,
    pub depth: u8,
    /// Set once the L3/L4 headers are known; consumed by the flow table.
    pub tuple: Option<Tuple>,
    /// True when the payload handed to the L7 dissectors came from TCP reassembly rather
    /// than from this frame alone.
    pub reassembled: bool,
    /// Set when a dissector wants to suppress port-based L7 dispatch (already handled).
    pub app_done: bool,
    /// When set, TCP payloads are left for the reassembly pass rather than dissected from
    /// this segment alone. UDP is unaffected — it has no reassembly to wait for.
    pub defer_tcp_app: bool,
}

impl<'a> Ctx<'a> {
    pub fn new(pkt: &'a mut Packet) -> Self {
        Ctx {
            pkt,
            stack: Vec::with_capacity(6),
            depth: 0,
            tuple: None,
            reassembled: false,
            app_done: false,
            defer_tcp_app: false,
        }
    }

    #[inline]
    pub fn layer(&mut self, name: &'static str) {
        self.stack.push(name);
    }

    /// Enter a nested encapsulation, refusing past [`MAX_DEPTH`].
    #[inline]
    pub fn descend(&mut self) -> DResult<()> {
        if self.depth >= MAX_DEPTH {
            return Err(crate::error::DissectError::DepthExceeded);
        }
        self.depth += 1;
        Ok(())
    }

    /// Finalise the derived stack columns.
    pub fn finish(&mut self) {
        if let Some(last) = self.stack.last() {
            self.pkt.highest_layer = Some((*last).to_string());
        }
        self.pkt.proto_stack = Some(self.stack.join(":"));
        self.pkt.tunnel_depth = Some(self.depth);
    }
}

/// Dissect one frame given its link type (the pcap LINKTYPE_* value).
///
/// Errors are informational: the caller records them in `malformed`/`truncated` and still
/// emits the row, because a partially parsed packet is usually the interesting one.
pub fn dissect_frame(data: &[u8], linktype: u16, ctx: &mut Ctx) -> DResult<()> {
    ctx.pkt.link_type = Some(linktype);
    let mut c = Cur::new(data);
    l2::dissect_link(&mut c, linktype, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn tuple_normalizes_both_directions_to_one_key() {
        let a = Tuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1234,
            dst_port: 80,
            proto: 6,
        };
        let b = Tuple {
            src_ip: a.dst_ip,
            dst_ip: a.src_ip,
            src_port: a.dst_port,
            dst_port: a.src_port,
            proto: 6,
        };
        let (ka, fwd_a) = a.normalized();
        let (kb, fwd_b) = b.normalized();
        assert_eq!(ka, kb);
        assert!(fwd_a != fwd_b);
    }

    #[test]
    fn depth_is_capped() {
        let mut p = Packet::default();
        let mut ctx = Ctx::new(&mut p);
        for _ in 0..MAX_DEPTH {
            ctx.descend().unwrap();
        }
        assert!(ctx.descend().is_err());
    }
}
