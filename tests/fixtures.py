"""Pure-stdlib builders for pcap / pcapng capture fixtures (no scapy).

Every builder returns raw ``bytes`` so tests can assemble frames and files
deterministically and assert on the extracted Parquet.
"""

from __future__ import annotations

import gzip
import struct
from typing import Iterable

# ---------------------------------------------------------------------------
# File containers
# ---------------------------------------------------------------------------

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_NULL = 0
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def pcap_file(
    packets: Iterable[bytes],
    *,
    linktype: int = LINKTYPE_ETHERNET,
    nanos: bool = False,
    big_endian: bool = False,
    base_ts: float = 1_700_000_000.0,
    interval: float = 0.001,
) -> bytes:
    """Build a classic pcap file from a list of raw link-layer frames."""
    endian = ">" if big_endian else "<"
    if nanos:
        magic = 0xA1B23C4D
    else:
        magic = 0xA1B2C3D4
    out = bytearray()
    out += struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    ts = base_ts
    for pkt in packets:
        sec = int(ts)
        frac = ts - sec
        subsec = int(round(frac * (1_000_000_000 if nanos else 1_000_000)))
        out += struct.pack(endian + "IIII", sec, subsec, len(pkt), len(pkt))
        out += pkt
        ts += interval
    return bytes(out)


def pcap_file_ts(
    packets_with_ts: Iterable[tuple[bytes, float]],
    *,
    linktype: int = LINKTYPE_ETHERNET,
    nanos: bool = False,
) -> bytes:
    """Build a pcap file with explicit per-packet timestamps (seconds float)."""
    endian = "<"
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    out = bytearray()
    out += struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    for pkt, ts in packets_with_ts:
        sec = int(ts)
        subsec = int(round((ts - sec) * (1_000_000_000 if nanos else 1_000_000)))
        out += struct.pack(endian + "IIII", sec, subsec, len(pkt), len(pkt))
        out += pkt
    return bytes(out)


def _opt(code: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def _ng_block(btype: int, body: bytes) -> bytes:
    pad = (-len(body)) % 4
    body = body + b"\x00" * pad
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def pcapng_file(
    packets: Iterable[bytes],
    *,
    linktype: int = LINKTYPE_ETHERNET,
    tsresol: int = 6,
    base_ts: float = 1_700_000_000.0,
    interval: float = 0.001,
) -> bytes:
    """Build a minimal single-section pcapng: SHB + IDB + EPBs."""
    out = bytearray()
    out += _ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb_body = struct.pack("<HHI", linktype, 0, 262144) + _opt(9, bytes([tsresol]))
    out += _ng_block(0x00000001, idb_body)

    ticks_per_sec = 10 ** tsresol
    ts = base_ts
    for pkt in packets:
        ticks = int(round(ts * ticks_per_sec))
        high = (ticks >> 32) & 0xFFFFFFFF
        low = ticks & 0xFFFFFFFF
        body = struct.pack("<IIIII", 0, high, low, len(pkt), len(pkt)) + pkt
        out += _ng_block(0x00000006, body)
        ts += interval

    return bytes(out)


def gz(data: bytes) -> bytes:
    return gzip.compress(data)


# ---------------------------------------------------------------------------
# Frame builders (Ethernet / IP / transport)
# ---------------------------------------------------------------------------

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def eth(payload: bytes, *, dst=MAC_A, src=MAC_B, ethertype: int = 0x0800) -> bytes:
    return dst + src + struct.pack(">H", ethertype) + payload


def vlan(inner: bytes, vid: int, *, pcp: int = 0, ethertype: int = 0x0800) -> bytes:
    """VLAN payload (TCI + inner ethertype). Wrap with ``eth(..., ethertype=0x8100)``."""
    tci = (pcp << 13) | (vid & 0x0FFF)
    return struct.pack(">H", tci) + struct.pack(">H", ethertype) + inner


def _ipv4_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(
    payload: bytes,
    *,
    src="10.0.0.1",
    dst="10.0.0.2",
    proto: int = 6,
    ttl: int = 64,
    ident: int = 0,
    df: bool = False,
    mf: bool = False,
    frag_offset: int = 0,
    dscp: int = 0,
    ecn: int = 0,
) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total = 20 + len(payload)
    flags_frag = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_offset & 0x1FFF)
    tos = (dscp << 2) | (ecn & 0x3)
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        tos,
        total,
        ident,
        flags_frag,
        ttl,
        proto,
        0,
        src_b,
        dst_b,
    )
    csum = _ipv4_checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", csum) + hdr[12:]
    return hdr + payload


def ipv6(payload: bytes, *, src="2001:db8::1", dst="2001:db8::2", nh: int = 6, hlim: int = 64) -> bytes:
    import ipaddress

    src_b = ipaddress.IPv6Address(src).packed
    dst_b = ipaddress.IPv6Address(dst).packed
    vtf = 0x60000000
    return struct.pack(">IHBB", vtf, len(payload), nh, hlim) + src_b + dst_b + payload


def tcp(
    payload: bytes = b"",
    *,
    sport: int = 12345,
    dport: int = 80,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x02,
    window: int = 64240,
    options: bytes = b"",
) -> bytes:
    if len(options) % 4 != 0:
        options = options + b"\x00" * (4 - len(options) % 4)
    data_off = (20 + len(options)) // 4
    off_flags = (data_off << 12) | (flags & 0x1FF)
    hdr = struct.pack(">HHIIHHHH", sport, dport, seq, ack, off_flags, window, 0, 0)
    return hdr + options + payload


def tcp_opts_syn() -> bytes:
    # MSS 1460, SACK permitted, Timestamps, NOP, WScale 7
    return (
        struct.pack(">BBH", 2, 4, 1460)
        + struct.pack(">BB", 4, 2)
        + struct.pack(">BBII", 8, 10, 111, 0)
        + b"\x01"
        + struct.pack(">BBB", 3, 3, 7)
    )


def udp(payload: bytes = b"", *, sport: int = 12345, dport: int = 53) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(*, req: bool = True, ident: int = 1, seq: int = 1, data: bytes = b"abcd") -> bytes:
    typ = 8 if req else 0
    return struct.pack(">BBHHH", typ, 0, 0, ident, seq) + data


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(name: str = "example.com", *, qtype: int = 1, txid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD set
    return header + dns_name(name) + struct.pack(">HH", qtype, 1)


def dns_response_a(name: str = "example.com", ip: str = "93.184.216.34", *, txid: int = 0x1234, ttl: int = 300) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    q = dns_name(name) + struct.pack(">HH", 1, 1)
    # answer uses a compression pointer back to the question name at offset 12
    ans = struct.pack(">H", 0xC00C) + struct.pack(">HHIH", 1, 1, ttl, 4)
    ans += bytes(int(x) for x in ip.split("."))
    return header + q + ans


def gre(inner: bytes, *, proto: int = 0x0800) -> bytes:
    return struct.pack(">HH", 0, proto) + inner


def vxlan(inner_eth: bytes, *, vni: int = 100) -> bytes:
    return struct.pack(">I", 0x08000000) + struct.pack(">I", (vni << 8)) + inner_eth
