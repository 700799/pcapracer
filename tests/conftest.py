"""Shared capture fixtures.

Captures are generated with scapy at test time rather than committed as binaries: a
checked-in pcap is opaque in review, and generating it makes the expected values obvious
from the code right next to the assertions.
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy.all", reason="scapy is required to build test captures")

from scapy.all import (  # noqa: E402
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    Ether,
    Raw,
    fragment,
    wrpcap,
)

CLIENT = "10.0.0.5"
SERVER = "93.184.216.34"
CLIENT_MAC = "00:11:22:33:44:55"
SERVER_MAC = "66:77:88:99:aa:bb"


def _eth(src=CLIENT_MAC, dst=SERVER_MAC):
    return Ether(src=src, dst=dst)


def _http_request():
    body = (
        b"GET /admin/index.html?debug=1 HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"User-Agent: curl/8.4.0\r\n"
        b"Accept: */*\r\n\r\n"
    )
    return (
        _eth()
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=1)
        / Raw(load=body)
    )


def _http_response():
    body = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\n\r\nhi"
    return (
        _eth(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER, dst=CLIENT)
        / TCP(sport=80, dport=50000, flags="PA", seq=5001, ack=1001 + len(body))
        / Raw(load=body)
    )


def _handshake():
    syn = _eth() / IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=80, flags="S", seq=1000)
    synack = (
        _eth(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER, dst=CLIENT)
        / TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001)
    )
    ack = _eth() / IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=80, flags="A", seq=1001, ack=5001)
    return [syn, synack, ack]


def _dns_query():
    return (
        _eth()
        / IP(src=CLIENT, dst="8.8.8.8")
        / UDP(sport=40000, dport=53)
        / DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))
    )


def _dns_response():
    return (
        _eth(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="8.8.8.8", dst=CLIENT)
        / UDP(sport=53, dport=40000)
        / DNS(
            id=0x1234,
            qr=1,
            ra=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            an=DNSRR(rrname="www.example.com", type="A", ttl=300, rdata=SERVER),
        )
    )


def _icmp_echo():
    return _eth() / IP(src=CLIENT, dst=SERVER) / ICMP(type=8, id=0x1234, seq=1) / Raw(load=b"ping")


def _arp_request():
    return Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc=CLIENT, pdst="10.0.0.1", hwsrc=CLIENT_MAC
    )


def _ipv6_ping():
    return (
        _eth()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / scapy.ICMPv6EchoRequest(id=0x1111, seq=2)
    )


def _tls_client_hello():
    """A hand-built ClientHello — scapy's TLS layer is an optional extra we do not require."""
    host = b"secure.example.com"
    sni_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    ext_sni = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    ext_groups = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"
    ext_alpn = b"\x00\x10\x00\x05\x00\x03\x02h2"
    ext_versions = b"\x00\x2b\x00\x03\x02\x03\x04"
    exts = ext_sni + ext_groups + ext_alpn + ext_versions

    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x06\x0a\x0a\x13\x01\x13\x02"  # GREASE + two ciphers
        + b"\x01\x00"
        + len(exts).to_bytes(2, "big")
        + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    return (
        _eth()
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=50001, dport=443, flags="PA", seq=1, ack=1)
        / Raw(load=record)
    )


@pytest.fixture(scope="session")
def mixed_capture(tmp_path_factory) -> str:
    """A capture exercising ARP, ICMP, IPv6, TCP+HTTP, TLS and DNS."""
    path = tmp_path_factory.mktemp("captures") / "mixed.pcap"
    packets = [
        _arp_request(),
        *_handshake(),
        _http_request(),
        _http_response(),
        _dns_query(),
        _dns_response(),
        _icmp_echo(),
        _ipv6_ping(),
        _tls_client_hello(),
    ]
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture(scope="session")
def segmented_capture(tmp_path_factory) -> str:
    """An HTTP request whose Host header straddles two TCP segments."""
    path = tmp_path_factory.mktemp("captures") / "segmented.pcap"
    part1 = b"GET /split HTTP/1.1\r\nHo"
    part2 = b"st: reassembled.example\r\nUser-Agent: probe/1.0\r\n\r\n"
    packets = [
        _eth()
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=50002, dport=80, flags="A", seq=2000, ack=1)
        / Raw(load=part1),
        _eth()
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=50002, dport=80, flags="PA", seq=2000 + len(part1), ack=1)
        / Raw(load=part2),
    ]
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture(scope="session")
def large_capture(tmp_path_factory) -> str:
    """Enough packets to cross the parallel-dissection threshold and several batches."""
    path = tmp_path_factory.mktemp("captures") / "large.pcap"
    packets = []
    for i in range(2000):
        packets.append(
            _eth()
            / IP(src=f"10.0.{i // 256 % 256}.{i % 256}", dst=SERVER)
            / UDP(sport=40000 + (i % 1000), dport=53)
            / DNS(id=i % 65535, rd=1, qd=DNSQR(qname=f"host{i}.example.com", qtype="A"))
        )
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture(scope="session")
def fragmented_dns_capture(tmp_path_factory) -> str:
    """A DNS response split across several IP fragments — the answer only appears once the
    datagram is reassembled."""
    path = tmp_path_factory.mktemp("captures") / "frag-dns.pcap"
    datagram = (
        IP(src="8.8.8.8", dst=CLIENT, id=44)
        / UDP(sport=53, dport=40000)
        / DNS(
            id=0x1234,
            qr=1,
            ra=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            an=DNSRR(rrname="www.example.com", type="A", ttl=300, rdata=SERVER),
        )
    )
    frags = fragment(datagram, fragsize=8)
    packets = [_eth(src=SERVER_MAC, dst=CLIENT_MAC) / f for f in frags]
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture(scope="session")
def fragmented_http_capture(tmp_path_factory) -> str:
    """An HTTP response whose headers span several IP fragments."""
    path = tmp_path_factory.mktemp("captures") / "frag-http.pcap"
    body = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nHost: frag.example\r\n\r\n"
    datagram = (
        IP(src=SERVER, dst=CLIENT, id=55)
        / TCP(sport=80, dport=50000, flags="PA", seq=5001, ack=1)
        / Raw(load=body)
    )
    frags = fragment(datagram, fragsize=16)
    packets = [_eth(src=SERVER_MAC, dst=CLIENT_MAC) / f for f in frags]
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture(scope="session")
def fragmented_with_hole_capture(tmp_path_factory) -> str:
    """A fragmented datagram missing a middle fragment: it must be dropped and counted, never
    half-parsed into wrong field values."""
    path = tmp_path_factory.mktemp("captures") / "frag-hole.pcap"
    datagram = (
        IP(src="8.8.8.8", dst=CLIENT, id=77)
        / UDP(sport=53, dport=40000)
        / DNS(
            id=0x1234,
            qr=1,
            ra=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            an=DNSRR(rrname="www.example.com", type="A", ttl=300, rdata=SERVER),
        )
    )
    frags = fragment(datagram, fragsize=8)
    # Drop a middle fragment so the datagram can never complete.
    del frags[len(frags) // 2]
    packets = [_eth(src=SERVER_MAC, dst=CLIENT_MAC) / f for f in frags]
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture(scope="session")
def empty_capture(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("captures") / "empty.pcap"
    wrpcap(str(path), [])
    return str(path)
