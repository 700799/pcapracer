"""Integration tests: build fixtures, run extract, assert on the Parquet."""

from __future__ import annotations

import pyarrow.parquet as pq

import pcapracer
import fixtures as fx


def _read(path):
    return pq.read_table(path).to_pydict()


def test_packets_basic_eth_ipv4_tcp_udp(tmp_path):
    frames = [
        fx.eth(fx.ipv4(fx.tcp(b"GET / HTTP/1.0\r\n", sport=44000, dport=80, flags=0x18))),
        fx.eth(fx.ipv4(fx.udp(b"\x00" * 20, sport=5353, dport=53), proto=17)),
    ]
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(fx.pcap_file(frames))

    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    assert summary["packets"] == 2
    assert summary["rows"]["packets"] == 2

    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["src_ip"] == ["10.0.0.1", "10.0.0.1"]
    assert t["dst_ip"] == ["10.0.0.2", "10.0.0.2"]
    assert t["ip_proto"] == [6, 17]
    assert t["src_port"] == [44000, 5353]
    assert t["dst_port"] == [80, 53]
    assert t["tcp_flag_syn"][0] is False
    assert t["tcp_flag_psh"][0] is True
    assert t["tcp_flag_ack"][0] is True
    assert t["eth_src"][0] == "02:00:00:00:00:02"


def test_tcp_options(tmp_path):
    frame = fx.eth(fx.ipv4(fx.tcp(options=fx.tcp_opts_syn(), flags=0x02)))
    pcap = tmp_path / "syn.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["tcp_mss"] == [1460]
    assert t["tcp_sack_permitted"] == [True]
    assert t["tcp_wscale"] == [7]
    assert t["tcp_ts_val"] == [111]


def test_vlan_and_ipv6(tmp_path):
    frames = [
        fx.eth(fx.vlan(fx.ipv4(fx.tcp()), vid=100, ethertype=0x0800), ethertype=0x8100),
        fx.eth(fx.ipv6(fx.tcp(dport=443)), ethertype=0x86DD),
    ]
    pcap = tmp_path / "vlan6.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["vlan1_id"][0] == 100
    assert t["ip_version"] == [4, 6]
    assert t["src_ip"][1] == "2001:db8::1"
    assert t["dst_port"][1] == 443


def test_arp(tmp_path):
    import struct

    arp = (
        struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
        + fx.MAC_B
        + bytes([192, 168, 0, 1])
        + fx.MAC_A
        + bytes([192, 168, 0, 2])
    )
    frame = fx.eth(arp, ethertype=0x0806)
    pcap = tmp_path / "arp.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["arp_op"] == [1]
    assert t["arp_sender_ip"] == ["192.168.0.1"]
    assert t["arp_target_ip"] == ["192.168.0.2"]


def test_icmp_echo(tmp_path):
    frame = fx.eth(fx.ipv4(fx.icmp_echo(ident=7, seq=3), proto=1))
    pcap = tmp_path / "icmp.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["icmp_type"] == [8]
    assert t["icmp_echo_id"] == [7]
    assert t["icmp_echo_seq"] == [3]


def test_pcapng_input(tmp_path):
    frames = [fx.eth(fx.ipv4(fx.tcp())) for _ in range(5)]
    ng = tmp_path / "cap.pcapng"
    ng.write_bytes(fx.pcapng_file(frames))
    summary = pcapracer.extract(str(ng), tmp_path, tables=["packets"])
    assert summary["packets"] == 5
    assert summary["rows"]["packets"] == 5


def test_gzip_input(tmp_path):
    frames = [fx.eth(fx.ipv4(fx.tcp())) for _ in range(3)]
    gzp = tmp_path / "cap.pcap.gz"
    gzp.write_bytes(fx.gz(fx.pcap_file(frames)))
    summary = pcapracer.extract(str(gzp), tmp_path, tables=["packets"])
    assert summary["packets"] == 3


def test_nanosecond_and_bigendian_pcap(tmp_path):
    frames = [fx.eth(fx.ipv4(fx.tcp()))]
    for name, kw in [("ns", {"nanos": True}), ("be", {"big_endian": True})]:
        p = tmp_path / f"{name}.pcap"
        p.write_bytes(fx.pcap_file(frames, **kw))
        summary = pcapracer.extract(str(p), tmp_path, tables=["packets"])
        assert summary["packets"] == 1


def test_gre_tunnel(tmp_path):
    inner = fx.ipv4(fx.udp(dport=53), src="192.168.1.1", dst="192.168.1.2", proto=17)
    outer = fx.ipv4(fx.gre(inner), src="1.1.1.1", dst="2.2.2.2", proto=47)
    frame = fx.eth(outer)
    pcap = tmp_path / "gre.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["src_ip"] == ["192.168.1.1"]
    assert t["outer_src_ip"] == ["1.1.1.1"]
    assert t["tunnel_depth"] == [1]
    assert t["dst_port"] == [53]


def test_vxlan_tunnel(tmp_path):
    inner_eth = fx.eth(fx.ipv4(fx.tcp(dport=8080), src="172.16.0.1", dst="172.16.0.2"))
    outer = fx.ipv4(
        fx.udp(fx.vxlan(inner_eth, vni=100), dport=4789),
        src="1.1.1.1",
        dst="2.2.2.2",
        proto=17,
    )
    frame = fx.eth(outer)
    pcap = tmp_path / "vxlan.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    t = _read(summary["files"][0]["paths"]["packets"])
    assert t["vxlan_vni"] == [100]
    assert t["src_ip"] == ["172.16.0.1"]
    assert t["dst_port"] == [8080]
    assert t["tunnel_depth"] == [1]
