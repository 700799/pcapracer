"""DNS table and inline-column tests."""

from __future__ import annotations

import pyarrow.parquet as pq

import pcapracer
import fixtures as fx


def _read(path):
    return pq.read_table(path).to_pylist()


def _dns_udp(payload, *, sport=40000, dport=53, src="10.0.0.1", dst="10.0.0.2"):
    return fx.eth(fx.ipv4(fx.udp(payload, sport=sport, dport=dport), src=src, dst=dst, proto=17))


def test_dns_query_and_response(tmp_path):
    frames = [
        _dns_udp(fx.dns_query("example.com", qtype=1)),
        _dns_udp(fx.dns_response_a("example.com", "93.184.216.34"), sport=53, dport=40000,
                 src="10.0.0.2", dst="10.0.0.1"),
    ]
    pcap = tmp_path / "dns.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["dns", "packets"])
    assert summary["rows"]["dns"] == 2

    dns_rows = _read(summary["files"][0]["paths"]["dns"])
    query = next(r for r in dns_rows if not r["is_response"])
    resp = next(r for r in dns_rows if r["is_response"])
    assert query["qname"] == "example.com"
    assert query["qtype"] == 1
    assert query["qtype_name"] == "A"
    assert query["service"] == "dns"
    assert resp["answer_name"] == ["example.com"]
    assert resp["answer_rdata"] == ["93.184.216.34"]
    assert resp["answer_ttl"] == [300]

    pkt_rows = _read(summary["files"][0]["paths"]["packets"])
    assert pkt_rows[0]["app_proto"] == "dns"
    assert pkt_rows[0]["dns_qname"] == "example.com"
    assert pkt_rows[0]["dns_is_response"] is False


def test_mdns_service_name(tmp_path):
    frame = _dns_udp(fx.dns_query("_services._dns-sd._udp.local", qtype=12),
                     sport=5353, dport=5353, src="10.0.0.5", dst="224.0.0.251")
    pcap = tmp_path / "mdns.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["dns"])
    rows = _read(summary["files"][0]["paths"]["dns"])
    assert rows[0]["service"] == "mdns"
    assert rows[0]["qtype_name"] == "PTR"


def test_dns_enriches_flow(tmp_path):
    frames = [_dns_udp(fx.dns_query("threat.example.net", qtype=1))]
    pcap = tmp_path / "dnsflow.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    rows = _read(summary["files"][0]["paths"]["flows"])
    assert rows[0]["app_protos"] == "dns"
    assert rows[0]["dns_qnames"] == "threat.example.net"
    assert rows[0]["dns_qname_count"] == 1


def test_empty_dns_table_is_valid(tmp_path):
    # A capture with no DNS still produces a readable (empty) dns.parquet.
    frame = fx.eth(fx.ipv4(fx.tcp()))
    pcap = tmp_path / "nodns.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["dns"])
    assert summary["rows"]["dns"] == 0
    t = pq.read_table(summary["files"][0]["paths"]["dns"])
    assert t.num_rows == 0
    assert "qname" in t.schema.names
