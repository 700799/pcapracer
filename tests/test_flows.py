"""Flow-engine tests with crafted timestamps and flags."""

from __future__ import annotations

import pyarrow.parquet as pq

import pcapracer
import fixtures as fx

# TCP flag combinations
SYN = 0x02
SYN_ACK = 0x12
ACK = 0x10
PSH_ACK = 0x18
FIN_ACK = 0x11
RST = 0x04


def _read(path):
    return pq.read_table(path).to_pylist()


def _c2s(payload=b"", flags=ACK, seq=1, ack=1):
    return fx.eth(
        fx.ipv4(fx.tcp(payload, sport=40000, dport=80, seq=seq, ack=ack, flags=flags),
                src="10.0.0.1", dst="10.0.0.2")
    )


def _s2c(payload=b"", flags=ACK, seq=1, ack=1):
    return fx.eth(
        fx.ipv4(fx.tcp(payload, sport=80, dport=40000, seq=seq, ack=ack, flags=flags),
                src="10.0.0.2", dst="10.0.0.1")
    )


def test_tcp_flow_features(tmp_path):
    packets = [
        (_c2s(flags=SYN), 0.00),
        (_s2c(flags=SYN_ACK), 0.05),
        (_c2s(flags=ACK), 0.10),
        (_c2s(b"x" * 100, flags=PSH_ACK), 0.20),
        (_s2c(b"y" * 200, flags=PSH_ACK), 0.30),
        (_c2s(flags=FIN_ACK), 0.40),
        (_s2c(flags=FIN_ACK), 0.50),
    ]
    pcap = tmp_path / "flow.pcap"
    pcap.write_bytes(fx.pcap_file_ts(packets))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    rows = _read(summary["files"][0]["paths"]["flows"])
    assert len(rows) == 1
    r = rows[0]
    assert r["src_ip"] == "10.0.0.1"
    assert r["dst_ip"] == "10.0.0.2"
    assert r["src_port"] == 40000
    assert r["dst_port"] == 80
    assert r["proto_name"] == "tcp"
    assert r["fwd_pkts"] == 4
    assert r["bwd_pkts"] == 3
    assert r["syn_count"] == 2
    assert r["fin_count"] == 2
    assert r["tcp_handshake_complete"] is True
    assert r["end_reason"] == "fin"
    # forward wire bytes: SYN(54) + ACK(54) + data(154) + FIN(54) = 316
    assert r["fwd_bytes"] == 316
    assert r["bwd_bytes"] == 54 + 254 + 54
    assert abs(r["duration_s"] - 0.5) < 1e-6
    # 6 inter-arrival gaps summing to 0.5s
    assert abs(r["flow_iat_mean"] - (0.5 / 6)) < 1e-6
    assert r["fwd_payload_bytes"] == 100
    assert r["bwd_payload_bytes"] == 200
    assert r["syn_synack_rtt_s"] is not None
    assert abs(r["syn_synack_rtt_s"] - 0.05) < 1e-6


def test_two_flows(tmp_path):
    a = [
        (_c2s(flags=SYN), 0.00),
        (_s2c(flags=SYN_ACK), 0.01),
        (_c2s(flags=RST | ACK), 0.02),
    ]
    b = [
        (fx.eth(fx.ipv4(fx.udp(b"q", sport=5555, dport=53), src="10.0.0.3", dst="10.0.0.4", proto=17)), 0.10),
        (fx.eth(fx.ipv4(fx.udp(b"r", sport=53, dport=5555), src="10.0.0.4", dst="10.0.0.3", proto=17)), 0.11),
    ]
    pcap = tmp_path / "two.pcap"
    pcap.write_bytes(fx.pcap_file_ts(a + b))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    rows = _read(summary["files"][0]["paths"]["flows"])
    assert len(rows) == 2
    protos = sorted(r["proto_name"] for r in rows)
    assert protos == ["tcp", "udp"]
    tcp_row = next(r for r in rows if r["proto_name"] == "tcp")
    assert tcp_row["rst_count"] == 1
    assert tcp_row["end_reason"] == "rst"


def test_idle_split(tmp_path):
    # Same UDP 5-tuple, two bursts 200s apart, idle_timeout=120 -> two flows.
    def u(sp, dp, src, dst, data):
        return fx.eth(fx.ipv4(fx.udp(data, sport=sp, dport=dp), src=src, dst=dst, proto=17))

    packets = [
        (u(5000, 53, "10.0.0.1", "10.0.0.2", b"a"), 0.0),
        (u(53, 5000, "10.0.0.2", "10.0.0.1", b"b"), 0.001),
        (u(5000, 53, "10.0.0.1", "10.0.0.2", b"c"), 200.0),
        (u(53, 5000, "10.0.0.2", "10.0.0.1", b"d"), 200.001),
    ]
    pcap = tmp_path / "idle.pcap"
    pcap.write_bytes(fx.pcap_file_ts(packets))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"], idle_timeout=120.0)
    rows = _read(summary["files"][0]["paths"]["flows"])
    assert len(rows) == 2
    assert all(r["fwd_pkts"] + r["bwd_pkts"] == 2 for r in rows)
    assert rows[0]["end_reason"] == "idle"
