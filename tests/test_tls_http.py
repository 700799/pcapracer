"""TLS (JA3/JA4) and HTTP tests, including split-ClientHello reassembly."""

from __future__ import annotations

import pyarrow.parquet as pq

import pcapracer
import fixtures as fx
import tls_fixture as tf

SYN = 0x02
ACK = 0x10
PSH_ACK = 0x18


def _read(path):
    return pq.read_table(path).to_pylist()


def _c2s(payload, seq, *, sport=44000, dport=443, flags=PSH_ACK):
    return fx.eth(fx.ipv4(fx.tcp(payload, sport=sport, dport=dport, seq=seq, flags=flags),
                          src="10.0.0.1", dst="10.0.0.2"))


def _s2c(payload, seq, *, sport=443, dport=44000, flags=PSH_ACK):
    return fx.eth(fx.ipv4(fx.tcp(payload, sport=sport, dport=dport, seq=seq, flags=flags),
                          src="10.0.0.2", dst="10.0.0.1"))


def test_tls_client_hello_ja3_ja4(tmp_path):
    record, ciphers, ext_types, groups, pf, sigs, versions, sni, alpn = tf.build_client_hello()
    frame = _c2s(record, seq=1)
    pcap = tmp_path / "tls.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["tls"])
    rows = _read(summary["files"][0]["paths"]["tls"])
    assert len(rows) == 1
    r = rows[0]
    assert r["msg"] == "client_hello"
    assert r["sni"] == "example.com"

    exp_ja3, exp_raw = tf.ja3(0x0303, ciphers, ext_types, groups, pf)
    exp_ja4 = tf.ja4(ciphers, ext_types, sigs, versions, True, alpn)
    assert r["ja3"] == exp_ja3
    assert r["ja3_raw"] == exp_raw
    assert r["ja4"] == exp_ja4
    assert r["ja4"].startswith("t13d")  # TLS1.3 from supported_versions, SNI present


def test_split_client_hello_reassembly(tmp_path):
    record = tf.build_client_hello()[0]
    split = 100
    # Two TCP segments with correct sequence numbers carrying one ClientHello.
    frames = [
        _c2s(record[:split], seq=1),
        _c2s(record[split:], seq=1 + split),
    ]
    pcap = tmp_path / "split.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["tls"])
    rows = _read(summary["files"][0]["paths"]["tls"])
    assert len(rows) == 1
    assert rows[0]["sni"] == "example.com"
    # identical result to the single-segment case
    single = tmp_path / "single.pcap"
    single.write_bytes(fx.pcap_file([_c2s(record, seq=1)]))
    s2 = pcapracer.extract(str(single), tmp_path / "s2", tables=["tls"])
    r2 = _read(s2["files"][0]["paths"]["tls"])
    assert rows[0]["ja3"] == r2[0]["ja3"]
    assert rows[0]["ja4"] == r2[0]["ja4"]


def test_http_request_response(tmp_path):
    req = b"GET /path HTTP/1.1\r\nHost: victim.example\r\nUser-Agent: evil/1.0\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
    frames = [
        _c2s(req, seq=1, dport=80),
        _s2c(resp, seq=1, sport=80),
    ]
    pcap = tmp_path / "http.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["http"])
    rows = _read(summary["files"][0]["paths"]["http"])
    assert len(rows) == 2
    req_row = next(r for r in rows if r["is_request"])
    resp_row = next(r for r in rows if not r["is_request"])
    assert req_row["method"] == "GET"
    assert req_row["host"] == "victim.example"
    assert req_row["user_agent"] == "evil/1.0"
    assert resp_row["status"] == 200
    assert resp_row["server"] == "nginx"
    assert resp_row["content_length"] == 5


def test_tls_and_http_enrich_flow(tmp_path):
    record = tf.build_client_hello("threat.tls.example")[0]
    frame = _c2s(record, seq=1)
    pcap = tmp_path / "enrich.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    rows = _read(summary["files"][0]["paths"]["flows"])
    assert rows[0]["tls_sni"] == "threat.tls.example"
    assert rows[0]["ja3"] is not None
    assert rows[0]["ja4"].startswith("t13d")
    assert "tls" in rows[0]["app_protos"]


def test_ssh_banner_enrichment(tmp_path):
    banner = b"SSH-2.0-OpenSSH_9.6\r\n"
    frames = [
        _c2s(b"", seq=1, dport=22, flags=SYN),
        _s2c(banner, seq=1, sport=22),
    ]
    pcap = tmp_path / "ssh.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    rows = _read(summary["files"][0]["paths"]["flows"])
    assert "ssh" in (rows[0]["app_protos"] or "")
    assert "OpenSSH" in (rows[0]["server_banner"] or "")
