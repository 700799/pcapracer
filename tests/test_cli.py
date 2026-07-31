"""CLI tests."""

from __future__ import annotations

import pyarrow.parquet as pq

import fixtures as fx
from pcapracer.cli import main


def test_cli_basic(tmp_path, capsys):
    frames = [fx.eth(fx.ipv4(fx.tcp(b"hi", flags=0x18))) for _ in range(3)]
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    out = tmp_path / "out"
    rc = main([str(pcap), "-o", str(out), "--tables", "packets,flows"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "packets" in captured.out
    t = pq.read_table(out / "cap.packets.parquet")
    assert t.num_rows == 3


def test_cli_zstd_and_threads(tmp_path):
    frames = [fx.eth(fx.ipv4(fx.udp(fx.dns_query("x.example"), dport=53), proto=17))]
    pcap = tmp_path / "z.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    out = tmp_path / "out"
    rc = main([str(pcap), "-o", str(out), "-c", "zstd", "--threads", "2", "-t", "dns", "-q"])
    assert rc == 0
    t = pq.read_table(out / "z.dns.parquet")
    assert t.num_rows == 1


def test_cli_missing_file(tmp_path, capsys):
    rc = main([str(tmp_path / "nope.pcap"), "-o", str(tmp_path)])
    assert rc == 1
    assert "error" in capsys.readouterr().err
