"""Robustness: hostile / malformed captures must never crash the extractor."""

from __future__ import annotations

import os
import random
import struct

import pcapracer
import fixtures as fx


def _pcap_header(linktype=1):
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)


def test_random_records_do_not_crash(tmp_path):
    rng = random.Random(1234)
    for i in range(150):
        body = bytearray(_pcap_header())
        for _ in range(rng.randint(0, 20)):
            n = rng.randint(0, 80)
            data = bytes(rng.randrange(256) for _ in range(n))
            body += struct.pack("<IIII", 1_700_000_000, 0, n, n)
            body += data
        p = tmp_path / f"rand{i}.pcap"
        p.write_bytes(body)
        # Must return normally; decode_errors may be > 0.
        summary = pcapracer.extract(str(p), tmp_path / "out", tables=["packets", "flows", "dns", "http", "tls"])
        assert summary["packets"] >= 0


def test_lying_caplen(tmp_path):
    # caplen claims far more than the file contains.
    body = bytearray(_pcap_header())
    body += struct.pack("<IIII", 1_700_000_000, 0, 100000, 100000)
    body += b"\x00" * 10  # only 10 bytes actually present
    p = tmp_path / "lying.pcap"
    p.write_bytes(body)
    summary = pcapracer.extract(str(p), tmp_path, tables=["packets"])
    assert summary["packets"] >= 0


def test_truncated_mid_frame(tmp_path):
    frame = fx.eth(fx.ipv4(fx.tcp(b"x" * 100)))
    full = fx.pcap_file([frame])
    for cut in range(24, len(full)):
        p = tmp_path / "trunc.pcap"
        p.write_bytes(full[:cut])
        pcapracer.extract(str(p), tmp_path / "out", tables=["packets", "flows"])


def test_malformed_dns_and_tls(tmp_path):
    rng = random.Random(99)
    frames = []
    for _ in range(50):
        n = rng.randint(1, 60)
        junk = bytes(rng.randrange(256) for _ in range(n))
        frames.append(fx.eth(fx.ipv4(fx.udp(junk, dport=53), proto=17)))
        # TLS-looking garbage (starts with 0x16)
        frames.append(fx.eth(fx.ipv4(fx.tcp(b"\x16\x03\x01" + junk, dport=443, flags=0x18))))
    p = tmp_path / "malformed.pcap"
    p.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(p), tmp_path, tables=["dns", "tls", "flows"])
    assert summary["packets"] == len(frames)


def test_empty_file(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(_pcap_header())
    summary = pcapracer.extract(str(p), tmp_path, tables=["packets", "flows"])
    assert summary["packets"] == 0
