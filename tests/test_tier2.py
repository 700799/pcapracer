"""Tier-2 protocol tests (SNMP, Modbus, SMB, IGMP, SCTP, TFTP, Syslog, SIP)."""

from __future__ import annotations

import struct

import pyarrow.parquet as pq

import pcapracer
import fixtures as fx


def _read(path):
    return pq.read_table(path).to_pylist()


def _extract(tmp_path, frames, name="t2"):
    pcap = tmp_path / f"{name}.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["packets"])
    return _read(summary["files"][0]["paths"]["packets"])


def test_snmp(tmp_path):
    snmp = bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x04, 0x06]) + b"public"
    frame = fx.eth(fx.ipv4(fx.udp(snmp, sport=40000, dport=161), proto=17))
    rows = _extract(tmp_path, [frame], "snmp")
    assert rows[0]["snmp_version"] == 1
    assert rows[0]["snmp_community"] == "public"
    assert rows[0]["app_proto"] == "snmp"


def test_modbus(tmp_path):
    mbap = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03])
    frame = fx.eth(fx.ipv4(fx.tcp(mbap, sport=40000, dport=502, flags=0x18)))
    rows = _extract(tmp_path, [frame], "modbus")
    assert rows[0]["modbus_unit_id"] == 0x11
    assert rows[0]["modbus_function"] == 3


def test_smb2(tmp_path):
    smb = bytes([0x00, 0x00, 0x00, 0x40, 0xFE]) + b"SMB" + bytes(16)
    frame = fx.eth(fx.ipv4(fx.tcp(smb, sport=40000, dport=445, flags=0x18)))
    rows = _extract(tmp_path, [frame], "smb")
    assert rows[0]["smb_dialect"] == "smb2"


def test_igmp(tmp_path):
    igmp = bytes([0x16, 0x00, 0x00, 0x00]) + bytes([239, 1, 2, 3])
    frame = fx.eth(fx.ipv4(igmp, proto=2, dst="224.0.0.22"))
    rows = _extract(tmp_path, [frame], "igmp")
    assert rows[0]["igmp_type"] == 0x16


def test_sctp(tmp_path):
    # SCTP: sport 100, dport 200, vtag, checksum, then a DATA chunk (type 0)
    sctp = struct.pack(">HHII", 100, 200, 0xDEADBEEF, 0) + bytes([0x00, 0x03, 0x00, 0x10])
    frame = fx.eth(fx.ipv4(sctp, proto=132))
    rows = _extract(tmp_path, [frame], "sctp")
    assert rows[0]["sctp_verification_tag"] == 0xDEADBEEF
    assert rows[0]["sctp_chunk_type"] == 0
    assert rows[0]["src_port"] == 100
    assert rows[0]["dst_port"] == 200


def test_syslog(tmp_path):
    msg = b"<34>Oct 11 22:14:15 myhost su: failed login"
    frame = fx.eth(fx.ipv4(fx.udp(msg, sport=40000, dport=514), proto=17))
    rows = _extract(tmp_path, [frame], "syslog")
    assert rows[0]["syslog_facility"] == 4
    assert rows[0]["syslog_severity"] == 2
