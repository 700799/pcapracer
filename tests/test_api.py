"""End-to-end tests against the installed package."""

from __future__ import annotations

import json
import os

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import pcapracer


def column(table: pa.Table, name: str) -> list:
    return table.column(name).to_pylist()


def nonnull(table: pa.Table, name: str) -> list:
    return [v for v in column(table, name) if v is not None]


# ---------------------------------------------------------------------------
# Reading into memory
# ---------------------------------------------------------------------------


def test_read_packets_extracts_every_layer(mixed_capture):
    t = pcapracer.read_packets(mixed_capture)

    assert t.num_rows == 11
    assert t.num_columns == len(pcapracer.packet_schema_names())

    # L2
    assert "00:11:22:33:44:55" in nonnull(t, "eth_src")
    assert nonnull(t, "arp_opcode_name") == ["request"]

    # L3
    assert "10.0.0.5" in nonnull(t, "ip_src")
    assert "2001:db8::1" in nonnull(t, "ip_src")
    assert nonnull(t, "icmp_type_name") == ["echo-request"]

    # L4
    assert 50000 in nonnull(t, "src_port")
    assert "SYN" in nonnull(t, "tcp_flags_str")

    # L7
    assert nonnull(t, "http_host") == ["www.example.com"]
    assert nonnull(t, "http_user_agent") == ["curl/8.4.0"]
    assert nonnull(t, "http_server") == ["nginx/1.24.0"]
    assert nonnull(t, "http_status_code") == [200]
    assert nonnull(t, "http_uri_query") == ["debug=1"]
    assert nonnull(t, "dns_qname") == ["www.example.com", "www.example.com"]
    assert nonnull(t, "dns_answer_ips") == ["93.184.216.34"]
    assert nonnull(t, "tls_sni") == ["secure.example.com"]
    assert nonnull(t, "tls_alpn") == ["h2"]


def test_fingerprints_are_computed(mixed_capture):
    t = pcapracer.read_packets(mixed_capture)

    ja3 = nonnull(t, "ja3")
    assert len(ja3) == 1
    assert len(ja3[0]) == 32  # md5 hex

    ja4 = nonnull(t, "ja4")
    assert len(ja4) == 1
    # TLS 1.3 (from supported_versions), SNI present, ALPN h2.
    assert ja4[0].startswith("t13d")
    assert ja4[0].count("_") == 2

    # GREASE must not leak into the JA3 string.
    assert "2570" not in nonnull(t, "ja3_full")[0]


def test_community_id_is_shared_by_both_directions(mixed_capture):
    t = pcapracer.read_packets(mixed_capture)
    rows = list(zip(column(t, "src_port"), column(t, "dst_port"), column(t, "community_id")))
    http = {cid for sp, dp, cid in rows if 80 in (sp, dp) and cid}
    assert len(http) == 1
    assert http.pop().startswith("1:")


def test_protocol_stack_is_recorded(mixed_capture):
    t = pcapracer.read_packets(mixed_capture)
    stacks = set(nonnull(t, "proto_stack"))
    assert "eth:ip:tcp:http" in stacks
    assert "eth:ip:udp:dns" in stacks
    assert "eth:arp" in stacks
    assert "eth:ipv6:icmpv6" in stacks
    assert "eth:ip:tcp:tls" in stacks


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------


def test_read_flows_aggregates_conversations(mixed_capture):
    f = pcapracer.read_flows(mixed_capture)

    # TCP/80, TCP/443, DNS, ICMP, ICMPv6 — ARP has no IP tuple and so no flow.
    assert f.num_rows == 5

    rows = f.to_pylist()
    http = next(r for r in rows if 80 in (r["src_port"], r["dst_port"]))
    assert http["packets_total"] == 5  # 3-way handshake plus request and response
    assert http["tcp_state"] == "established"
    assert http["http_host"] == "www.example.com"
    assert http["packets_c2s"] > 0 and http["packets_s2c"] > 0
    assert http["bytes_total"] == http["bytes_c2s"] + http["bytes_s2c"]

    tls = next(r for r in rows if 443 in (r["src_port"], r["dst_port"]))
    assert tls["tls_sni"] == "secure.example.com"
    assert tls["ja3"] is not None


def test_flow_duration_and_timestamps(mixed_capture):
    f = pcapracer.read_flows(mixed_capture)
    for row in f.to_pylist():
        assert row["last_ts"] >= row["first_ts"]
        assert row["duration_sec"] >= 0
        assert row["community_id"].startswith("1:")


# ---------------------------------------------------------------------------
# Reassembly
# ---------------------------------------------------------------------------


def test_reassembly_recovers_a_split_header(segmented_capture):
    t = pcapracer.read_packets(segmented_capture, reassemble=True)
    assert nonnull(t, "http_host") == ["reassembled.example"]
    assert nonnull(t, "http_user_agent") == ["probe/1.0"]
    assert True in column(t, "reassembled")


def test_without_reassembly_the_split_header_is_missed(segmented_capture):
    t = pcapracer.read_packets(segmented_capture, reassemble=False)
    assert nonnull(t, "http_host") == []


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("threads", [1, 2, 8])
def test_thread_count_does_not_change_results(large_capture, threads):
    baseline = pcapracer.read_packets(large_capture, threads=1)
    other = pcapracer.read_packets(large_capture, threads=threads)
    assert baseline.equals(other)


def test_batch_size_does_not_change_results(large_capture):
    a = pcapracer.read_packets(large_capture, batch_size=64)
    b = pcapracer.read_packets(large_capture, batch_size=100_000)
    assert a.equals(b)


# ---------------------------------------------------------------------------
# Parquet output
# ---------------------------------------------------------------------------


def test_to_parquet_wide_mode(mixed_capture, tmp_path):
    out = tmp_path / "wide"
    report = pcapracer.to_parquet(mixed_capture, out)

    assert report["stats"]["packets"] == 11
    assert report["stats"]["bad_blocks"] == 0
    assert report["files"]["packets.parquet"] == 11

    packets = pq.read_table(out / "packets.parquet")
    assert packets.num_rows == 11
    assert "tls_sni" in packets.schema.names

    flows = pq.read_table(out / "flows.parquet")
    assert flows.num_rows == 5

    meta = json.loads((out / "_meta.json").read_text())
    assert meta["stats"]["packets"] == 11
    assert meta["stats"]["pcapracer_version"]


def test_to_parquet_split_mode(mixed_capture, tmp_path):
    out = tmp_path / "split"
    report = pcapracer.to_parquet(mixed_capture, out, mode="split")

    assert report["files"]["http.parquet"] == 2
    assert report["files"]["dns.parquet"] == 2
    assert report["files"]["tls.parquet"] == 1
    assert report["files"]["arp.parquet"] == 1

    # Protocols not in the capture must not leave empty files behind.
    assert not (out / "modbus.parquet").exists()
    assert not (out / "sip.parquet").exists()

    core = pq.read_table(out / "packets.parquet")
    assert core.num_rows == 11
    assert "tls_sni" not in core.schema.names
    assert "packet_id" in core.schema.names

    # Sidecars join back to the core table on packet_id.
    http = pq.read_table(out / "http.parquet")
    assert set(http.column("packet_id").to_pylist()) <= set(core.column("packet_id").to_pylist())
    assert "http_host" in http.schema.names


def test_wide_and_split_agree_on_content(mixed_capture, tmp_path):
    wide_dir, split_dir = tmp_path / "w", tmp_path / "s"
    pcapracer.to_parquet(mixed_capture, wide_dir, mode="wide")
    pcapracer.to_parquet(mixed_capture, split_dir, mode="split")

    wide = pq.read_table(wide_dir / "packets.parquet")
    dns_sidecar = pq.read_table(split_dir / "dns.parquet")

    wide_qnames = sorted(v for v in wide.column("dns_qname").to_pylist() if v)
    split_qnames = sorted(v for v in dns_sidecar.column("dns_qname").to_pylist() if v)
    assert wide_qnames == split_qnames


@pytest.mark.parametrize("compression", ["zstd", "snappy", "lz4", "gzip", "none"])
def test_all_compression_codecs_round_trip(mixed_capture, tmp_path, compression):
    out = tmp_path / compression
    pcapracer.to_parquet(mixed_capture, out, compression=compression)
    assert pq.read_table(out / "packets.parquet").num_rows == 11


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_iter_batches_is_lazy_and_complete(large_capture):
    total = 0
    batches = 0
    for batch in pcapracer.iter_batches(large_capture, batch_size=256):
        assert isinstance(batch, pa.RecordBatch)
        total += batch.num_rows
        batches += 1
    assert total == 2000
    assert batches > 1


def test_iter_batches_can_be_abandoned_early(large_capture):
    it = pcapracer.iter_batches(large_capture, batch_size=64)
    first = next(it)
    assert first.num_rows == 64
    it.close()  # must not hang or leak the worker thread


def test_for_each_batch_propagates_callback_errors(large_capture):
    class Boom(Exception):
        pass

    def explode(batch):
        raise Boom("from the callback")

    with pytest.raises(Boom, match="from the callback"):
        pcapracer.for_each_batch(large_capture, explode, batch_size=64)


def test_streaming_matches_in_memory(large_capture):
    streamed = pa.Table.from_batches(
        list(pcapracer.iter_batches(large_capture, batch_size=128))
    )
    assert streamed.equals(pcapracer.read_packets(large_capture))


# ---------------------------------------------------------------------------
# Edge cases and errors
# ---------------------------------------------------------------------------


def test_empty_capture_produces_readable_output(empty_capture, tmp_path):
    out = tmp_path / "empty"
    report = pcapracer.to_parquet(empty_capture, out)
    assert report["stats"]["packets"] == 0
    assert pq.read_table(out / "packets.parquet").num_rows == 0
    assert pq.read_table(out / "flows.parquet").num_rows == 0


def test_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        pcapracer.read_packets(tmp_path / "nope.pcap")


def test_garbage_file_raises_a_clear_error(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"definitely not a capture file")
    with pytest.raises(ValueError, match="pcap"):
        pcapracer.read_packets(bad)


def test_invalid_options_are_rejected(mixed_capture, tmp_path):
    with pytest.raises(ValueError, match="mode"):
        pcapracer.read_packets(mixed_capture, mode="sideways")
    with pytest.raises(ValueError, match="compression"):
        pcapracer.to_parquet(mixed_capture, tmp_path / "x", compression="rar")


def test_gzipped_capture_is_read_transparently(mixed_capture, tmp_path):
    import gzip
    import shutil

    gz = tmp_path / "mixed.pcap.gz"
    with open(mixed_capture, "rb") as src, gzip.open(gz, "wb") as dst:
        shutil.copyfileobj(src, dst)

    assert pcapracer.read_packets(gz).num_rows == 11


def test_flow_cap_is_enforced_and_reported(large_capture):
    _, _, stats = pcapracer.read(large_capture, max_flows=10)
    assert stats["flows"] <= 10
    assert stats["flows_evicted"] > 0


def test_schema_introspection():
    names = pcapracer.packet_schema_names()
    assert len(names) > 200
    assert names[0] == "packet_id"
    for expected in ("tls_sni", "dns_qname", "ja4", "modbus_function_name", "krb_cname"):
        assert expected in names

    tables = pcapracer.protocol_tables()
    assert {"dns", "http", "tls", "modbus", "kerberos"} <= set(tables)


def test_version_is_exposed():
    assert pcapracer.__version__.count(".") == 2
