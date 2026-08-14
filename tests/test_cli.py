"""CLI tests."""

from __future__ import annotations

import json

import pyarrow.parquet as pq
import pytest

from pcapracer.cli import main


def test_extract_writes_output(mixed_capture, tmp_path, capsys):
    out = tmp_path / "out"
    assert main([mixed_capture, "-o", str(out)]) == 0

    captured = capsys.readouterr().out
    assert "11 packets" in captured
    assert "packets.parquet" in captured
    assert pq.read_table(out / "packets.parquet").num_rows == 11


def test_extract_subcommand_is_optional(mixed_capture, tmp_path):
    out = tmp_path / "explicit"
    assert main(["extract", mixed_capture, "-o", str(out)]) == 0
    assert (out / "packets.parquet").exists()


def test_json_report(mixed_capture, tmp_path, capsys):
    out = tmp_path / "json"
    assert main([mixed_capture, "-o", str(out), "--json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["stats"]["packets"] == 11
    assert report["files"]["packets.parquet"] == 11
    assert report["elapsed_sec"] >= 0


def test_split_mode(mixed_capture, tmp_path):
    out = tmp_path / "split"
    assert main([mixed_capture, "-o", str(out), "--mode", "split"]) == 0
    assert (out / "dns.parquet").exists()
    assert not (out / "sip.parquet").exists()


def test_info_summarises_without_writing(mixed_capture, tmp_path, capsys):
    assert main(["info", mixed_capture]) == 0
    out = capsys.readouterr().out
    assert "11 packets" in out
    assert "top protocols" in out
    assert "http" in out
    assert "dns" in out
    # `info` must not create anything.
    assert list(tmp_path.iterdir()) == []


def test_info_json(mixed_capture, capsys):
    assert main(["info", mixed_capture, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["packets"] == 11
    assert payload["protocols"]["http"] == 2


def test_missing_file_exits_nonzero(tmp_path, capsys):
    assert main([str(tmp_path / "absent.pcap"), "-o", str(tmp_path / "o")]) == 2
    assert "error" in capsys.readouterr().err


def test_bad_capture_exits_nonzero(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"nope")
    assert main([str(bad), "-o", str(tmp_path / "o")]) == 1
    assert "error" in capsys.readouterr().err


def test_no_arguments_prints_help(capsys):
    assert main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_flow_cap_warning_is_reported(large_capture, tmp_path, capsys):
    out = tmp_path / "capped"
    assert main([large_capture, "-o", str(out), "--max-flows", "5"]) == 0
    assert "warning" in capsys.readouterr().err


@pytest.mark.parametrize("threads", ["1", "4"])
def test_thread_flag(mixed_capture, tmp_path, threads):
    out = tmp_path / f"t{threads}"
    assert main([mixed_capture, "-o", str(out), "-j", threads]) == 0
    assert pq.read_table(out / "packets.parquet").num_rows == 11
