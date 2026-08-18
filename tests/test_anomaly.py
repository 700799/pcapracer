"""Tests for the unsupervised anomaly-scoring module."""

from __future__ import annotations

import pytest

pytest.importorskip("numpy")
pytest.importorskip("pyarrow")

import numpy as np  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

import pcapracer  # noqa: E402
import fixtures as fx  # noqa: E402
from pcapracer import anomaly  # noqa: E402


def _benign_and_exfil_pcap(path):
    """30 short benign HTTP flows + 1 long-lived high-volume flow to an odd port."""
    frames, ts, t = [], [], 0.0
    for i in range(30):
        sp = 30000 + i
        frames.append(
            fx.eth(fx.ipv4(fx.tcp(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", sport=sp, dport=80, flags=0x18),
                           src="10.0.0.5", dst="10.0.0.6"))
        )
        ts.append(t); t += 0.01
        frames.append(
            fx.eth(fx.ipv4(fx.tcp(b"HTTP/1.1 200 OK\r\n\r\n", sport=80, dport=sp, flags=0x18),
                           src="10.0.0.6", dst="10.0.0.5"))
        )
        ts.append(t); t += 0.01
    for k in range(20):
        frames.append(
            fx.eth(fx.ipv4(fx.tcp(b"x" * 1400, sport=4444, dport=53201, seq=1 + k * 1400, flags=0x18),
                           src="10.0.0.5", dst="6.6.6.6"))
        )
        ts.append(t); t += 3.0
    path.write_bytes(fx.pcap_file_ts(list(zip(frames, ts))))


def test_ranks_planted_anomaly(tmp_path):
    pcap = tmp_path / "mix.pcap"
    _benign_and_exfil_pcap(pcap)
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    flows = summary["files"][0]["paths"]["flows"]

    scored = anomaly.rank_anomalies(flows, table="flows", top=3)
    rows = scored.to_pylist()
    assert rows[0]["dst_ip"] == "6.6.6.6"  # the exfil flow is the most anomalous
    assert rows[0]["anomaly_rank"] == 1
    assert rows[0]["anomaly_score"] > rows[1]["anomaly_score"]
    # the reason should name a volume/rate/length feature
    reason = rows[0]["anomaly_reason"]
    assert any(k in reason for k in ("bytes", "pkt_len", "per_s", "iat", "duration"))


def test_score_table_adds_columns_and_soft_export(tmp_path):
    pcap = tmp_path / "mix.pcap"
    _benign_and_exfil_pcap(pcap)
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    # soft export from the top-level package
    scored = pcapracer.score_table(summary["files"][0]["paths"]["flows"])
    for col in ("anomaly_score", "anomaly_rank", "anomaly_reason"):
        assert col in scored.schema.names
    assert scored.num_rows == 31
    # ranks are a permutation of 1..n
    ranks = sorted(scored.column("anomaly_rank").to_pylist())
    assert ranks == list(range(1, 32))


def test_directory_source(tmp_path):
    pcap = tmp_path / "mix.pcap"
    _benign_and_exfil_pcap(pcap)
    pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    # passing the directory auto-selects *.flows.parquet
    scored = anomaly.rank_anomalies(str(tmp_path), table="flows", top=1)
    assert scored.to_pylist()[0]["dst_ip"] == "6.6.6.6"


def test_gaussian_mixture_recovers_two_clusters():
    rng = np.random.default_rng(0)
    x = np.concatenate([rng.normal(-5, 0.5, 150), rng.normal(5, 0.5, 150)])[:, None]
    gmm = anomaly._fit_mixture(x, max_components=4, seed=0)
    assert gmm.n_components >= 2
    means = sorted(float(m) for m in gmm.means[:, 0])
    assert means[0] < -3 and means[-1] > 3
    # density is higher at a cluster centre than in the empty gap at 0
    ld = gmm.log_density(np.array([[-5.0], [0.0], [5.0]]))
    assert ld[0] > ld[1] and ld[2] > ld[1]


def test_feature_selection_excludes_identifiers(tmp_path):
    # Mixed protocols so the categorical `proto_name` actually varies.
    frames = []
    for i in range(10):
        frames.append(fx.eth(fx.ipv4(fx.tcp(b"hi", sport=40000 + i, dport=80, flags=0x18),
                                     src="10.0.0.1", dst="10.0.0.2")))
    for i in range(10):
        frames.append(fx.eth(fx.ipv4(fx.udp(fx.dns_query("x.example"), sport=50000 + i, dport=53),
                                     src="10.0.0.1", dst="10.0.0.3", proto=17)))
    pcap = tmp_path / "mixproto.pcap"
    pcap.write_bytes(fx.pcap_file(frames))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    tbl = pq.read_table(summary["files"][0]["paths"]["flows"])
    numeric, categorical = anomaly._select_features(tbl, None)
    picked = set(numeric) | set(categorical)
    # identifiers / high-cardinality never selected
    for bad in ("flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "first_ts", "ja3"):
        assert bad not in picked
    # useful behavioural features are selected
    assert "fwd_pkts" in numeric
    assert "proto_name" in categorical  # cardinality {tcp, udp} > 1


def test_empty_table(tmp_path):
    frame = fx.eth(fx.ipv4(fx.tcp(b"", flags=0x02)))  # a lone SYN -> a flow exists
    pcap = tmp_path / "one.pcap"
    pcap.write_bytes(fx.pcap_file([frame]))
    summary = pcapracer.extract(str(pcap), tmp_path, tables=["flows"])
    scored = anomaly.score_table(summary["files"][0]["paths"]["flows"])
    assert "anomaly_score" in scored.schema.names  # never raises on tiny input
