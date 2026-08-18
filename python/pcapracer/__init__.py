"""pcapracer — fast PCAP/pcapng feature extraction to Parquet, powered by Rust.

Extracts packet-level fields, bidirectional flow features, and application-layer
records (DNS, HTTP, TLS with JA3/JA4) into Parquet tables for cyber analysis.

Basic usage::

    import pcapracer
    summary = pcapracer.extract("capture.pcap", output_dir="out/")
    print(summary["rows"])   # {'packets': 1234, 'flows': 56, ...}
"""

from __future__ import annotations

import glob as _glob
import os
from pathlib import Path
from typing import Iterable, Sequence, Union

from ._pcapracer import __version__, extract_one

__all__ = [
    "__version__",
    "extract",
    "extract_packets",
    "extract_flows",
    "score_table",
    "rank_anomalies",
    "ALL_TABLES",
]

ALL_TABLES = ["packets", "flows", "dns", "http", "tls"]

PathLike = Union[str, os.PathLike]


def _expand_inputs(inp: Union[PathLike, Sequence[PathLike]]) -> list[str]:
    """Normalize the input argument into a concrete list of file paths."""
    if isinstance(inp, (str, os.PathLike)):
        candidates: Iterable[PathLike] = [inp]
    else:
        candidates = inp
    out: list[str] = []
    for c in candidates:
        s = os.fspath(c)
        if any(ch in s for ch in "*?[") and not os.path.exists(s):
            matches = sorted(_glob.glob(s))
            if not matches:
                raise FileNotFoundError(f"no files match glob: {s!r}")
            out.extend(matches)
        else:
            if not os.path.exists(s):
                raise FileNotFoundError(s)
            out.append(s)
    if not out:
        raise ValueError("no input files provided")
    return out


def extract(
    input: Union[PathLike, Sequence[PathLike]],
    output_dir: PathLike = ".",
    *,
    tables: Sequence[str] = ALL_TABLES,
    compression: str = "snappy",
    zstd_level: int = 3,
    idle_timeout: float = 120.0,
    active_threshold: float = 1.0,
    max_flows: int = 1_000_000,
    app_buffer_bytes: int = 8192,
    hex_prefix_len: int = 0,
    threads: int = 0,
    batch_size: int = 8192,
) -> dict:
    """Extract features from one or more capture files into Parquet tables.

    ``input`` may be a path, a glob pattern, or a sequence of either. Each file
    produces ``<output_dir>/<stem>.<table>.parquet``. Returns a summary dict
    with per-file results under ``"files"`` and aggregate row counts.
    """
    files = _expand_inputs(input)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    tables = list(tables)
    per_file = []
    agg_rows: dict[str, int] = {t: 0 for t in tables}
    total_packets = 0
    total_errors = 0
    total_elapsed = 0.0

    for f in files:
        summary = extract_one(
            f,
            output_dir=str(out),
            tables=tables,
            compression=compression,
            zstd_level=zstd_level,
            idle_timeout=idle_timeout,
            active_threshold=active_threshold,
            max_flows=max_flows,
            app_buffer_bytes=app_buffer_bytes,
            hex_prefix_len=hex_prefix_len,
            threads=threads,
            batch_size=batch_size,
        )
        summary["input"] = f
        per_file.append(summary)
        total_packets += summary["packets"]
        total_errors += summary["decode_errors"]
        total_elapsed += summary["elapsed_s"]
        for t, n in summary["rows"].items():
            agg_rows[t] = agg_rows.get(t, 0) + n

    return {
        "files": per_file,
        "packets": total_packets,
        "decode_errors": total_errors,
        "elapsed_s": total_elapsed,
        "pkts_per_s": (total_packets / total_elapsed) if total_elapsed > 0 else 0.0,
        "rows": agg_rows,
    }


def extract_packets(input, output_dir=".", **kwargs) -> dict:
    """Convenience wrapper: extract only the ``packets`` table."""
    return extract(input, output_dir, tables=["packets"], **kwargs)


def extract_flows(input, output_dir=".", **kwargs) -> dict:
    """Convenience wrapper: extract only the ``flows`` table."""
    return extract(input, output_dir, tables=["flows"], **kwargs)


def __getattr__(name):
    # Lazy, optional import: keeps the core dependency-free (no numpy/pyarrow
    # needed to `import pcapracer`); `pip install 'pcapracer[anomaly]'` enables it.
    if name in ("score_table", "rank_anomalies"):
        from . import anomaly

        return getattr(anomaly, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
