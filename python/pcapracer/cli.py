"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import Sequence

from . import __version__
from .api import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_FLOWS,
    DEFAULT_MAX_STREAM_BYTES,
    DEFAULT_MAX_STREAMS,
    DEFAULT_ROW_GROUP_ROWS,
    for_each_batch,
    to_parquet,
)


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}TB"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcapracer",
        description="Extract packet, flow and protocol features from a capture into Parquet.",
    )
    p.add_argument("--version", action="version", version=f"pcapracer {__version__}")
    sub = p.add_subparsers(dest="command")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("input", help="a .pcap, .pcapng, or gzipped capture")
        sp.add_argument(
            "--no-reassemble",
            action="store_true",
            help="skip TCP stream reassembly (faster, but misses L7 fields split across segments)",
        )
        sp.add_argument(
            "-j",
            "--threads",
            type=int,
            default=0,
            help="worker threads (0 = all cores). Output is identical at any thread count.",
        )
        sp.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
        sp.add_argument("--max-flows", type=int, default=DEFAULT_MAX_FLOWS)
        sp.add_argument("--max-streams", type=int, default=DEFAULT_MAX_STREAMS)
        sp.add_argument("--max-stream-bytes", type=int, default=DEFAULT_MAX_STREAM_BYTES)

    extract = sub.add_parser("extract", help="write Parquet output (default command)")
    add_common(extract)
    extract.add_argument("-o", "--out", required=True, help="output directory")
    extract.add_argument("--mode", choices=("wide", "split"), default="wide")
    extract.add_argument(
        "--compression", choices=("zstd", "snappy", "lz4", "gzip", "none"), default="zstd"
    )
    extract.add_argument("--compression-level", type=int, default=3)
    extract.add_argument("--row-group-rows", type=int, default=DEFAULT_ROW_GROUP_ROWS)
    extract.add_argument(
        "--no-distributions",
        action="store_true",
        help="skip fitting numeric fields against scipy's distributions (_distributions.json)",
    )
    extract.add_argument("--json", action="store_true", help="print the run report as JSON")

    info = sub.add_parser("info", help="summarise a capture without writing output")
    add_common(info)
    info.add_argument("--json", action="store_true")
    info.add_argument("--top", type=int, default=15, help="protocols to list")

    return p


def _cmd_extract(args: argparse.Namespace) -> int:
    start = time.perf_counter()
    report = to_parquet(
        args.input,
        args.out,
        mode=args.mode,
        reassemble=not args.no_reassemble,
        threads=args.threads,
        batch_size=args.batch_size,
        compression=args.compression,
        compression_level=args.compression_level,
        row_group_rows=args.row_group_rows,
        max_flows=args.max_flows,
        max_streams=args.max_streams,
        max_stream_bytes=args.max_stream_bytes,
        fit_distributions=not args.no_distributions,
    )
    elapsed = time.perf_counter() - start

    if args.json:
        report["elapsed_sec"] = elapsed
        print(json.dumps(report, indent=2))
        return 0

    stats = report["stats"]
    packets = stats["packets"]
    rate = packets / elapsed if elapsed > 0 else 0.0
    print(f"{packets:,} packets, {stats['flows']:,} flows in {elapsed:.2f}s ({rate:,.0f} pkt/s)")
    print(f"capture bytes: {_human(stats['capture_bytes'])}")

    for name, rows in sorted(report["files"].items()):
        path = os.path.join(args.out, name)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        print(f"  {name:<24} {rows:>10,} rows  {_human(size):>9}")

    _print_distributions(report.get("distributions"))
    _warn_about_limits(stats)
    return 0


def _print_distributions(dists: dict | None) -> None:
    if not dists:
        return
    print()
    print("field distributions (best fit by Kolmogorov-Smirnov statistic, lower is better):")
    for name, fit in sorted(dists.items()):
        best = fit.get("best")
        if best:
            print(f"  {name:<24} {best['distribution']:<16} ks={best['ks_statistic']:.4f}")


def _warn_about_limits(stats: dict) -> None:
    """Surface anything the run had to drop.

    These are the cases where the output is quietly incomplete, so they belong on stderr
    rather than buried in _meta.json.
    """
    warnings = [
        ("bad_blocks", "unparseable capture blocks (file may be truncated or damaged)"),
        ("flows_evicted", "packets that opened no flow because --max-flows was reached"),
        ("streams_evicted", "segments dissected unreassembled because --max-streams was reached"),
        ("streams_truncated", "TCP streams cut off at --max-stream-bytes"),
        ("fragments_dropped", "IP fragment sets abandoned"),
        ("dissect_panics", "packets whose dissection panicked (please report — a dissector bug)"),
    ]
    for key, description in warnings:
        count = stats.get(key, 0)
        if count:
            print(f"warning: {count:,} {description}", file=sys.stderr)


def _cmd_info(args: argparse.Namespace) -> int:
    protocols: Counter[str] = Counter()
    start = time.perf_counter()

    def tally(batch) -> None:
        column = batch.column(batch.schema.get_field_index("highest_layer"))
        for value in column:
            protocols[value.as_py() or "unknown"] += 1

    stats = for_each_batch(
        args.input,
        tally,
        reassemble=not args.no_reassemble,
        threads=args.threads,
        batch_size=args.batch_size,
        max_flows=args.max_flows,
        max_streams=args.max_streams,
        max_stream_bytes=args.max_stream_bytes,
    )
    elapsed = time.perf_counter() - start

    if args.json:
        print(json.dumps({"stats": stats, "protocols": dict(protocols.most_common())}, indent=2))
        return 0

    packets = stats["packets"]
    rate = packets / elapsed if elapsed > 0 else 0.0
    print(f"{args.input}: {packets:,} packets in {elapsed:.2f}s ({rate:,.0f} pkt/s)")
    if stats["first_ts_ns"]:
        span = (stats["last_ts_ns"] - stats["first_ts_ns"]) / 1e9
        print(f"time span: {span:,.1f}s")
    print(f"malformed: {stats['malformed']:,}   snaplen-truncated: {stats['truncated']:,}")
    print()
    print("top protocols:")
    for name, count in protocols.most_common(args.top):
        share = 100.0 * count / packets if packets else 0.0
        print(f"  {name:<16} {count:>10,}  {share:5.1f}%")

    _warn_about_limits(stats)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `pcapracer capture.pcap -o out/` should work without typing the subcommand.
    if argv and not argv[0].startswith("-") and argv[0] not in ("extract", "info"):
        argv.insert(0, "extract")

    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1

    try:
        if args.command == "info":
            return _cmd_info(args)
        return _cmd_extract(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
