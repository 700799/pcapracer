"""Command-line interface for pcapracer."""

from __future__ import annotations

import argparse
import sys

from . import ALL_TABLES, __version__, extract


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcapracer",
        description="Fast PCAP/pcapng feature extraction to Parquet for cyber analysis.",
    )
    p.add_argument("inputs", nargs="+", help="capture file(s) or glob pattern(s)")
    p.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="directory for the Parquet outputs (default: current dir)",
    )
    p.add_argument(
        "-t",
        "--tables",
        default=",".join(ALL_TABLES),
        help="comma-separated tables to emit (default: all): " + ",".join(ALL_TABLES),
    )
    p.add_argument(
        "-c",
        "--compression",
        default="snappy",
        choices=["none", "snappy", "zstd"],
        help="Parquet compression codec (default: snappy)",
    )
    p.add_argument("--zstd-level", type=int, default=3, help="zstd level when -c zstd")
    p.add_argument(
        "--idle-timeout",
        type=float,
        default=120.0,
        help="flow idle timeout in seconds (default: 120)",
    )
    p.add_argument(
        "--active-threshold",
        type=float,
        default=1.0,
        help="active/idle gap threshold in seconds (default: 1.0)",
    )
    p.add_argument("--max-flows", type=int, default=1_000_000)
    p.add_argument("--hex-prefix-len", type=int, default=0)
    p.add_argument("--threads", type=int, default=0, help="worker threads (0 = auto)")
    p.add_argument("--batch-size", type=int, default=8192)
    p.add_argument("-q", "--quiet", action="store_true", help="suppress the summary")
    p.add_argument("--version", action="version", version=f"pcapracer {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tables = [t.strip() for t in args.tables.split(",") if t.strip()]
    try:
        summary = extract(
            args.inputs,
            args.output_dir,
            tables=tables,
            compression=args.compression,
            zstd_level=args.zstd_level,
            idle_timeout=args.idle_timeout,
            active_threshold=args.active_threshold,
            max_flows=args.max_flows,
            hex_prefix_len=args.hex_prefix_len,
            threads=args.threads,
            batch_size=args.batch_size,
        )
    except (OSError, ValueError) as e:
        print(f"pcapracer: error: {e}", file=sys.stderr)
        return 1

    if not args.quiet:
        n = summary["packets"]
        elapsed = summary["elapsed_s"]
        rate = summary["pkts_per_s"]
        print(
            f"pcapracer: {n} packets in {elapsed:.3f}s ({rate/1e6:.2f}M pkts/s), "
            f"{summary['decode_errors']} decode errors"
        )
        for table, rows in summary["rows"].items():
            print(f"  {table:8s} {rows} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
