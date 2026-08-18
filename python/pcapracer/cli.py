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


def build_anomaly_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pcapracer-anomaly",
        description="Unsupervised anomaly scoring over a pcapracer Parquet table.",
    )
    p.add_argument("source", help="a .parquet file or an output directory")
    p.add_argument(
        "-t",
        "--table",
        default="flows",
        help="table to score when SOURCE is a directory (default: flows)",
    )
    p.add_argument("-n", "--top", type=int, default=20, help="rows to show (default: 20)")
    p.add_argument("--out", help="write the full scored table to this Parquet path")
    p.add_argument("--max-components", type=int, default=6)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--version", action="version", version=f"pcapracer {__version__}")
    return p


def anomaly_main(argv: list[str] | None = None) -> int:
    args = build_anomaly_parser().parse_args(argv)
    try:
        from .anomaly import score_table
    except ImportError as e:
        print(f"pcapracer-anomaly: {e}", file=sys.stderr)
        return 1

    try:
        scored = score_table(
            args.source,
            table=args.table,
            max_components=args.max_components,
            seed=args.seed,
        )
    except (OSError, ValueError) as e:
        print(f"pcapracer-anomaly: error: {e}", file=sys.stderr)
        return 1

    if args.out:
        import pyarrow.parquet as pq

        pq.write_table(scored, args.out)

    import pyarrow.compute as pc

    order = pc.sort_indices(scored, sort_keys=[("anomaly_score", "descending")])
    top = scored.take(order[: min(args.top, scored.num_rows)]).to_pylist()
    have = set(scored.schema.names)

    def col(row, *names):
        for nm in names:
            if nm in have and row.get(nm) is not None:
                return row[nm]
        return ""

    print(f"{'rank':>4}  {'score':>7}  {'src':>21}  {'dst':>21}  reason")
    for row in top:
        src = f"{col(row,'src_ip')}:{col(row,'src_port')}"
        dst = f"{col(row,'dst_ip')}:{col(row,'dst_port')}"
        print(
            f"{row['anomaly_rank']:>4}  {row['anomaly_score']:>7.2f}  "
            f"{src:>21}  {dst:>21}  {row['anomaly_reason']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
