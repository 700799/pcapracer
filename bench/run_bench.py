#!/usr/bin/env python3
"""Benchmark pcapracer throughput across table selections.

Usage: python bench/run_bench.py [bench.pcap]
"""

from __future__ import annotations

import os
import resource
import sys
import time

import pcapracer


def bench(pcap: str, tables, label: str, out_dir: str) -> None:
    t0 = time.perf_counter()
    summary = pcapracer.extract(pcap, out_dir, tables=tables)
    dt = time.perf_counter() - t0
    pkts = summary["packets"]
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # MB on Linux
    rate = pkts / dt / 1e6 if dt > 0 else 0
    rows = ", ".join(f"{k}={v}" for k, v in summary["rows"].items())
    print(f"{label:14s} {dt:6.3f}s  {rate:6.2f}M pkts/s  RSS {rss:6.0f}MB  [{rows}]")


def main() -> None:
    pcap = sys.argv[1] if len(sys.argv) > 1 else "bench/bench.pcap"
    if not os.path.exists(pcap):
        print(f"missing {pcap}; run bench/make_bench_pcap.py first", file=sys.stderr)
        sys.exit(1)
    out = "bench/out"
    os.makedirs(out, exist_ok=True)
    print(f"benchmarking {pcap} ({os.path.getsize(pcap)/1e6:.0f} MB)")
    bench(pcap, ["packets"], "packets", out)
    bench(pcap, ["flows"], "flows", out)
    bench(pcap, ["packets", "flows", "dns", "http", "tls"], "all-tables", out)


if __name__ == "__main__":
    main()
