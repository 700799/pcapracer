# pcapracer

**Fast PCAP → Parquet feature extraction for cyber analysis, powered by Rust.**

[![CI](https://github.com/700799/pcapracer/actions/workflows/ci.yml/badge.svg)](https://github.com/700799/pcapracer/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pcapracer.svg)](https://pypi.org/project/pcapracer/)
[![Python](https://img.shields.io/pypi/pyversions/pcapracer.svg)](https://pypi.org/project/pcapracer/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`pcapracer` reads pcap / pcapng captures and extracts **as many protocol features as
possible** into columnar **Parquet** tables — packet fields, bidirectional flow
statistics, and application-layer records (DNS, HTTP, TLS with JA3/JA4). It is built
for threat hunting, DFIR triage, and ML feature engineering: point it at a capture,
get analysis-ready Parquet you can load into pandas, polars, DuckDB, or Spark.

- **Rust core, zero Python dependencies** — one self-contained wheel per platform.
- **Wide feature coverage** — 100+ packet columns, 95 flow features, per-protocol tables.
- **Robust** — never panics on malformed or hostile captures; it counts and continues.
- **Fast & parallel** — memory-mapped, zero-copy, multi-threaded pipeline.

## Install

```bash
pip install pcapracer
```

Wheels are published for Linux (x86_64, aarch64; glibc and musl), macOS (arm64, x86_64),
and Windows (x64), for CPython ≥ 3.10.

## Quickstart

```python
import pcapracer

summary = pcapracer.extract("capture.pcap", output_dir="out/")
print(summary["rows"])   # {'packets': 12043, 'flows': 210, 'dns': 88, 'http': 15, 'tls': 12}

# then analyze with your tool of choice
import pyarrow.parquet as pq
tls = pq.read_table("out/capture.tls.parquet")
print(tls.column("ja4").to_pylist())
```

Select only the tables you need (faster):

```python
pcapracer.extract("capture.pcapng", "out/", tables=["flows", "tls"])
pcapracer.extract_packets("capture.pcap.gz", "out/")     # packets only, gzip input ok
pcapracer.extract(["a.pcap", "b.pcap", "glob/*.pcap"], "out/")  # many files / globs
```

### Command line

```bash
pcapracer capture.pcap -o out/
pcapracer '*.pcapng' -o out/ --tables flows,dns,tls --compression zstd
pcapracer capture.pcap -o out/ --threads 8
```

### Load the Parquet

```python
import polars as pl
flows = pl.read_parquet("out/capture.flows.parquet")
flows.filter(pl.col("dst_port") == 443).select(["src_ip", "tls_sni", "ja3", "ja4"])
```

```python
import duckdb
duckdb.sql("SELECT ja3, count(*) FROM 'out/*.tls.parquet' GROUP BY ja3 ORDER BY 2 DESC")
```

## Output tables

| Table     | Grain                      | Highlights |
|-----------|----------------------------|------------|
| `packets` | one row per packet         | frame, L2 (MAC/VLAN/MPLS), ARP, tunnels, IPv4/6, ICMP, TCP (+options)/UDP, payload entropy, inline app summary — 100+ columns |
| `flows`   | one row per bidirectional flow | CICFlowMeter-style stats: fwd/bwd packet & byte counts, packet-length and IAT min/max/mean/std, TCP flag counts, init windows, handshake RTT, active/idle periods, plus enrichment (app protocols, SNI, JA3/JA3S/JA4, DNS names, HTTP hosts, banners) — 95 features |
| `dns`     | one row per DNS message    | DNS/mDNS/LLMNR/NBNS: id, flags, opcode/rcode, question, answers (name/type/ttl/rdata as list columns) |
| `http`    | one row per HTTP/1.x message | method, URI, host, user-agent, status, server, content-type/length, header counts |
| `tls`     | one row per handshake message | ClientHello (SNI, ALPN, ciphers, extensions, groups, **JA3**, **JA4**), ServerHello (cipher, **JA3S**), Certificate (subject/issuer/validity/serial/SAN) |

Every selected table is always written, even when empty (a schema-valid, zero-row
Parquet file), so downstream globbing stays simple.

## Protocol coverage

**Link/tunnel:** Ethernet II, 802.1Q + QinQ VLAN, MPLS, Linux SLL/SLL2, Null/Loopback,
raw IP; GRE, VXLAN, IP-in-IP / 6in4 (recursive decapsulation — the innermost 5-tuple
wins the flow key; the outermost IPs are preserved).

**Network/transport:** ARP, IPv4, IPv6 (+ extension headers), ICMPv4, ICMPv6, TCP (with
MSS / window-scale / SACK / timestamp options), UDP, IGMP, SCTP.

**Application:** DNS / mDNS / LLMNR / NBNS, DHCP, NTP, QUIC (header), TLS
(ClientHello / ServerHello / Certificate), HTTP/1.x, SSH / FTP / SMTP / POP3 / IMAP
banners, SNMP, Modbus/TCP, TFTP, Syslog, SIP, SMB1/2/3 (dialect).

**Input formats:** classic pcap (all four magics — microsecond/nanosecond × little/big
endian), pcapng (multi-section, per-interface link type and timestamp resolution),
and gzip-compressed (`.pcap.gz`).

## Performance

Measured on a 4-core VM over a synthetic 1,000,000-packet (142 MB) mixed-traffic
capture, memory-mapped, snappy compression:

| Selection    | Throughput   | Notes |
|--------------|--------------|-------|
| `packets`    | ~0.8M pkts/s | wide 100+ column table (dominated by string formatting) |
| `flows`      | ~4.3M pkts/s | flow statistics only |
| all tables   | ~0.65M pkts/s | packets + flows + dns + http + tls |

Throughput scales with cores; set `threads=` (or `--threads`) to tune, or `0` for auto.
Reproduce with `python bench/make_bench_pcap.py && python bench/run_bench.py`.

## Notes & scope

- **JA4 licensing.** pcapracer implements JA3, JA3S, and the **JA4 TLS *client*
  fingerprint**, which is the BSD-licensed component of the JA4+ suite. The FoxIO
  non-commercial variants (JA4S/JA4H/JA4L/…) are intentionally not implemented.
- **CIC feature mapping.** Flow features follow CICFlowMeter conventions but drop its
  known-buggy bulk-rate and subflow features; `active_*` / `idle_*` are the honest
  replacements. Lengths are wire lengths; durations and IATs are in seconds.
- **Reassembly.** TCP application parsing uses lightweight in-order-only reassembly
  (default 8 KiB per direction), which is enough for multi-segment TLS ClientHellos
  (common with post-quantum key shares) and HTTP headers. Full stream reassembly, IP
  fragment reassembly, QUIC Initial decryption, and payload carving are out of scope
  for v1. Inline application columns in `packets` are best-effort; the per-protocol
  tables are authoritative.
- **Determinism.** `packets` rows preserve capture order. `flows` rows are emitted in
  close order — sort by `first_ts` for start order.

## Development

```bash
pip install maturin pytest pyarrow
maturin develop --release
pytest tests/
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

## License

MIT — see [LICENSE](LICENSE).
