#!/usr/bin/env python3
"""Generate a synthetic mixed-traffic pcap for benchmarking.

Usage: python bench/make_bench_pcap.py [num_packets] [out.pcap]
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
import fixtures as fx  # noqa: E402
import tls_fixture as tf  # noqa: E402


def build(num: int, out_path: str) -> None:
    ch = tf.build_client_hello("bench.example.com")[0]
    http_req = b"GET /index.html HTTP/1.1\r\nHost: bench.example\r\nUser-Agent: bench/1.0\r\n\r\n"
    dns_q = fx.dns_query("bench.example.com", qtype=1)

    # Pre-build representative frames; vary addresses per flow to exercise the map.
    templates = []
    for i in range(256):
        a = f"10.0.{i % 256}.{(i * 7) % 256}"
        b = f"93.184.{i % 256}.{(i * 13) % 256}"
        sp = 20000 + (i % 20000)
        # 70% TCP data, 10% handshake, 10% DNS, 5% TLS, 5% ICMP
        templates.append(fx.eth(fx.ipv4(fx.tcp(b"x" * 200, sport=sp, dport=80, flags=0x18),
                                        src=a, dst=b)))
        templates.append(fx.eth(fx.ipv4(fx.tcp(b"", sport=sp, dport=80, flags=0x02), src=a, dst=b)))
        templates.append(fx.eth(fx.ipv4(fx.udp(dns_q, sport=sp, dport=53), src=a, dst=b, proto=17)))
        templates.append(fx.eth(fx.ipv4(fx.tcp(ch, sport=sp, dport=443, flags=0x18), src=a, dst=b)))
        templates.append(fx.eth(fx.ipv4(fx.tcp(http_req, sport=sp, dport=80, flags=0x18),
                                        src=a, dst=b)))
        templates.append(fx.eth(fx.ipv4(fx.icmp_echo(ident=i, seq=1), proto=1, src=a, dst=b)))

    magic = 0xA1B2C3D4
    with open(out_path, "wb") as f:
        f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 262144, 1))
        ts = 1_700_000_000
        subsec = 0
        written = 0
        buf = bytearray()
        n_templates = len(templates)
        while written < num:
            pkt = templates[written % n_templates]
            subsec += 100
            if subsec >= 1_000_000:
                subsec = 0
                ts += 1
            buf += struct.pack("<IIII", ts, subsec, len(pkt), len(pkt))
            buf += pkt
            written += 1
            if len(buf) > 8_000_000:
                f.write(buf)
                buf = bytearray()
        f.write(buf)

    size = os.path.getsize(out_path)
    print(f"wrote {num} packets ({size/1e6:.1f} MB) to {out_path}")


if __name__ == "__main__":
    num = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    out = sys.argv[2] if len(sys.argv) > 2 else "bench/bench.pcap"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    build(num, out)
