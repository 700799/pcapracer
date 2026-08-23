# pcapracer

Fast PCAP feature extraction to Parquet, written in Rust, built for cyber analysis.

`pcapracer` reads a capture, dissects it from Ethernet up through the application layer,
and writes the extracted features straight to Parquet. The parse loop never touches Python,
so the output lands in polars or DuckDB ready to query rather than needing to be reshaped
first.

```bash
pip install pcapracer
```

```python
import pcapracer

# Everything to Parquet
report = pcapracer.to_parquet("capture.pcap", "out/")
print(report["stats"]["packets"], "packets,", report["stats"]["flows"], "flows")

# Or straight into Arrow
packets = pcapracer.read_packets("capture.pcap")
flows = pcapracer.read_flows("capture.pcap")
```

```bash
pcapracer capture.pcap -o out/           # extract
pcapracer info capture.pcap              # protocol histogram, writes nothing
```

Then query it:

```python
import polars as pl

df = pl.read_parquet("out/packets.parquet")

# Long, high-entropy DNS names — the classic DGA / tunnelling shape
df.filter((pl.col("dns_qname_entropy") > 4.0) & (pl.col("dns_qname_len") > 50))

# Self-signed certificates on non-standard ports
df.filter(pl.col("tls_cert_self_signed") & (pl.col("dst_port") != 443))

# Every JA3 seen, by client
df.group_by("ip_src", "ja3").len().sort("len", descending=True)
```

## What it extracts

Over 250 columns per packet. No configuration — every field a dissector can find is
populated, and columns for protocols that were not present stay null (which costs almost
nothing on disk under ZSTD).

**Link** — Ethernet II, 802.1Q/QinQ, 802.3 LLC/SNAP, MPLS, PPPoE, ARP/RARP, Linux SLL/SLL2,
raw IP, 802.11 + RadioTap

**Network** — IPv4 with options and fragments, IPv6 with the full extension-header chain,
ICMP, ICMPv6/NDP, IGMP

**Transport** — TCP (flags, MSS, window scale, SACK, timestamps, option ordering), UDP,
UDP-Lite, SCTP with chunk types

**Tunnels** — GRE, VXLAN, Geneve, GTP-U, ERSPAN, IP-in-IP, L2TP, Teredo. Inner addressing
replaces the outer, which moves to `outer_ip_src` / `outer_ip_dst`.

**Application** — DNS/mDNS/LLMNR, HTTP/1.x, HTTP/2, TLS/DTLS (including certificate subject,
issuer, SANs and validity), QUIC, DHCPv4/v6, SMB1/SMB2 + NTLM, SSH, NTP, SNMP, SMTP, FTP,
IMAP, POP3, LDAP, Kerberos, RDP, MQTT, SIP, RTP/RTCP, RADIUS, Syslog, NetBIOS, TFTP, IRC,
Telnet, VNC, WireGuard, IPsec ESP/IKEv2

**ICS/OT** — Modbus/TCP, DNP3, S7comm, EtherNet/IP + CIP, IEC 60870-5-104, BACnet

**Fingerprints** — JA3, JA3S, JA4, JA4S, HASSH, HASSHServer, and Community ID on every flow

Application protocols are matched on their registered port first and by content signature
second, so HTTP on port 31337 is still labelled `http`.

## Output layout

Both modes write `flows.parquet` (bidirectional conversations with per-direction byte and
packet counts, TCP state, duration and Community ID) and `_meta.json` (counts, plus
everything the run had to drop).

**`mode="wide"`** (default) — `packets.parquet`, one row per packet with every column.
Simplest to query; no joins.

**`mode="split"`** — `packets.parquet` holds only core identity and addressing columns, and
each protocol found gets its own narrow file (`dns.parquet`, `tls.parquet`, …) joinable on
`packet_id`. Protocols absent from the capture produce no file at all.

## Field distributions

Every extraction also fits the numeric fields most worth characterizing by shape — packet
and payload lengths, TTL, TCP window, flow duration, byte counts — against scipy's catalog
of continuous distributions, ranks them by Kolmogorov-Smirnov statistic, and writes the
result to `_distributions.json`. The idea (scan a broad distribution catalog, rank
candidates by fit) is the same one tools like [distfit](https://github.com/erdogant/distfit)
and [Fitter](https://github.com/cokelaer/fitter) are built around; this is an independent
implementation against pcapracer's own schema, not a port of either.

```python
report = pcapracer.to_parquet("capture.pcap", "out/")
report["distributions"]["packets.payload_entropy"]["best"]
# {"distribution": "beta", "params": [...], "ks_statistic": 0.014, "ks_pvalue": 0.71}
```

Pass `fit_distributions=False` (or `--no-distributions` on the CLI) to skip it — it scans
dozens of candidate distributions per field, so it costs more time than the extraction
itself on very large captures. `distribution_fields={"packets": [...], "flows": [...]}`
overrides which columns get fit.

## Reassembly

TCP streams are reassembled by default, so an HTTP request split across segments still
yields its `Host` header. Reassembly is bounded — 1 MiB per stream and ~262k concurrent
streams by default — because a capture is untrusted input and unbounded buffering is a
memory-exhaustion bug waiting to happen. Anything dropped at those limits is counted in
`_meta.json` and warned about on stderr, never silently discarded.

IP fragments are reassembled the same way: a UDP or TCP payload split across IPv4/IPv6
fragments is stitched back together before L7 dissection, so a DNS answer or HTTP header
spread over several fragments is still recovered — fragmentation is a classic
analysis-evasion trick, so this closes a real blind spot. Fragment reassembly is bounded
too (per-datagram byte cap and a cap on concurrent fragment sets); overlapping fragments
resolve first-copy-wins, and a datagram with a missing fragment is dropped and counted in
`fragments_dropped` rather than half-parsed. `fragments_reassembled` reports how many
datagrams were recovered.

`reassemble=False` skips both TCP and IP reassembly entirely, which is faster and lighter
if you only need flow-level features.

## Threads

`threads=0` (the default) uses every core. Packets are dissected in parallel; flow
aggregation and reassembly run serially in capture order, because a stream's bytes only
mean anything in sequence.

**Output is byte-identical at any thread count.** Threads change how fast you get the
answer, never what the answer is — there is a test asserting exactly this.

## Streaming

`read_packets` materialises the whole capture. For files larger than memory:

```python
for batch in pcapracer.iter_batches("huge.pcapng", batch_size=100_000):
    ...  # a pyarrow.RecordBatch; memory stays bounded regardless of file size
```

## Notes on fidelity

A few deliberate limits, so you know what the null columns mean:

- **QUIC** — version, packet type and connection IDs are extracted. The Initial packet's
  payload is encrypted under a key derived from the connection ID, so `quic_sni` stays null
  rather than being guessed at.
- **HTTP/2** — framing, stream IDs and headers encoded against the static HPACK table are
  recovered. Huffman-coded and dynamic-table headers need connection state a single frame
  does not carry.
- **Certificates** — subject CN, issuer CN, SANs, serial and validity are parsed. This is
  not a full X.509 implementation, deliberately; those are the fields that get pivoted on.
- **LDAP simple bind** — the DN is recorded, the password is not.

Malformed packets are never fatal. Whatever layers parsed are emitted, with `malformed` set,
so a damaged capture still yields its intact packets. This holds even for a dissector *bug*:
each packet is dissected behind a panic boundary, so an unforeseen panic on a crafted packet
degrades that one row to its frame-level columns (with `panicked` set and counted in
`dissect_panics`) instead of taking down the run — a capture can never be a
denial-of-service against the tool.

## Development

```bash
cargo test --lib                 # Rust unit tests
maturin develop --release        # build into the active virtualenv
pytest tests -v                  # end-to-end tests
```

## License

MIT OR Apache-2.0, at your option.
