# Changelog

## 0.1.0 (unreleased)

Initial release.

- **Input:** pcap (all four legacy magics), pcapng (multi-section, per-interface
  link type and timestamp resolution/offset), and gzip-compressed input.
- **Link/tunnel:** Ethernet II, 802.1Q VLAN (incl. QinQ), MPLS, Linux SLL/SLL2,
  Null/Loopback, raw IP; GRE, VXLAN, IP-in-IP / 6in4 (recursive, depth-capped).
- **Network/transport:** ARP, IPv4, IPv6 (+ extension headers), ICMPv4, ICMPv6,
  TCP (with option parsing), UDP, IGMP, SCTP.
- **Application:** DNS/mDNS/LLMNR/NBNS, DHCP, NTP, QUIC (header), TLS
  (ClientHello/ServerHello/Certificate), HTTP/1.x, SSH/FTP/SMTP/POP3/IMAP banners,
  SNMP, Modbus/TCP, TFTP, Syslog, SIP, SMB1/2/3 (dialect).
- **TLS fingerprints:** JA3, JA3S, JA4 (TLS client).
- **Outputs:** `packets`, `flows` (bidirectional CIC-style features), `dns`, `http`,
  `tls` Parquet tables; snappy (default) or zstd compression.
- **Engine:** memory-mapped zero-copy reading, multi-threaded decode with an
  ordered collector, bounded memory, no-panic guarantee on malformed input.
- Zero-dependency wheels (abi3, CPython ≥ 3.10) for Linux/macOS/Windows.

### Publishing (maintainers)

Releases are built and published by `.github/workflows/release.yml` on a `v*` tag via
PyPI Trusted Publishing. One-time setup: on PyPI, add a pending publisher for this
repository, workflow `release.yml`, environment `pypi`. Then `git tag v0.1.0 &&
git push origin v0.1.0`.
