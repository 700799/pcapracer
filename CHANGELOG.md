# Changelog

## 0.1.0 (unreleased)

Initial release.

- pcap, pcapng and gzipped input (all four legacy magics, per-interface pcapng metadata)
- Link layers: Ethernet II, 802.1Q VLAN (incl. QinQ), MPLS, Linux SLL/SLL2, Null/Loopback, raw IP
- Network/transport: ARP, IPv4, IPv6 (+ extension headers), ICMPv4, ICMPv6, TCP (with option parsing), UDP
- Tunnels: GRE, VXLAN, IP-in-IP / 6in4 (recursive decapsulation, depth-capped)
- Application: DNS/mDNS/LLMNR/NBNS, DHCP, NTP, QUIC (header), TLS (ClientHello/ServerHello/Certificate),
  HTTP/1.x, SSH/FTP/SMTP/POP3/IMAP banners
- TLS fingerprints: JA3, JA3S, JA4 (TLS client)
- Parquet outputs: `packets`, `flows` (bidirectional CIC-style features), `dns`, `http`, `tls`
- Parallel, zero-copy pipeline; snappy/zstd compression
