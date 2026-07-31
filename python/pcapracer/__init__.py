"""pcapracer — fast PCAP/pcapng feature extraction to Parquet, powered by Rust.

Extracts packet-level fields, bidirectional flow features, and application-layer
records (DNS, HTTP, TLS with JA3/JA4) into Parquet tables for cyber analysis.
"""

from ._pcapracer import __version__

__all__ = ["__version__"]
