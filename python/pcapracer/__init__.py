"""pcapracer — fast PCAP feature extraction to Parquet, for cyber analysis.

    >>> import pcapracer
    >>> report = pcapracer.to_parquet("capture.pcap", "out/")
    >>> report["stats"]["packets"]
    120345

    >>> packets = pcapracer.read_packets("capture.pcap")
    >>> flows = pcapracer.read_flows("capture.pcap")
"""

from ._pcapracer import __version__
from .api import (
    for_each_batch,
    iter_batches,
    packet_schema_names,
    protocol_tables,
    read,
    read_flows,
    read_packets,
    to_parquet,
)

__all__ = [
    "__version__",
    "to_parquet",
    "read",
    "read_packets",
    "read_flows",
    "iter_batches",
    "for_each_batch",
    "packet_schema_names",
    "protocol_tables",
]
