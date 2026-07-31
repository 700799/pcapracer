"""Type stubs for the native pcapracer extension module."""

from os import PathLike
from typing import Any, Dict, List, Optional, Union

__version__: str

def extract_one(
    input: Union[str, PathLike],
    *,
    output_dir: Optional[Union[str, PathLike]] = ...,
    tables: Optional[List[str]] = ...,
    compression: str = ...,
    zstd_level: int = ...,
    idle_timeout: float = ...,
    active_threshold: float = ...,
    max_flows: int = ...,
    app_buffer_bytes: int = ...,
    hex_prefix_len: int = ...,
    threads: int = ...,
    batch_size: int = ...,
) -> Dict[str, Any]:
    """Extract features from a single capture file into Parquet tables.

    Returns a dict with keys: ``packets`` (int), ``decode_errors`` (int),
    ``elapsed_s`` (float), ``pkts_per_s`` (float), ``rows`` (dict of table -> row
    count), and ``paths`` (dict of table -> output path).
    """
    ...
