"""Type stubs for the compiled extension.

These mirror the PyO3 signatures in ``rust/src/python.rs``. The extension is an internal
boundary — user-facing types live on the wrappers in ``api.py``.
"""

from typing import Any, Callable

__version__: str

def extract_to_parquet(
    input: str,
    out_dir: str,
    mode: str,
    reassemble: bool,
    threads: int,
    batch_size: int,
    compression: str,
    compression_level: int,
    row_group_rows: int,
    max_flows: int,
    max_streams: int,
    max_stream_bytes: int,
) -> str:
    """Returns the run report as a JSON string."""

def extract_to_batches(
    input: str,
    mode: str,
    reassemble: bool,
    threads: int,
    batch_size: int,
    max_flows: int,
    max_streams: int,
    max_stream_bytes: int,
) -> tuple[list[Any], Any, str]:
    """Returns ``(packet_batches, flow_batch, stats_json)``."""

def stream_batches(
    input: str,
    callback: Callable[[Any], None],
    mode: str,
    reassemble: bool,
    threads: int,
    batch_size: int,
    max_flows: int,
    max_streams: int,
    max_stream_bytes: int,
) -> str:
    """Returns the run stats as a JSON string."""

def wide_field_names() -> list[str]: ...
def protocol_table_names() -> list[str]: ...
def version() -> str: ...
