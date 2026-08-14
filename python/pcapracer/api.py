"""The user-facing pcapracer API.

Argument handling and defaults live here rather than in Rust: it keeps the FFI boundary
narrow, and it means the docstrings a user actually reads sit next to the signatures.
"""

from __future__ import annotations

import json
import os
import queue
import threading
from pathlib import Path
from typing import Any, Callable, Iterator

import pyarrow as pa

from . import _pcapracer

__all__ = [
    "to_parquet",
    "read_packets",
    "read_flows",
    "read",
    "iter_batches",
    "for_each_batch",
    "packet_schema_names",
    "protocol_tables",
]

# Defaults mirrored from the Rust side. Kept here so the Python signatures are
# self-documenting rather than forwarding sentinels.
DEFAULT_BATCH_SIZE = 65_536
DEFAULT_ROW_GROUP_ROWS = 128 * 1024
DEFAULT_MAX_FLOWS = 1 << 20
DEFAULT_MAX_STREAMS = 1 << 18
DEFAULT_MAX_STREAM_BYTES = 1 << 20

_MODES = ("wide", "split")
_COMPRESSIONS = ("zstd", "snappy", "lz4", "gzip", "none")


def _check(input_path: str | os.PathLike[str], mode: str, compression: str | None = None) -> str:
    path = os.fspath(input_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"capture not found: {path}")
    if mode not in _MODES:
        raise ValueError(f"mode must be one of {_MODES}, got {mode!r}")
    if compression is not None and compression not in _COMPRESSIONS:
        raise ValueError(f"compression must be one of {_COMPRESSIONS}, got {compression!r}")
    return path


def to_parquet(
    input_path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    *,
    mode: str = "wide",
    reassemble: bool = True,
    threads: int = 0,
    batch_size: int = DEFAULT_BATCH_SIZE,
    compression: str = "zstd",
    compression_level: int = 3,
    row_group_rows: int = DEFAULT_ROW_GROUP_ROWS,
    max_flows: int = DEFAULT_MAX_FLOWS,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> dict[str, Any]:
    """Extract a capture to Parquet files under ``out_dir``.

    Always writes ``packets.parquet``, ``flows.parquet`` and ``_meta.json``. In ``split``
    mode ``packets.parquet`` carries only the core columns and each protocol found gets its
    own file, joinable on ``packet_id``.

    Args:
        input_path: A ``.pcap``, ``.pcapng``, or gzip-compressed capture.
        out_dir: Created if it does not exist.
        mode: ``"wide"`` for one table with every column, ``"split"`` for per-protocol files.
        reassemble: Reassemble TCP streams so L7 fields split across segments are recovered.
            Turning this off is faster and uses less memory, at the cost of missing any
            application field that did not fit in a single segment.
        threads: 0 uses every core. Output is identical at any thread count.
        compression: One of zstd, snappy, lz4, gzip, none.

    Returns:
        A report dict with ``stats`` (packet/flow counts and what was dropped) and ``files``
        (each output file mapped to its row count).
    """
    path = _check(input_path, mode, compression)
    report = _pcapracer.extract_to_parquet(
        path,
        os.fspath(out_dir),
        mode,
        reassemble,
        threads,
        batch_size,
        compression,
        compression_level,
        row_group_rows,
        max_flows,
        max_streams,
        max_stream_bytes,
    )
    return json.loads(report)


def read(
    input_path: str | os.PathLike[str],
    *,
    mode: str = "wide",
    reassemble: bool = True,
    threads: int = 0,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_flows: int = DEFAULT_MAX_FLOWS,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> tuple[pa.Table, pa.Table, dict[str, Any]]:
    """Extract into memory. Returns ``(packets, flows, stats)``.

    Nothing is written to disk. Suitable when the capture fits comfortably in RAM; use
    :func:`iter_batches` otherwise.
    """
    path = _check(input_path, mode)
    batches, flows, stats = _pcapracer.extract_to_batches(
        path, mode, reassemble, threads, batch_size, max_flows, max_streams, max_stream_bytes
    )
    if batches:
        packets = pa.Table.from_batches(batches)
    else:
        # An empty capture still needs a table with the right schema so callers can filter
        # and concatenate without a special case.
        packets = pa.Table.from_batches([], schema=_empty_packet_schema())
    return packets, pa.Table.from_batches([flows]), json.loads(stats)


def read_packets(input_path: str | os.PathLike[str], **kwargs: Any) -> pa.Table:
    """The packet table for a capture, as a ``pyarrow.Table``."""
    return read(input_path, **kwargs)[0]


def read_flows(input_path: str | os.PathLike[str], **kwargs: Any) -> pa.Table:
    """The bidirectional flow table for a capture, as a ``pyarrow.Table``."""
    return read(input_path, **kwargs)[1]


def for_each_batch(
    input_path: str | os.PathLike[str],
    callback: Callable[[pa.RecordBatch], None],
    *,
    mode: str = "wide",
    reassemble: bool = True,
    threads: int = 0,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_flows: int = DEFAULT_MAX_FLOWS,
    max_streams: int = DEFAULT_MAX_STREAMS,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> dict[str, Any]:
    """Call ``callback`` with each packet batch as it is produced.

    Memory is bounded by ``batch_size``, not by the size of the capture. An exception raised
    by the callback stops the run and propagates with its traceback intact.
    """
    path = _check(input_path, mode)
    stats = _pcapracer.stream_batches(
        path,
        callback,
        mode,
        reassemble,
        threads,
        batch_size,
        max_flows,
        max_streams,
        max_stream_bytes,
    )
    return json.loads(stats)


_DONE = object()


def iter_batches(
    input_path: str | os.PathLike[str],
    *,
    queue_size: int = 4,
    **kwargs: Any,
) -> Iterator[pa.RecordBatch]:
    """Iterate packet batches lazily, with bounded memory.

    The extraction runs on a worker thread feeding a bounded queue, so at most
    ``queue_size`` batches are held at once no matter how large the capture is. Abandoning
    the iterator early stops the worker.
    """
    q: queue.Queue[Any] = queue.Queue(maxsize=max(1, queue_size))
    stop = threading.Event()

    class _Stop(Exception):
        """Raised inside the worker to unwind when the consumer goes away."""

    def _emit(batch: pa.RecordBatch) -> None:
        # Poll rather than block forever, so an abandoned iterator cannot wedge the worker
        # on a queue nobody is draining.
        while not stop.is_set():
            try:
                q.put(batch, timeout=0.1)
                return
            except queue.Full:
                continue
        raise _Stop

    def _worker() -> None:
        try:
            for_each_batch(input_path, _emit, **kwargs)
            q.put(_DONE)
        except _Stop:
            q.put(_DONE)
        except BaseException as exc:  # noqa: BLE001 - forwarded to the consumer verbatim
            q.put(exc)

    thread = threading.Thread(target=_worker, name="pcapracer-reader", daemon=True)
    thread.start()

    try:
        while True:
            item = q.get()
            if item is _DONE:
                return
            if isinstance(item, BaseException):
                raise item
            yield item
    finally:
        stop.set()
        thread.join(timeout=5.0)


def _empty_packet_schema() -> pa.Schema:
    # Built from the Rust column list so it cannot drift from the real schema. Types are not
    # reproduced here — an empty table only needs the field names to be usable for a concat.
    return pa.schema([pa.field(name, pa.null()) for name in _pcapracer.wide_field_names()])


def packet_schema_names() -> list[str]:
    """Every column in the wide packet schema, in order."""
    return _pcapracer.wide_field_names()


def protocol_tables() -> list[str]:
    """The per-protocol table names that ``split`` mode can produce."""
    return _pcapracer.protocol_table_names()
