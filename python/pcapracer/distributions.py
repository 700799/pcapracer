"""Statistical shape-fitting for extracted numeric fields.

The general idea — scan a field's values against a broad catalog of scipy's continuous
distributions and rank the candidates by goodness of fit — is the same one tools like
distfit and Fitter are built around. This is an independent implementation of that idea
against pcapracer's own schema, not a port of either: the candidate list is discovered from
the installed scipy rather than hand-copied, and fit quality is scored with a single
one-sample Kolmogorov-Smirnov test rather than a histogram-residual sum of squares.

Wired into the extraction pipeline (see api.to_parquet), this turns "what values does this
field take" into "what shape does this field take" — a heavy-tailed payload_entropy versus a
tight one, a bytes_total that looks lognormal versus one with a second mode, are the kind of
signal a raw column dump does not surface on its own.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from scipy import stats

__all__ = [
    "DEFAULT_PACKET_FIELDS",
    "DEFAULT_FLOW_FIELDS",
    "FitResult",
    "FieldFit",
    "fit_field",
    "fit_table",
    "fit_parquet_dir",
]

# Numeric columns worth characterizing by shape. Left out: identifiers, booleans, and raw
# port/type/enum codes — a distribution over those answers a question nobody is asking.
DEFAULT_PACKET_FIELDS: tuple[str, ...] = (
    "frame_len",
    "payload_len",
    "payload_entropy",
    "ip_ttl",
    "tcp_window",
    "tcp_payload_len",
    "udp_payload_len",
)
DEFAULT_FLOW_FIELDS: tuple[str, ...] = (
    "duration_sec",
    "packets_total",
    "bytes_total",
    "bytes_c2s",
    "bytes_s2c",
)

# Below this many finite samples, a "best fit" is noise wearing a distribution's name.
_MIN_SAMPLES = 8

# Distributions whose MLE fit is measured, not assumed, to be disproportionately slow: each
# one here took 10-30x the catalog median to fit a few hundred points in profiling (multi-
# parameter shapes with no closed-form MLE, so scipy falls back to a numerical optimizer that
# needs many likelihood evaluations — levy_stable and studentized_range are worse still, at
# multiple seconds each). Together the catalog's slowest ~15% of distributions accounted for
# ~70% of total fit time; excluding them keeps a field's fit within a second or two instead
# of tens of seconds, and still leaves close to the ~90 that were never the bottleneck.
_EXCLUDED_DISTRIBUTIONS = frozenset({
    "levy_stable", "studentized_range", "recipinvgauss", "nct", "genhyperbolic",
    "gausshyper", "kappa4", "tukeylambda", "vonmises_line", "ncx2", "ncf",
    "powerlognorm", "norminvgauss", "geninvgauss", "truncpareto", "genexpon", "johnsonsb",
})


def _candidate_distributions() -> list[Any]:
    """Every continuous distribution the installed scipy ships, minus the excluded few.

    Discovered rather than hand-copied, so this tracks whatever scipy version is installed
    instead of freezing a list that drifts from it — and lands at roughly the same
    ~90-distribution catalog other distribution-scanning tools scan.
    """
    names = stats._continuous_distns._distn_names  # type: ignore[attr-defined]
    return [getattr(stats, name) for name in names if name not in _EXCLUDED_DISTRIBUTIONS]


_DISTRIBUTIONS = _candidate_distributions()


@dataclass(frozen=True)
class FitResult:
    distribution: str
    params: tuple[float, ...]
    statistic: float
    pvalue: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "distribution": self.distribution,
            "params": list(self.params),
            "ks_statistic": self.statistic,
            "ks_pvalue": self.pvalue,
        }


@dataclass(frozen=True)
class FieldFit:
    field: str
    n: int
    best: FitResult | None
    top: tuple[FitResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "n": self.n,
            "best": self.best.to_dict() if self.best else None,
            "top": [r.to_dict() for r in self.top],
        }


def fit_field(
    data: np.ndarray,
    *,
    name: str = "",
    top: int = 5,
    sample_size: int = 2000,
    seed: int = 0,
) -> FieldFit | None:
    """Rank scipy's continuous distributions by one-sample KS fit to ``data``.

    Returns ``None`` if fewer than ``_MIN_SAMPLES`` finite values remain after dropping
    nulls/NaNs, or if every candidate distribution failed to fit. Above ``sample_size``,
    values are uniformly subsampled (never just truncated) with a seeded RNG, so a
    multi-million-row capture does not turn every field into a multi-minute MLE sweep, and
    results stay deterministic for a given capture and seed.
    """
    values = np.asarray(data, dtype=np.float64)
    values = values[np.isfinite(values)]
    n = values.size
    if n < _MIN_SAMPLES:
        return None

    if n > sample_size:
        rng = np.random.default_rng(seed)
        values = rng.choice(values, size=sample_size, replace=False)

    results: list[FitResult] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for dist in _DISTRIBUTIONS:
            try:
                params = dist.fit(values)
                statistic, pvalue = stats.kstest(values, dist.name, args=params)
            except Exception:  # noqa: BLE001 - one distribution failing to fit isn't fatal
                continue
            if not np.isfinite(statistic):
                continue
            results.append(
                FitResult(dist.name, tuple(float(p) for p in params), float(statistic), float(pvalue))
            )

    if not results:
        return None
    results.sort(key=lambda r: r.statistic)
    return FieldFit(field=name, n=n, best=results[0], top=tuple(results[:top]))


def fit_table(table: pa.Table, fields: Sequence[str], **kwargs: Any) -> dict[str, FieldFit]:
    """Fit every field in ``fields`` that is actually present in ``table``."""
    present = [f for f in fields if f in table.schema.names]
    out: dict[str, FieldFit] = {}
    for name in present:
        values = table.column(name).to_numpy(zero_copy_only=False)
        result = fit_field(values, name=name, **kwargs)
        if result is not None:
            out[name] = result
    return out


def fit_parquet_dir(
    out_dir: str | os.PathLike[str],
    *,
    packet_fields: Sequence[str] = DEFAULT_PACKET_FIELDS,
    flow_fields: Sequence[str] = DEFAULT_FLOW_FIELDS,
    top: int = 5,
    sample_size: int = 2000,
    seed: int = 0,
) -> dict[str, dict[str, Any]]:
    """Fit every configured field found in ``packets.parquet`` / ``flows.parquet``.

    Reads only the requested columns: a columnar Parquet read of a handful of numeric fields
    stays cheap even against a huge capture, unlike materializing the whole table. Fields
    absent from this run's schema (e.g. protocol fields in ``split`` mode's narrow
    ``packets.parquet``) are silently skipped rather than treated as an error.
    """
    out_path = Path(out_dir)
    results: dict[str, dict[str, Any]] = {}
    for filename, fields in (("packets.parquet", packet_fields), ("flows.parquet", flow_fields)):
        file_path = out_path / filename
        if not fields or not file_path.exists():
            continue
        schema_names = pq.ParquetFile(file_path).schema_arrow.names
        present = [f for f in fields if f in schema_names]
        if not present:
            continue
        table = pq.read_table(file_path, columns=present)
        table_key = filename.removesuffix(".parquet")
        for name, fit in fit_table(table, present, top=top, sample_size=sample_size, seed=seed).items():
            results[f"{table_key}.{name}"] = fit.to_dict()
    return results
