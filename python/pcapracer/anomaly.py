"""Unsupervised anomaly scoring for pcapracer tables.

Fits a small probabilistic density model over the extracted feature columns —
with **no labels and no training set** — and scores each row by how *improbable*
it is: low density = unusual = worth an analyst's attention. Each score comes
with a short reason naming the fields that drove it.

The approach (heterogeneous unsupervised density + per-field explanation) is a
classic mixture-model idea, implemented here from scratch on top of NumPy — this
module has no dependency beyond ``numpy`` and ``pyarrow`` (the ``[anomaly]``
extra) and keeps the pcapracer core import dependency-free.

    import pcapracer
    scored = pcapracer.rank_anomalies("out/", table="flows", top=20)
    print(scored.select(["src_ip", "dst_ip", "anomaly_score", "anomaly_reason"]))

This is an unsupervised statistical baseline: it flags outliers, not "malice".
"""

from __future__ import annotations

import math
import os
from typing import List, Optional, Sequence, Tuple, Union

_INSTALL_HINT = (
    "pcapracer anomaly scoring needs numpy and pyarrow. "
    "Install them with:  pip install 'pcapracer[anomaly]'"
)

try:
    import numpy as np
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.parquet as pq
except ImportError as exc:  # pragma: no cover - exercised via install matrix
    raise ImportError(_INSTALL_HINT) from exc

PathLike = Union[str, "os.PathLike[str]"]

# Columns that identify a row rather than describe its behaviour — never features.
_EXCLUDE = frozenset(
    {
        "pkt_id",
        "flow_id",
        "iface_id",
        "ts",
        "first_ts",
        "last_ts",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "outer_src_ip",
        "outer_dst_ip",
        "eth_src",
        "eth_dst",
        "arp_sender_ip",
        "arp_target_ip",
        "arp_sender_mac",
        "arp_target_mac",
        # high-cardinality / free-text application fields
        "ja3",
        "ja3s",
        "ja4",
        "ja3_raw",
        "ja3s_raw",
        "tls_sni",
        "sni",
        "dns_qname",
        "dns_qnames",
        "qname",
        "http_host",
        "http_hosts",
        "http_uri",
        "uri",
        "http_user_agent",
        "user_agent",
        "http_methods",
        "referer",
        "location",
        "server",
        "client_banner",
        "server_banner",
        "banner",
        "app_protos",
        "app_proto",
        "quic_dcid",
        "payload_hex_prefix",
        "snmp_community",
        "sip_uri",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_san",
        "tunnel_stack",
        "ipv6_ext_headers",
    }
)

_MAX_CARDINALITY = 32
_MIN_ROWS_FOR_MIXTURE = 20
_LOG2PI = math.log(2.0 * math.pi)


def _logsumexp(a: "np.ndarray", axis: int) -> "np.ndarray":
    m = np.max(a, axis=axis, keepdims=True)
    m = np.where(np.isfinite(m), m, 0.0)
    return (m + np.log(np.sum(np.exp(a - m), axis=axis, keepdims=True))).squeeze(axis)


class _GaussianMixture:
    """Diagonal-covariance Gaussian mixture fit by EM, with BIC model selection."""

    def __init__(self, weights, means, variances):
        self.weights = weights  # [K]
        self.means = means  # [K, D]
        self.variances = variances  # [K, D]

    @property
    def n_components(self) -> int:
        return self.means.shape[0]

    def _component_logpdf(self, x: "np.ndarray") -> "np.ndarray":
        """Per-component log-density, [n, K]. Loops over K (K is tiny)."""
        n, d = x.shape
        k = self.means.shape[0]
        out = np.empty((n, k))
        for j in range(k):
            diff = x - self.means[j]
            out[:, j] = -0.5 * (
                d * _LOG2PI
                + np.sum(np.log(self.variances[j]) + diff * diff / self.variances[j], axis=1)
            )
        return out

    def log_density(self, x: "np.ndarray") -> "np.ndarray":
        logp = self._component_logpdf(x) + np.log(self.weights)[None, :]
        return _logsumexp(logp, axis=1)


def _fit_em(x: "np.ndarray", k: int, rng, iters: int = 100, tol: float = 1e-4):
    n, d = x.shape
    idx = rng.choice(n, size=k, replace=False)
    means = x[idx].copy()
    global_var = np.maximum(x.var(axis=0), 1e-6)
    variances = np.tile(global_var, (k, 1))
    weights = np.full(k, 1.0 / k)
    prev = -np.inf
    for _ in range(iters):
        model = _GaussianMixture(weights, means, variances)
        logp = model._component_logpdf(x) + np.log(weights)[None, :]
        row_ll = _logsumexp(logp, axis=1)
        loglik = float(row_ll.sum())
        resp = np.exp(logp - row_ll[:, None])
        nk = resp.sum(axis=0) + 1e-12
        weights = nk / n
        means = (resp.T @ x) / nk[:, None]
        for j in range(k):
            diff = x - means[j]
            variances[j] = np.maximum((resp[:, j][:, None] * diff * diff).sum(axis=0) / nk[j], 1e-6)
        if loglik - prev < tol * (abs(prev) + 1e-9):
            break
        prev = loglik
    model = _GaussianMixture(weights, means, variances)
    loglik = float(model.log_density(x).sum())
    return model, loglik


def _fit_mixture(x: "np.ndarray", max_components: int, seed: int) -> _GaussianMixture:
    """Fit a GMM, choosing the component count by BIC (lower is better)."""
    n, d = x.shape
    k_max = 1 if n < _MIN_ROWS_FOR_MIXTURE else max(1, max_components)
    k_max = min(k_max, max(1, n // 4))
    best: Optional[_GaussianMixture] = None
    best_bic = np.inf
    for k in range(1, k_max + 1):
        for restart in range(3 if k > 1 else 1):
            rng = np.random.default_rng(seed + 1009 * k + restart)
            try:
                model, loglik = _fit_em(x, k, rng)
            except (ValueError, FloatingPointError):
                continue
            n_params = k * (2 * d) + (k - 1)
            bic = -2.0 * loglik + n_params * math.log(max(n, 2))
            if bic < best_bic:
                best_bic, best = bic, model
    if best is None:  # degenerate fallback: single component from global stats
        best = _GaussianMixture(
            np.array([1.0]),
            x.mean(axis=0, keepdims=True),
            np.maximum(x.var(axis=0, keepdims=True), 1e-6),
        )
    return best


def _load_table(source: Union[PathLike, "pa.Table"], table: str) -> "pa.Table":
    if isinstance(source, pa.Table):
        return source
    path = os.fspath(source)
    if os.path.isdir(path):
        import glob

        matches = sorted(glob.glob(os.path.join(path, f"*.{table}.parquet")))
        if not matches:
            raise FileNotFoundError(f"no *.{table}.parquet under {path!r}")
        tables = [pq.read_table(m) for m in matches]
        return pa.concat_tables(tables) if len(tables) > 1 else tables[0]
    return pq.read_table(path)


def _select_features(
    tbl: "pa.Table", features: Optional[Sequence[str]]
) -> Tuple[List[str], List[str]]:
    numeric: List[str] = []
    categorical: List[str] = []
    for field in tbl.schema:
        name = field.name
        if features is not None:
            if name not in features:
                continue
        elif name in _EXCLUDE:
            continue
        t = field.type
        if pa.types.is_floating(t) or pa.types.is_integer(t):
            col = tbl[name]
            # need at least some non-null variation
            if col.null_count == len(col):
                continue
            numeric.append(name)
        elif pa.types.is_boolean(t):
            categorical.append(name)
        elif pa.types.is_string(t) or pa.types.is_large_string(t):
            n_distinct = pc.count_distinct(tbl[name], mode="only_valid").as_py()
            if 1 < n_distinct <= _MAX_CARDINALITY:
                categorical.append(name)
    return numeric, categorical


def _prepare_numeric(tbl: "pa.Table", cols: List[str]) -> Tuple["np.ndarray", List[str]]:
    """Return a robustly standardized matrix and the columns actually kept."""
    kept: List[str] = []
    columns = []
    for name in cols:
        arr = tbl[name].cast(pa.float64()).to_numpy(zero_copy_only=False)
        arr = np.asarray(arr, dtype=np.float64)
        finite = arr[np.isfinite(arr)]
        if finite.size == 0:
            continue
        median = float(np.median(finite))
        arr = np.where(np.isfinite(arr), arr, median)
        mad = float(np.median(np.abs(arr - median)))
        scale = 1.4826 * mad
        if scale <= 1e-12:
            scale = float(arr.std())
        if scale <= 1e-12:
            continue  # constant column carries no signal
        columns.append((arr - median) / scale)
        kept.append(name)
    if not kept:
        return np.empty((tbl.num_rows, 0)), []
    return np.column_stack(columns), kept


def _categorical_logprob(
    tbl: "pa.Table", cols: List[str]
) -> Tuple["np.ndarray", List[str]]:
    """Per-row, per-column log-probability under a smoothed frequency model."""
    n = tbl.num_rows
    kept: List[str] = []
    columns = []
    alpha = 0.5
    for name in cols:
        if pa.types.is_boolean(tbl.schema.field(name).type):
            values = ["true" if v else ("∅" if v is None else "false") for v in tbl[name].to_pylist()]
        else:
            values = [v if v is not None else "∅" for v in tbl[name].to_pylist()]
        counts: dict = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        n_cats = len(counts)
        denom = n + alpha * n_cats
        logp_of = {v: math.log((c + alpha) / denom) for v, c in counts.items()}
        columns.append(np.array([logp_of[v] for v in values], dtype=np.float64))
        kept.append(name)
    if not kept:
        return np.empty((n, 0)), []
    return np.column_stack(columns), kept


def _robust_z(a: "np.ndarray", axis: int = 0) -> "np.ndarray":
    """Median/MAD standardization (falls back to std, then to no-op)."""
    med = np.median(a, axis=axis, keepdims=True)
    mad = np.median(np.abs(a - med), axis=axis, keepdims=True)
    scale = 1.4826 * mad
    flat = scale <= 1e-12
    if np.any(flat):
        std = np.std(a, axis=axis, keepdims=True)
        scale = np.where(flat, std, scale)
    scale = np.where(scale <= 1e-12, 1.0, scale)
    return (a - med) / scale


def _reasons(contrib: "np.ndarray", names: List[str], top: int = 3, thresh: float = 1.0) -> List[str]:
    """Name the fields whose contribution is unusually low *for this row*.

    Each column is standardized across rows, so heterogeneous fields compare
    fairly; a field is reported only if it is at least ``thresh`` robust SDs below
    its own typical contribution.
    """
    if contrib.shape[1] == 0:
        return [""] * contrib.shape[0]
    dev = _robust_z(contrib, axis=0)  # negative = unusually improbable here
    order = np.argsort(dev, axis=1)  # ascending -> most negative first
    reasons = []
    for i in range(contrib.shape[0]):
        picks = [names[j] for j in order[i, :top] if dev[i, j] < -thresh]
        reasons.append(", ".join(picks))
    return reasons


def score_table(
    source: Union[PathLike, "pa.Table"],
    *,
    table: str = "flows",
    features: Optional[Sequence[str]] = None,
    max_components: int = 6,
    seed: int = 0,
) -> "pa.Table":
    """Score every row of a pcapracer table by how anomalous it is.

    Returns the input table with three added columns:

    - ``anomaly_score`` (float64): higher = more anomalous (= negative log-density).
    - ``anomaly_rank`` (uint32): 1 = most anomalous.
    - ``anomaly_reason`` (string): up to three fields that drove the score.
    """
    tbl = _load_table(source, table)
    n = tbl.num_rows
    if n == 0:
        empty_f = pa.array([], type=pa.float64())
        empty_u = pa.array([], type=pa.uint32())
        empty_s = pa.array([], type=pa.string())
        return (
            tbl.append_column("anomaly_score", empty_f)
            .append_column("anomaly_rank", empty_u)
            .append_column("anomaly_reason", empty_s)
        )

    num_cols, cat_cols = _select_features(tbl, features)
    x, num_kept = _prepare_numeric(tbl, num_cols)
    cat_contrib, cat_kept = _categorical_logprob(tbl, cat_cols)
    if not num_kept and not cat_kept:
        raise ValueError(
            "no usable feature columns found to score "
            f"(table={table!r}); pass explicit `features=`"
        )

    total_logdensity = np.zeros(n, dtype=np.float64)
    contrib_blocks = []
    contrib_names: List[str] = []

    if num_kept:
        gmm = _fit_mixture(x, max_components, seed)
        # Score with the full mixture (captures multimodal "normal")...
        total_logdensity += gmm.log_density(x)
        # ...but explain with the population-level per-feature deviation, so an
        # outlier that formed its own mixture component isn't "explained away".
        contrib_blocks.append(-0.5 * x * x)
        contrib_names.extend(num_kept)
    if cat_kept:
        total_logdensity += cat_contrib.sum(axis=1)
        contrib_blocks.append(cat_contrib)
        contrib_names.extend(cat_kept)

    contrib = np.concatenate(contrib_blocks, axis=1) if contrib_blocks else np.empty((n, 0))

    # Robust-z of the negative log-density: ~0 is typical, positive is anomalous,
    # and the scale is comparable across captures. Ranking is unchanged.
    score = _robust_z(-total_logdensity[:, None], axis=0)[:, 0]

    order = np.argsort(-score, kind="stable")
    rank = np.empty(n, dtype=np.uint32)
    rank[order] = np.arange(1, n + 1, dtype=np.uint32)
    reasons = _reasons(contrib, contrib_names)

    return (
        tbl.append_column("anomaly_score", pa.array(score, type=pa.float64()))
        .append_column("anomaly_rank", pa.array(rank, type=pa.uint32()))
        .append_column("anomaly_reason", pa.array(reasons, type=pa.string()))
    )


def rank_anomalies(
    source: Union[PathLike, "pa.Table"],
    *,
    table: str = "flows",
    top: int = 50,
    **kwargs,
) -> "pa.Table":
    """Score, then return the ``top`` most anomalous rows, most-anomalous first."""
    scored = score_table(source, table=table, **kwargs)
    if scored.num_rows == 0:
        return scored
    idx = pc.sort_indices(scored, sort_keys=[("anomaly_score", "descending")])
    return scored.take(idx[: min(top, scored.num_rows)])
