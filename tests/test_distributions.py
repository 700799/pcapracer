"""Tests for statistical distribution fitting."""

from __future__ import annotations

import json

import numpy as np
import pytest

import pcapracer
from pcapracer.distributions import FieldFit, FitResult, fit_field


def test_fit_field_ranks_by_ks_statistic_ascending():
    rng = np.random.default_rng(1234)
    data = rng.normal(loc=10.0, scale=2.0, size=500)

    result = fit_field(data, name="latency", top=5)

    assert isinstance(result, FieldFit)
    assert result.field == "latency"
    assert result.n == 500
    assert isinstance(result.best, FitResult)
    statistics = [r.statistic for r in result.top]
    assert statistics == sorted(statistics)
    assert result.best.statistic == statistics[0]
    for r in result.top:
        assert 0.0 <= r.statistic <= 1.0
        assert 0.0 <= r.pvalue <= 1.0


def test_fit_field_is_deterministic_when_subsampled():
    rng = np.random.default_rng(7)
    data = rng.exponential(scale=3.0, size=20_000)

    a = fit_field(data, sample_size=1000, seed=42)
    b = fit_field(data, sample_size=1000, seed=42)

    assert a.best.distribution == b.best.distribution
    assert a.best.statistic == b.best.statistic


def test_fit_field_too_few_samples_returns_none():
    assert fit_field(np.array([1.0, 2.0, 3.0])) is None


def test_fit_field_empty_returns_none():
    assert fit_field(np.array([])) is None


def test_fit_field_ignores_nan_and_inf():
    data = np.array([1.0, 2.0, np.nan, 3.0, np.inf, 2.5, 1.5, 2.2, 1.8, 2.1])
    result = fit_field(data)
    assert result is not None
    assert result.n == 8  # 10 values minus one nan and one inf


def test_fit_field_constant_data_does_not_raise():
    # Zero-variance input breaks the MLE for most distributions; every candidate should be
    # skipped cleanly rather than propagating a scipy exception.
    result = fit_field(np.full(50, 7.0))
    assert result is None or isinstance(result, FieldFit)


def test_field_fit_to_dict_is_json_serialisable():
    rng = np.random.default_rng(0)
    result = fit_field(rng.uniform(size=200), name="x")
    assert result is not None
    json.dumps(result.to_dict())  # must not raise


def test_to_parquet_writes_distributions_report(large_capture, tmp_path):
    out = tmp_path / "out"
    report = pcapracer.to_parquet(large_capture, out)

    assert (out / "_distributions.json").exists()
    on_disk = json.loads((out / "_distributions.json").read_text())
    assert on_disk == report["distributions"]

    frame_len = report["distributions"]["packets.frame_len"]
    assert frame_len["n"] >= 8
    assert frame_len["best"]["distribution"]
    assert 0.0 <= frame_len["best"]["ks_statistic"] <= 1.0


def test_fit_distributions_can_be_disabled(large_capture, tmp_path):
    out = tmp_path / "out"
    report = pcapracer.to_parquet(large_capture, out, fit_distributions=False)

    assert "distributions" not in report
    assert not (out / "_distributions.json").exists()


def test_distribution_fields_can_be_overridden(large_capture, tmp_path):
    out = tmp_path / "out"
    report = pcapracer.to_parquet(
        large_capture,
        out,
        distribution_fields={"packets": ["frame_len"], "flows": []},
    )

    assert set(report["distributions"]) == {"packets.frame_len"}


def test_missing_fields_are_skipped_not_errors(mixed_capture, tmp_path):
    out = tmp_path / "out"
    report = pcapracer.to_parquet(
        mixed_capture,
        out,
        distribution_fields={"packets": ["does_not_exist"], "flows": []},
    )
    assert report["distributions"] == {}
