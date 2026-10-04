"""Tests for cross-verification and source reliability scoring."""

from __future__ import annotations

from threatint.models import IndicatorType, Observation
from threatint.verification import build_indicators, compute_source_reliability, score_indicator


def _obs(source, value, itype=IndicatorType.IPV4, confidence=0.8, tags=None):
    return Observation(source=source, indicator=value, indicator_type=itype, confidence=confidence, tags=tags or [])


def test_consensus_requires_multiple_sources(config):
    observations = [
        _obs("s1", "1.1.1.1"),
        _obs("s2", "1.1.1.1"),
        _obs("s3", "1.1.1.1"),
        _obs("s1", "2.2.2.2"),
    ]
    rel = compute_source_reliability(observations, config)
    # s2/s3 only ever report the consensus indicator -> perfect precision.
    assert rel["s2"].precision == 1.0
    assert rel["s3"].precision == 1.0
    # s1 reports a non-consensus indicator too -> lower precision.
    assert rel["s1"].precision < 1.0


def test_recall_reflects_coverage_of_consensus(config):
    observations = [
        _obs("s1", "1.1.1.1"),
        _obs("s2", "1.1.1.1"),
        _obs("s2", "3.3.3.3"),
        _obs("s3", "3.3.3.3"),
    ]
    rel = compute_source_reliability(observations, config)
    # Both 1.1.1.1 and 3.3.3.3 are consensus; s2 covers both.
    assert rel["s2"].recall == 1.0
    assert rel["s1"].recall == 0.5


def test_agreement_is_higher_for_overlapping_sources(config):
    observations = [
        _obs("a", "1.1.1.1"),
        _obs("a", "2.2.2.2"),
        _obs("b", "1.1.1.1"),
        _obs("b", "2.2.2.2"),
        _obs("c", "9.9.9.9"),
    ]
    rel = compute_source_reliability(observations, config)
    assert rel["a"].agreement > rel["c"].agreement


def test_score_indicator_bonuses_corroboration(config):
    reliabilities = compute_source_reliability(
        [_obs("s1", "1.1.1.1"), _obs("s2", "1.1.1.1"), _obs("s1", "9.9.9.9")],
        config,
    )
    single = score_indicator([_obs("s1", "9.9.9.9")], reliabilities, config)
    multi = score_indicator([_obs("s1", "1.1.1.1"), _obs("s2", "1.1.1.1")], reliabilities, config)
    assert multi > single


def test_build_indicators_deduplicates_and_aggregates(config):
    observations = [
        _obs("s1", "1.1.1.1", confidence=0.9, tags=["c2"]),
        _obs("s2", "1.1.1.1", confidence=0.7, tags=["botnet"]),
        _obs("s1", "evil.xyz", itype=IndicatorType.DOMAIN),
    ]
    rel = compute_source_reliability(observations, config)
    indicators = build_indicators(observations, rel, config)
    by_value = {i.value: i for i in indicators}

    ip = by_value["1.1.1.1"]
    assert ip.source_count == 2
    assert set(ip.sources) == {"s1", "s2"}
    assert set(ip.tags) == {"c2", "botnet"}
    assert len(indicators) == 2


def test_reliability_scores_are_bounded(config):
    observations = [_obs(f"s{i}", "1.1.1.1") for i in range(6)]
    rel = compute_source_reliability(observations, config)
    for source_rel in rel.values():
        assert 0.0 <= source_rel.score <= 1.0
        assert 0.0 <= source_rel.precision <= 1.0
        assert 0.0 <= source_rel.recall <= 1.0
