"""Tests for campaign clustering."""

from __future__ import annotations

from threatint.clustering import cluster_campaigns
from threatint.features import featurize
from threatint.models import Indicator, IndicatorType, Verdict


def _indicator(value, itype, tags, reliability=0.8, verdict=Verdict.MALICIOUS):
    ind = Indicator(value=value, indicator_type=itype, tags=list(tags), source_count=2, reliability_score=reliability)
    ind.verdict = verdict
    return ind


def test_related_indicators_cluster_together(config):
    indicators = [
        # Two phishing URLs sharing tags and lexical shape.
        _indicator("http://paypal-login1.xyz/verify", IndicatorType.URL, ["phishing", "credential"]),
        _indicator("http://paypal-login2.xyz/verify", IndicatorType.URL, ["phishing", "credential"]),
        # Two botnet IPs sharing tags.
        _indicator("185.220.101.34", IndicatorType.IPV4, ["botnet", "c2"]),
        _indicator("45.155.205.233", IndicatorType.IPV4, ["botnet", "c2"]),
    ]
    featurize(indicators, config)
    campaigns = cluster_campaigns(indicators, config)

    assert len(campaigns) == 2
    sizes = sorted(c.size for c in campaigns)
    assert sizes == [2, 2]
    # Every clustered indicator is stamped with a campaign id.
    assert all(i.campaign_id is not None for i in indicators)


def test_benign_indicators_are_not_clustered(config):
    indicators = [
        _indicator("http://paypal-login1.xyz/verify", IndicatorType.URL, ["phishing"], verdict=Verdict.BENIGN),
        _indicator("http://paypal-login2.xyz/verify", IndicatorType.URL, ["phishing"], verdict=Verdict.BENIGN),
    ]
    featurize(indicators, config)
    campaigns = cluster_campaigns(indicators, config)
    assert campaigns == []
    assert all(i.campaign_id is None for i in indicators)


def test_low_reliability_indicators_excluded(config):
    indicators = [
        _indicator("http://a1.xyz/verify", IndicatorType.URL, ["phishing"], reliability=0.1),
        _indicator("http://a2.xyz/verify", IndicatorType.URL, ["phishing"], reliability=0.1),
    ]
    featurize(indicators, config)
    campaigns = cluster_campaigns(indicators, config)
    assert campaigns == []


def test_campaign_id_is_stable(config):
    indicators = [
        _indicator("http://stable1.xyz/verify", IndicatorType.URL, ["phishing"]),
        _indicator("http://stable2.xyz/verify", IndicatorType.URL, ["phishing"]),
    ]
    featurize(indicators, config)
    first = cluster_campaigns(indicators, config)[0].campaign_id

    indicators2 = [
        _indicator("http://stable2.xyz/verify", IndicatorType.URL, ["phishing"]),
        _indicator("http://stable1.xyz/verify", IndicatorType.URL, ["phishing"]),
    ]
    featurize(indicators2, config)
    second = cluster_campaigns(indicators2, config)[0].campaign_id
    assert first == second


def test_too_few_indicators_returns_empty(config):
    indicators = [_indicator("http://solo.xyz/verify", IndicatorType.URL, ["phishing"])]
    featurize(indicators, config)
    assert cluster_campaigns(indicators, config) == []
