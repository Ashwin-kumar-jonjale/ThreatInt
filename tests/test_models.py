"""Tests for the data models themselves."""

from __future__ import annotations

from datetime import datetime, timezone

from threatint.models import Campaign, Indicator, IndicatorType, Observation, Verdict


def test_indicator_id_is_stable_and_type_scoped():
    a = Indicator(value="8.8.8.8", indicator_type=IndicatorType.IPV4)
    b = Indicator(value="8.8.8.8", indicator_type=IndicatorType.IPV4)
    c = Indicator(value="8.8.8.8", indicator_type=IndicatorType.DOMAIN)
    assert a.indicator_id == b.indicator_id
    assert a.indicator_id != c.indicator_id


def test_indicator_sources_deduplicated():
    now = datetime.now(timezone.utc)
    ind = Indicator(value="8.8.8.8", indicator_type=IndicatorType.IPV4)
    ind.observations = [
        Observation(source="s1", indicator="8.8.8.8", indicator_type=IndicatorType.IPV4, observed_at=now),
        Observation(source="s1", indicator="8.8.8.8", indicator_type=IndicatorType.IPV4, observed_at=now),
        Observation(source="s2", indicator="8.8.8.8", indicator_type=IndicatorType.IPV4, observed_at=now),
    ]
    assert ind.sources == ["s1", "s2"]


def test_campaign_aggregates():
    campaign = Campaign(campaign_id="c1", label="campaign: test")
    campaign.indicators = [
        Indicator(value="a", indicator_type=IndicatorType.DOMAIN, reliability_score=0.8, malicious_probability=1.0),
        Indicator(value="b", indicator_type=IndicatorType.DOMAIN, reliability_score=0.6, malicious_probability=0.0),
    ]
    assert campaign.size == 2
    assert abs(campaign.mean_reliability - 0.7) < 1e-9
    assert abs(campaign.mean_malicious_probability - 0.5) < 1e-9


def test_indicator_to_dict_is_json_friendly():
    import json

    ind = Indicator(value="8.8.8.8", indicator_type=IndicatorType.IPV4, verdict=Verdict.MALICIOUS)
    ind.malicious_probability = 0.9
    payload = ind.to_dict()
    assert payload["verdict"] == "malicious"
    assert payload["indicator_type"] == "ipv4"
    json.dumps(payload)  # must not raise
