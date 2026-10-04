"""Tests for feature engineering."""

from __future__ import annotations

from threatint.features import FEATURE_NAMES, FeatureExtractor, featurize
from threatint.models import Indicator, IndicatorType


def _indicator(value, itype, source_count=1, reliability=0.5):
    return Indicator(value=value, indicator_type=itype, source_count=source_count, reliability_score=reliability)


def test_feature_vector_has_stable_shape(config):
    extractor = FeatureExtractor(config)
    ind = _indicator("http://evil.xyz/login", IndicatorType.URL)
    features = extractor.extract(ind)
    assert list(features.keys()) == FEATURE_NAMES
    assert all(isinstance(v, float) for v in features.values())


def test_suspicious_tld_and_keyword_flags(config):
    extractor = FeatureExtractor(config)
    suspicious = extractor.extract(_indicator("http://secure-login.xyz/verify", IndicatorType.URL))
    benign = extractor.extract(_indicator("http://docs.example.org/index", IndicatorType.URL))
    assert suspicious["has_suspicious_tld"] == 1.0
    assert suspicious["suspicious_keyword_count"] >= 2
    assert benign["has_suspicious_tld"] == 0.0


def test_url_path_depth_and_port(config):
    extractor = FeatureExtractor(config)
    deep = extractor.extract(_indicator("http://evil.xyz/a/b/c", IndicatorType.URL))
    shallow = extractor.extract(_indicator("http://evil.xyz/", IndicatorType.URL))
    assert deep["path_depth"] > shallow["path_depth"]
    with_port = extractor.extract(_indicator("http://evil.xyz:8080/x", IndicatorType.URL))
    assert with_port["has_port"] == 1.0


def test_high_risk_port_detection(config):
    extractor = FeatureExtractor(config)
    risky = extractor.extract(_indicator("http://evil.xyz:4444/x", IndicatorType.URL))
    safe = extractor.extract(_indicator("http://evil.xyz:443/x", IndicatorType.URL))
    assert risky["port_high_risk"] == 1.0
    assert safe["port_high_risk"] == 0.0


def test_type_one_hot_is_exclusive(config):
    extractor = FeatureExtractor(config)
    for value, itype, key in [
        ("8.8.8.8", IndicatorType.IPV4, "is_ipv4"),
        ("evil.xyz", IndicatorType.DOMAIN, "is_domain"),
        ("http://evil.xyz/a", IndicatorType.URL, "is_url"),
        ("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.MD5, "is_hash"),
    ]:
        features = extractor.extract(_indicator(value, itype))
        assert features[key] == 1.0
        assert sum(features[k] for k in ("is_ipv4", "is_domain", "is_url", "is_hash")) == 1.0


def test_public_ip_flag(config):
    extractor = FeatureExtractor(config)
    public = extractor.extract(_indicator("8.8.8.8", IndicatorType.IPV4))
    private = extractor.extract(_indicator("192.168.0.1", IndicatorType.IPV4))
    assert public["is_public_ip"] == 1.0
    assert private["is_public_ip"] == 0.0


def test_featurize_attaches_features_in_place(config):
    indicators = [
        _indicator("8.8.8.8", IndicatorType.IPV4),
        _indicator("evil.xyz", IndicatorType.DOMAIN),
    ]
    featurize(indicators, config)
    for ind in indicators:
        assert set(ind.features.keys()) == set(FEATURE_NAMES)
