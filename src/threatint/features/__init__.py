"""Feature engineering for indicators.

Produces a fixed-order numeric vector per indicator so the same
representation feeds both the classifier and the clustering stage. Features
are intentionally interpretable: lexical structure, entropy, suspicious
tokens, and the cross-source trust signals computed earlier.
"""

from __future__ import annotations

import ipaddress
import math

from collections import Counter
from typing import Dict, List, Sequence
from urllib.parse import urlsplit

from threatint.config import Config
from threatint.models import Indicator, IndicatorType

FEATURE_NAMES: List[str] = [
    "is_ipv4",
    "is_domain",
    "is_url",
    "is_hash",
    "length",
    "digit_ratio",
    "alpha_ratio",
    "entropy",
    "dot_count",
    "hyphen_count",
    "has_suspicious_tld",
    "suspicious_keyword_count",
    "is_https",
    "path_depth",
    "has_port",
    "port_high_risk",
    "is_public_ip",
    "source_count",
    "reliability_score",
    "tag_count",
    "age_days",
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _ratio(text: str, predicate) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if predicate(ch)) / len(text)


def _host_of(value: str) -> str:
    if "://" in value:
        return urlsplit(value).hostname or value
    return value


def _tld_of(host: str) -> str:
    host = host.lower().strip(".")
    if not host or "." not in host:
        return ""
    return host.rsplit(".", 1)[-1]


class FeatureExtractor:
    """Stateless-ish extractor holding the configured suspicious token sets."""

    def __init__(self, config: Config):
        self.config = config
        self.suspicious_tlds = {str(t).lower() for t in config.features.get("suspicious_tlds", [])}
        self.suspicious_keywords = [str(k).lower() for k in config.features.get("suspicious_keywords", [])]
        self.high_risk_ports = {int(p) for p in config.features.get("high_risk_ports", []) if str(p).strip()}

    def extract(self, indicator: Indicator) -> Dict[str, float]:
        value = indicator.value
        host = _host_of(value)
        itype = indicator.indicator_type

        is_ip = 1.0 if itype is IndicatorType.IPV4 else 0.0
        is_domain = 1.0 if itype is IndicatorType.DOMAIN else 0.0
        is_url = 1.0 if itype is IndicatorType.URL else 0.0
        is_hash = 1.0 if itype in (IndicatorType.MD5, IndicatorType.SHA256) else 0.0

        length = float(len(value))
        digit_ratio = _ratio(value, str.isdigit)
        alpha_ratio = _ratio(value, str.isalpha)
        entropy = _entropy(value)
        dot_count = float(value.count("."))
        hyphen_count = float(value.count("-"))

        tld = _tld_of(host)
        has_suspicious_tld = 1.0 if tld in self.suspicious_tlds else 0.0
        lowered = value.lower()
        suspicious_keyword_count = float(sum(1 for kw in self.suspicious_keywords if kw in lowered))

        is_https = 1.0 if value.lower().startswith("https://") else 0.0

        if is_url:
            parts = urlsplit(value)
            path = parts.path or "/"
            path_depth = float(len([seg for seg in path.split("/") if seg]))
            has_port = 1.0 if parts.port else 0.0
            port = parts.port
        else:
            path_depth = 0.0
            has_port = 0.0
            port = None

        port_high_risk = 0.0
        if port is not None and port in self.high_risk_ports:
            port_high_risk = 1.0
        elif is_ip and ":" in value:
            try:
                p = int(value.split(":")[-1])
                port_high_risk = 1.0 if p in self.high_risk_ports else 0.0
            except ValueError:
                port_high_risk = 0.0

        is_public_ip = 0.0
        if is_ip:
            try:
                is_public_ip = 1.0 if ipaddress.ip_address(value).is_global else 0.0
            except ValueError:
                is_public_ip = 0.0

        age_days = max(0.0, (indicator.last_seen - indicator.first_seen).total_seconds() / 86400.0)

        return {
            "is_ipv4": is_ip,
            "is_domain": is_domain,
            "is_url": is_url,
            "is_hash": is_hash,
            "length": length,
            "digit_ratio": digit_ratio,
            "alpha_ratio": alpha_ratio,
            "entropy": entropy,
            "dot_count": dot_count,
            "hyphen_count": hyphen_count,
            "has_suspicious_tld": has_suspicious_tld,
            "suspicious_keyword_count": suspicious_keyword_count,
            "is_https": is_https,
            "path_depth": path_depth,
            "has_port": has_port,
            "port_high_risk": port_high_risk,
            "is_public_ip": is_public_ip,
            "source_count": float(indicator.source_count),
            "reliability_score": float(indicator.reliability_score),
            "tag_count": float(len(set(indicator.tags))),
            "age_days": age_days,
        }

    def transform(self, indicators: Sequence[Indicator]) -> List[List[float]]:
        return [[feat[name] for name in FEATURE_NAMES] for feat in (self.extract(i) for i in indicators)]


def featurize(indicators: Sequence[Indicator], config: Config) -> None:
    """Attach engineered features to each indicator in place."""
    extractor = FeatureExtractor(config)
    for indicator in indicators:
        indicator.features = extractor.extract(indicator)
