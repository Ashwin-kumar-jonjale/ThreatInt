"""Core data models for the ThreatInt pipeline.

The pipeline moves through a small number of well-defined shapes:

    RawRecord        -> what a collector emits (source-specific, unvalidated)
    Indicator        -> a normalized, deduplicated atomic observable
    Observation      -> one source's claim about an indicator
    Campaign         -> a cluster of indicators believed to be related
    SourceReliability-> a rolling trust score for a feed

Keeping these as plain dataclasses (rather than framework objects) keeps the
collectors, verifiers and models decoupled and easy to test.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IndicatorType(str, Enum):
    """Supported atomic observable types."""

    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA256 = "sha256"

    @classmethod
    def values(cls) -> List[str]:
        return [m.value for m in cls]


class Verdict(str, Enum):
    """Classifier output."""

    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RawRecord:
    """A single, source-specific record emitted by a collector.

    ``raw`` preserves the original payload so downstream stages can be
    re-run without re-fetching and so analysts can audit provenance.
    """

    source: str
    indicator: str
    indicator_type: IndicatorType
    observed_at: datetime = field(default_factory=_utcnow)
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.5
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["observed_at"] = self.observed_at.isoformat()
        d["indicator_type"] = self.indicator_type.value
        return d


@dataclass
class Observation:
    """One source's claim about an indicator at a point in time."""

    source: str
    indicator: str
    indicator_type: IndicatorType
    observed_at: datetime = field(default_factory=_utcnow)
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["observed_at"] = self.observed_at.isoformat()
        d["indicator_type"] = self.indicator_type.value
        return d


@dataclass
class Indicator:
    """A normalized, deduplicated atomic observable.

    ``indicator_id`` is a stable hash of ``(indicator_type, value)`` so the
    same observable seen by different sources collapses to one object.
    """

    value: str
    indicator_type: IndicatorType
    first_seen: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)
    observations: List[Observation] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source_count: int = 0
    reliability_score: float = 0.0
    verdict: Verdict = Verdict.UNKNOWN
    malicious_probability: float = 0.0
    campaign_id: Optional[str] = None
    features: Dict[str, float] = field(default_factory=dict)

    @property
    def indicator_id(self) -> str:
        key = f"{self.indicator_type.value}:{self.value}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    @property
    def sources(self) -> List[str]:
        return sorted({o.source for o in self.observations})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "value": self.value,
            "indicator_type": self.indicator_type.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source_count": self.source_count,
            "sources": self.sources,
            "reliability_score": round(self.reliability_score, 4),
            "verdict": self.verdict.value,
            "malicious_probability": round(self.malicious_probability, 4),
            "campaign_id": self.campaign_id,
            "tags": sorted(set(self.tags)),
            "features": {k: round(v, 4) for k, v in self.features.items()},
        }


@dataclass
class SourceReliability:
    """Rolling reliability estimate for a feed.

    Combines a static analyst-assigned prior with dynamic signals observed
    during cross-verification (agreement with the consensus, volume, recency).
    """

    source: str
    prior: float = 0.5
    precision: float = 0.0
    recall: float = 0.0
    agreement: float = 0.0
    volume: int = 0
    score: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "prior": round(self.prior, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "agreement": round(self.agreement, 4),
            "volume": self.volume,
            "score": round(self.score, 4),
        }


@dataclass
class Campaign:
    """A cluster of indicators believed to belong to the same operation."""

    campaign_id: str
    label: str
    indicators: List[Indicator] = field(default_factory=list)
    shared_tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=_utcnow)

    @property
    def size(self) -> int:
        return len(self.indicators)

    @property
    def mean_reliability(self) -> float:
        if not self.indicators:
            return 0.0
        return sum(i.reliability_score for i in self.indicators) / len(self.indicators)

    @property
    def mean_malicious_probability(self) -> float:
        if not self.indicators:
            return 0.0
        return sum(i.malicious_probability for i in self.indicators) / len(self.indicators)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "label": self.label,
            "size": self.size,
            "shared_tags": self.shared_tags,
            "mean_reliability": round(self.mean_reliability, 4),
            "mean_malicious_probability": round(self.mean_malicious_probability, 4),
            "indicator_ids": [i.indicator_id for i in self.indicators],
            "indicators": [i.value for i in self.indicators],
            "created_at": self.created_at.isoformat(),
        }
