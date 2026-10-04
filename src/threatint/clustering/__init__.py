"""Campaign clustering.

Related indicators are grouped with DBSCAN over a composite distance that
blends two notions of "related":

* lexical similarity  - cosine distance between engineered feature vectors,
  so DGA-like strings, phishing-pattern URLs and C2 IPs naturally sit apart.
* campaign similarity - Jaccard overlap of threat tags, so indicators that a
  feed labelled with the same malware family / attack type pull together even
  when their lexical forms differ.

DBSCAN is a good fit because the number of campaigns is unknown in advance
and isolated indicators should be treated as noise rather than forced into a
cluster. Benign-verdict indicators are excluded so we never report a benign
host as part of an attack campaign.
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from typing import Dict, List, Sequence, Tuple

import numpy as np

from threatint.config import Config
from threatint.features import FEATURE_NAMES
from threatint.models import Campaign, Indicator, Verdict

logger = logging.getLogger(__name__)

# Feature weights applied before clustering so strong semantic signals
# (type, suspicious tokens) dominate raw length/entropy differences.
_FEATURE_WEIGHTS: Dict[str, float] = {
    "is_ipv4": 1.0,
    "is_domain": 1.0,
    "is_url": 1.0,
    "is_hash": 1.0,
    "length": 0.15,
    "digit_ratio": 0.5,
    "alpha_ratio": 0.5,
    "entropy": 1.2,
    "dot_count": 0.6,
    "hyphen_count": 0.4,
    "has_suspicious_tld": 1.5,
    "suspicious_keyword_count": 1.5,
    "is_https": 0.4,
    "path_depth": 0.5,
    "has_port": 0.6,
    "port_high_risk": 1.2,
    "is_public_ip": 0.3,
    "source_count": 0.4,
    "reliability_score": 0.3,
    "tag_count": 0.3,
    "age_days": 0.1,
}

# Weight of tag similarity vs. lexical similarity in the composite distance.
_TAG_WEIGHT = 0.4
_LEXICAL_WEIGHT = 1.0 - _TAG_WEIGHT


def _vector(indicator: Indicator) -> List[float]:
    return [indicator.features.get(name, 0.0) * _FEATURE_WEIGHTS.get(name, 1.0) for name in FEATURE_NAMES]


def _composite_distance(matrix: np.ndarray, indicators: Sequence[Indicator]) -> np.ndarray:
    """Pairwise distance in [0, 1]: lexical cosine + tag-set disagreement."""
    from sklearn.metrics.pairwise import cosine_similarity

    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    safe = np.divide(matrix, norms, out=np.zeros_like(matrix), where=norms > 0)
    lexical = 1.0 - cosine_similarity(safe)
    lexical = np.clip(lexical, 0.0, 1.0)

    n = len(indicators)
    tag_sets = [set(i.tags) for i in indicators]
    tag_dist = np.zeros((n, n), dtype=float)
    for a in range(n):
        for b in range(a + 1, n):
            sa, sb = tag_sets[a], tag_sets[b]
            union = sa | sb
            jaccard = len(sa & sb) / len(union) if union else 0.0
            d = 1.0 - jaccard
            tag_dist[a, b] = tag_dist[b, a] = d

    return _LEXICAL_WEIGHT * lexical + _TAG_WEIGHT * tag_dist


def _campaign_id(member_ids: Sequence[str]) -> str:
    key = "|".join(sorted(member_ids))
    return "camp-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]


def _label_for(members: Sequence[Indicator]) -> Tuple[str, List[str]]:
    counter: Counter = Counter()
    for member in members:
        counter.update(set(member.tags))
    shared = [tag for tag, count in counter.items() if count >= max(2, len(members) // 2)]
    shared.sort(key=lambda tag: (-counter[tag], tag))
    if shared:
        return f"campaign: {shared[0]}", shared
    types = Counter(m.indicator_type.value for m in members)
    dominant = types.most_common(1)[0][0] if types else "mixed"
    return f"campaign: {dominant}-cluster", shared


def cluster_campaigns(
    indicators: Sequence[Indicator],
    config: Config,
    persist: bool = True,
) -> List[Campaign]:
    """Cluster indicators into campaigns and stamp ``campaign_id`` on members."""
    from sklearn.cluster import DBSCAN

    min_reliability = float(config.pipeline.min_reliability_for_clustering)
    eligible = [
        i for i in indicators
        if i.reliability_score >= min_reliability and i.verdict is not Verdict.BENIGN
    ]
    if len(eligible) < 2:
        logger.info("not enough eligible indicators for clustering (%d)", len(eligible))
        return []

    matrix = np.asarray([_vector(i) for i in eligible], dtype=float)
    distance = _composite_distance(matrix, eligible)

    eps = float(config.clustering.get("eps", 0.6))
    min_samples = int(config.clustering.get("min_samples", 2))

    labels = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed").fit_predict(distance)

    groups: Dict[int, List[Indicator]] = {}
    for label, indicator in zip(labels, eligible):
        if label == -1:  # noise
            continue
        groups.setdefault(int(label), []).append(indicator)

    campaigns: List[Campaign] = []
    for label, members in sorted(groups.items()):
        cid = _campaign_id([m.indicator_id for m in members])
        name, shared = _label_for(members)
        campaign = Campaign(campaign_id=cid, label=name, indicators=members, shared_tags=shared)
        campaigns.append(campaign)
        if persist:
            for member in members:
                member.campaign_id = cid

    campaigns.sort(key=lambda c: (-c.size, -c.mean_malicious_probability, c.campaign_id))
    logger.info(
        "clustered %d eligible indicators into %d campaigns (%d noise)",
        len(eligible), len(campaigns), int((labels == -1).sum()),
    )
    return campaigns
