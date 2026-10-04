"""Cross-verification and source reliability scoring.

Two questions are answered here:

1. How much should we trust each feed?  We blend the analyst prior with
   dynamic signals measured against the cross-source consensus:
   - precision: of the indicators a source reported, what share reached
     consensus (reported by >= ``min_sources`` distinct sources)?
   - recall: of all consensus indicators, what share did the source report?
   - agreement: mean pairwise Jaccard overlap with every other source.

2. How much should we trust a single indicator?  Its reliability is the
   reliability-weighted average across the sources that reported it, with a
   consensus bonus when enough independent sources agree.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

from threatint.config import Config
from threatint.models import Indicator, Observation, SourceReliability


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def compute_source_reliability(
    observations: Sequence[Observation],
    config: Config,
) -> Dict[str, SourceReliability]:
    """Compute dynamic reliability for every source that contributed data."""
    by_source: Dict[str, set] = defaultdict(set)
    for obs in observations:
        by_source[obs.source].add((obs.indicator_type.value, obs.indicator))


    # Consensus set: indicators seen by at least min_sources distinct sources.
    indicator_sources: Dict[Tuple[str, str], set] = defaultdict(set)
    for obs in observations:
        indicator_sources[(obs.indicator_type.value, obs.indicator)].add(obs.source)
    min_sources = max(1, config.pipeline.min_sources_for_verification)
    consensus = {key for key, srcs in indicator_sources.items() if len(srcs) >= min_sources}

    sources = sorted(by_source.keys())
    reliabilities: Dict[str, SourceReliability] = {}

    for source in sources:
        reported = by_source[source]
        hits = reported & consensus
        precision = len(hits) / len(reported) if reported else 0.0
        recall = len(hits) / len(consensus) if consensus else 0.0

        agreements = [
            _jaccard(reported, by_source[other])
            for other in sources
            if other != source
        ]
        agreement = sum(agreements) / len(agreements) if agreements else 0.0

        prior = config.get_source(source).reliability_prior if config.get_source(source) else 0.5

        # Volume dampening: a source with very few reports shouldn't swing
        # the dynamic component too far from its prior.
        volume_factor = 1.0 - math.exp(-len(reported) / 25.0)

        dynamic = 0.45 * precision + 0.25 * recall + 0.30 * agreement
        blended = prior * (1.0 - volume_factor) + (0.5 * prior + 0.5 * dynamic) * volume_factor
        score = max(0.0, min(1.0, blended))

        reliabilities[source] = SourceReliability(
            source=source,
            prior=prior,
            precision=precision,
            recall=recall,
            agreement=agreement,
            volume=len(reported),
            score=score,
        )

    return reliabilities


def score_indicator(
    observations: Sequence[Observation],
    reliabilities: Dict[str, SourceReliability],
    config: Config,
) -> float:
    """Reliability-weighted trust score for one indicator, in [0, 1]."""
    if not observations:
        return 0.0
    weights = [max(0.01, reliabilities[o.source].score) for o in observations if o.source in reliabilities]
    confidences = [o.confidence for o in observations if o.source in reliabilities]
    if not weights:
        return 0.0
    weighted = sum(w * c for w, c in zip(weights, confidences)) / sum(weights)

    distinct = len({o.source for o in observations})
    min_sources = max(1, config.pipeline.min_sources_for_verification)
    if distinct >= min_sources:
        # Reward independent corroboration, saturating so a huge feed count
        # doesn't dominate the signal.
        bonus = 0.15 * min(1.0, (distinct - min_sources + 1) / 3.0)
        weighted = min(1.0, weighted + bonus)

    return max(0.0, min(1.0, weighted))


def build_indicators(
    observations: Sequence[Observation],
    reliabilities: Dict[str, SourceReliability],
    config: Config,
) -> List[Indicator]:
    """Collapse observations into deduplicated, scored indicators."""
    grouped: Dict[Tuple[str, str], List[Observation]] = defaultdict(list)
    for obs in observations:
        grouped[(obs.indicator_type.value, obs.indicator)].append(obs)

    indicators: List[Indicator] = []
    for (type_value, value), obs_list in grouped.items():
        from threatint.models import IndicatorType

        itype = IndicatorType(type_value)
        times = [o.observed_at for o in obs_list]
        tags: List[str] = []
        for o in obs_list:
            tags.extend(o.tags)

        indicator = Indicator(
            value=value,
            indicator_type=itype,
            first_seen=min(times),
            last_seen=max(times),
            observations=list(obs_list),
            tags=tags,
            source_count=len({o.source for o in obs_list}),
            reliability_score=score_indicator(obs_list, reliabilities, config),
        )
        indicators.append(indicator)

    indicators.sort(key=lambda i: (-i.reliability_score, i.indicator_type.value, i.value))
    return indicators
