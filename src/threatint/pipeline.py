"""End-to-end pipeline orchestration.

    collect -> normalize/dedup -> cross-verify -> featurize
            -> classify -> cluster -> report

Each stage is a small function so it can be tested and reordered
independently. The orchestrator owns no global state; a run is fully
described by its :class:`PipelineResult`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from threatint.clustering import cluster_campaigns
from threatint.collectors import build_collectors
from threatint.config import Config, load_config
from threatint.features import featurize
from threatint.ml.classifier import IndicatorClassifier
from threatint.models import Campaign, Indicator, Observation, RawRecord, SourceReliability, Verdict
from threatint.verification import build_indicators, compute_source_reliability

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    generated_at: datetime
    indicators: List[Indicator] = field(default_factory=list)
    campaigns: List[Campaign] = field(default_factory=list)
    source_reliability: Dict[str, SourceReliability] = field(default_factory=dict)
    raw_record_count: int = 0
    training_report: Optional[Dict[str, Any]] = None
    stages: Dict[str, Any] = field(default_factory=dict)

    @property
    def malicious(self) -> List[Indicator]:
        return [i for i in self.indicators if i.verdict is Verdict.MALICIOUS]

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for ind in self.indicators:
            by_type[ind.indicator_type.value] = by_type.get(ind.indicator_type.value, 0) + 1
        verdicts: Dict[str, int] = {}
        for ind in self.indicators:
            verdicts[ind.verdict.value] = verdicts.get(ind.verdict.value, 0) + 1
        return {
            "generated_at": self.generated_at.isoformat(),
            "raw_records": self.raw_record_count,
            "indicators": len(self.indicators),
            "malicious": len(self.malicious),
            "campaigns": len(self.campaigns),
            "by_type": by_type,
            "by_verdict": verdicts,
            "sources": {name: rel.to_dict() for name, rel in self.source_reliability.items()},
            "training": self.training_report,
            "stages": self.stages,
        }

    def to_dict(self, max_indicators: Optional[int] = None) -> Dict[str, Any]:
        indicators = self.indicators if max_indicators is None else self.indicators[:max_indicators]
        return {
            "summary": self.summary(),
            "campaigns": [c.to_dict() for c in self.campaigns],
            "indicators": [i.to_dict() for i in indicators],
        }


def collect_raw_records(config: Config, offline: bool = False) -> List[RawRecord]:
    records: List[RawRecord] = []
    for collector in build_collectors(config, offline=offline):
        try:
            fetched = collector.fetch()
        except Exception as exc:  # a single bad feed must not kill the run
            logger.error("collector %s failed: %s", collector.source.name, exc)
            continue
        logger.info("collected %d records from %s", len(fetched), collector.source.name)
        records.extend(fetched)
    return records


def records_to_observations(records: Sequence[RawRecord]) -> List[Observation]:
    return [
        Observation(
            source=r.source,
            indicator=r.indicator,
            indicator_type=r.indicator_type,
            observed_at=r.observed_at,
            confidence=r.confidence,
            tags=r.tags,
        )
        for r in records
    ]


def run_pipeline(
    config: Optional[Config] = None,
    offline: bool = False,
    labels_path: Optional[str] = None,
    model_path: Optional[str] = None,
    use_saved_model: bool = False,
    corpus_size: int = 1200,
    train_classifier: bool = True,
) -> PipelineResult:
    """Execute the full pipeline and return a :class:`PipelineResult`."""
    config = config or load_config()
    result = PipelineResult(generated_at=datetime.now(timezone.utc))

    # 1. Collect ----------------------------------------------------------
    records = collect_raw_records(config, offline=offline)
    result.raw_record_count = len(records)
    observations = records_to_observations(records)
    result.stages["collect"] = {
        "raw_records": len(records),
        "distinct_sources": len({r.source for r in records}),
    }

    # 2. Cross-verify -----------------------------------------------------
    reliabilities = compute_source_reliability(observations, config)
    result.source_reliability = reliabilities
    indicators = build_indicators(observations, reliabilities, config)
    result.stages["verify"] = {
        "indicators": len(indicators),
        "multi_source": sum(1 for i in indicators if i.source_count >= config.pipeline.min_sources_for_verification),
    }

    # 3. Feature engineering ---------------------------------------------
    featurize(indicators, config)
    result.stages["features"] = {"feature_count": len(next(iter(indicators)).features) if indicators else 0}

    # 4. Classify ---------------------------------------------------------
    classifier = IndicatorClassifier(config)
    if use_saved_model:
        try:
            classifier.load(model_path)
        except FileNotFoundError:
            logger.warning("no saved model; training a fresh classifier")
            use_saved_model = False
    if not use_saved_model:
        if train_classifier:
            report = classifier.train(labels_path=labels_path, corpus_size=corpus_size)
            result.training_report = report.to_dict()
            try:
                classifier.save(model_path)
            except Exception as exc:  # persistence is best-effort
                logger.warning("could not persist model: %s", exc)
        else:
            logger.warning("classifier training disabled and no saved model; verdicts left UNKNOWN")
            classifier = None

    if classifier is not None and classifier.estimator is not None:
        classifier.predict(indicators)
    result.stages["classify"] = {
        "malicious": sum(1 for i in indicators if i.verdict is Verdict.MALICIOUS),
        "benign": sum(1 for i in indicators if i.verdict is Verdict.BENIGN),
        "unknown": sum(1 for i in indicators if i.verdict is Verdict.UNKNOWN),
    }

    result.indicators = indicators

    # 5. Cluster ----------------------------------------------------------
    campaigns = cluster_campaigns(indicators, config)
    result.campaigns = campaigns
    result.stages["cluster"] = {
        "campaigns": len(campaigns),
        "clustered_indicators": sum(c.size for c in campaigns),
    }

    return result
