"""Machine-learning classifier for malicious indicators.

The classifier is trained on engineered feature vectors and predicts the
probability that an indicator is malicious. Two training-data paths exist:

* ``--labels path.csv``  analyst-reviewed ``indicator,label`` data (preferred)
* otherwise              a seeded synthetic bootstrap corpus

The trained model and a small evaluation report are persisted so runs are
auditable and repeatable.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from threatint.config import Config
from threatint.features import FEATURE_NAMES, FeatureExtractor
from threatint.models import Indicator, Verdict
from threatint.ml.synthetic import generate_corpus
from threatint.normalize import canonicalize, detect_type

logger = logging.getLogger(__name__)


@dataclass
class TrainingReport:
    model: str
    n_samples: int
    n_malicious: int
    n_benign: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    feature_importance: Dict[str, float] = field(default_factory=dict)
    data_source: str = "synthetic"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "n_samples": self.n_samples,
            "n_malicious": self.n_malicious,
            "n_benign": self.n_benign,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "roc_auc": round(self.roc_auc, 4),
            "data_source": self.data_source,
            "feature_importance": {k: round(v, 4) for k, v in self.feature_importance.items()},
        }


def _make_estimator(cfg: Dict[str, Any], seed: int):
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier

    model = str(cfg.get("model", "random_forest"))
    n_estimators = int(cfg.get("n_estimators", 300))
    max_depth = cfg.get("max_depth", 12)
    if model == "gradient_boosting":
        return GradientBoostingClassifier(
            n_estimators=n_estimators, max_depth=int(max_depth) if max_depth else 3, random_state=seed
        )
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=int(max_depth) if max_depth else None,
        random_state=seed,
        n_jobs=-1,
        class_weight="balanced",
    )


def load_labeled_data(path: str) -> Tuple[List[str], List[int]]:
    """Load analyst labels from a CSV with ``indicator`` and ``label`` columns."""
    import csv

    values: List[str] = []
    labels: List[int] = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
        val_col = cols.get("indicator") or cols.get("value") or cols.get("ioc")
        lbl_col = cols.get("label") or cols.get("verdict") or cols.get("malicious")
        if not val_col or not lbl_col:
            raise ValueError("Labeled CSV must have 'indicator' and 'label' columns")
        for row in reader:
            raw_label = str(row[lbl_col]).strip().lower()
            label = 1 if raw_label in {"1", "true", "malicious", "yes", "bad"} else 0
            values.append(row[val_col])
            labels.append(label)
    return values, labels


class IndicatorClassifier:
    """Wrapper around a scikit-learn estimator with a stable feature contract."""

    def __init__(self, config: Config):
        self.config = config
        self.extractor = FeatureExtractor(config)
        self.estimator = None
        self.report: Optional[TrainingReport] = None

    # -- training ----------------------------------------------------------
    def train(
        self,
        labels_path: Optional[str] = None,
        corpus_size: int = 1200,
    ) -> TrainingReport:
        from sklearn.metrics import (
            accuracy_score,
            f1_score,
            precision_score,
            recall_score,
            roc_auc_score,
        )
        from sklearn.model_selection import train_test_split

        seed = int(self.config.pipeline.random_seed)
        ml_cfg = self.config.ml

        if labels_path:
            values, labels = load_labeled_data(labels_path)
            data_source = f"labels:{labels_path}"
        else:
            values, labels = generate_corpus(n=corpus_size, seed=seed)
            data_source = "synthetic"

        # Build usable (indicator, label) pairs, dropping values whose type
        # cannot be inferred so X and y stay aligned.
        pairs: List[Tuple[Indicator, int]] = []
        for value, label in zip(values, labels):
            itype = detect_type(value)
            if itype is None:
                continue
            canon = canonicalize(value, itype)
            if canon is None:
                continue
            pairs.append(
                (Indicator(value=canon, indicator_type=itype, source_count=1, reliability_score=0.5), int(label))
            )
        if not pairs:
            raise ValueError("No usable labeled indicators found")

        indicators = [p[0] for p in pairs]
        y = np.array([p[1] for p in pairs], dtype=int)
        X_arr = np.asarray(self.extractor.transform(indicators), dtype=float)
        test_size = float(ml_cfg.get("test_size", 0.25))

        X_train, X_test, y_train, y_test = train_test_split(
            X_arr, y, test_size=test_size, random_state=seed, stratify=y if len(set(y.tolist())) > 1 else None
        )

        self.estimator = _make_estimator(ml_cfg, seed)
        self.estimator.fit(X_train, y_train)

        y_pred = self.estimator.predict(X_test)
        try:
            y_prob = self.estimator.predict_proba(X_test)[:, 1]
            roc_auc = float(roc_auc_score(y_test, y_prob)) if len(set(y_test.tolist())) > 1 else 0.5
        except Exception:
            roc_auc = 0.5

        importances = getattr(self.estimator, "feature_importances_", None)
        feature_importance = (
            dict(zip(FEATURE_NAMES, [float(v) for v in importances])) if importances is not None else {}
        )

        self.report = TrainingReport(
            model=str(ml_cfg.get("model", "random_forest")),
            n_samples=int(len(y)),
            n_malicious=int((y == 1).sum()),
            n_benign=int((y == 0).sum()),
            accuracy=float(accuracy_score(y_test, y_pred)),
            precision=float(precision_score(y_test, y_pred, zero_division=0)),
            recall=float(recall_score(y_test, y_pred, zero_division=0)),
            f1=float(f1_score(y_test, y_pred, zero_division=0)),
            roc_auc=roc_auc,
            feature_importance=feature_importance,
            data_source=data_source,
        )
        logger.info(
            "trained %s on %d samples: acc=%.3f f1=%.3f auc=%.3f",
            self.report.model, self.report.n_samples, self.report.accuracy, self.report.f1, self.report.roc_auc,
        )
        return self.report

    # -- inference ---------------------------------------------------------
    def predict(self, indicators: Sequence[Indicator]) -> None:
        """Set ``malicious_probability`` and ``verdict`` on each indicator."""
        if self.estimator is None:
            raise RuntimeError("Classifier is not trained")
        if not indicators:
            return
        X = np.asarray(self.extractor.transform(indicators), dtype=float)
        probs = self.estimator.predict_proba(X)[:, 1]
        threshold = float(self.config.pipeline.malicious_threshold)
        for indicator, prob in zip(indicators, probs):
            indicator.malicious_probability = float(prob)
            if prob >= threshold:
                indicator.verdict = Verdict.MALICIOUS
            elif prob <= 1.0 - threshold:
                indicator.verdict = Verdict.BENIGN
            else:
                indicator.verdict = Verdict.UNKNOWN

    # -- persistence -------------------------------------------------------
    def save(self, path: Optional[str] = None) -> Path:
        import joblib

        target = Path(path or self.config.ml.get("model_path", "artifacts/classifier.joblib"))
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"estimator": self.estimator, "report": self.report.to_dict() if self.report else None},
            target,
        )
        report_path = target.with_suffix(".report.json")
        if self.report:
            report_path.write_text(json.dumps(self.report.to_dict(), indent=2), encoding="utf-8")
        return target

    def load(self, path: Optional[str] = None) -> "IndicatorClassifier":
        import joblib

        target = Path(path or self.config.ml.get("model_path", "artifacts/classifier.joblib"))
        if not target.exists():
            raise FileNotFoundError(f"No model at {target}")
        blob = joblib.load(target)
        self.estimator = blob["estimator"]
        report = blob.get("report")
        if report:
            self.report = TrainingReport(
                model=report.get("model", "unknown"),
                n_samples=report.get("n_samples", 0),
                n_malicious=report.get("n_malicious", 0),
                n_benign=report.get("n_benign", 0),
                accuracy=report.get("accuracy", 0.0),
                precision=report.get("precision", 0.0),
                recall=report.get("recall", 0.0),
                f1=report.get("f1", 0.0),
                roc_auc=report.get("roc_auc", 0.0),
                feature_importance=report.get("feature_importance", {}),
                data_source=report.get("data_source", "unknown"),
            )
        return self
