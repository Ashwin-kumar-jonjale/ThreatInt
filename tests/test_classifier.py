"""Tests for the ML classifier: training quality, inference and persistence."""

from __future__ import annotations


from threatint.features import featurize
from threatint.ml.classifier import IndicatorClassifier, load_labeled_data
from threatint.models import Indicator, IndicatorType, Verdict
from threatint.ml.synthetic import generate_corpus


def test_synthetic_corpus_is_deterministic():
    a = generate_corpus(n=200, seed=7)
    b = generate_corpus(n=200, seed=7)
    assert a == b
    values, labels = a
    assert set(labels) == {0, 1}
    assert len(values) == len(labels)


def test_classifier_learns_synthetic_task(config):
    clf = IndicatorClassifier(config)
    report = clf.train(corpus_size=800)
    # The synthetic task is separable; a sane model should clear this bar.
    assert report.roc_auc > 0.85
    assert report.f1 > 0.75
    assert report.n_samples > 0


def test_classifier_ranks_obvious_malicious_above_benign(config):
    clf = IndicatorClassifier(config)
    clf.train(corpus_size=1200)

    malicious = [
        Indicator(value="http://paypal-verify-login.xyz/account/verify", indicator_type=IndicatorType.URL),
        Indicator(value="secure-bank-update.tk", indicator_type=IndicatorType.DOMAIN),
    ]
    benign = [
        Indicator(value="https://github.com/", indicator_type=IndicatorType.URL),
        Indicator(value="google.com", indicator_type=IndicatorType.DOMAIN),
    ]
    for ind in malicious + benign:
        ind.source_count = 1
        ind.reliability_score = 0.5
    featurize(malicious + benign, config)
    clf.predict(malicious + benign)

    assert min(i.malicious_probability for i in malicious) > max(i.malicious_probability for i in benign)
    assert all(i.verdict is Verdict.MALICIOUS for i in malicious)
    assert all(i.verdict is Verdict.BENIGN for i in benign)


def test_classifier_persistence_roundtrip(config, tmp_path):
    clf = IndicatorClassifier(config)
    clf.train(corpus_size=400)
    path = tmp_path / "model.joblib"
    clf.save(str(path))
    assert path.exists()

    restored = IndicatorClassifier(config).load(str(path))
    ind = Indicator(value="http://evil-login.xyz/verify", indicator_type=IndicatorType.URL)
    ind.source_count = 1
    ind.reliability_score = 0.5
    featurize([ind], config)
    restored.predict([ind])
    assert 0.0 <= ind.malicious_probability <= 1.0
    assert restored.report is not None


def test_load_labeled_data(config, tmp_path):
    csv_path = tmp_path / "labels.csv"
    csv_path.write_text(
        "indicator,label\n"
        "http://evil.xyz/a,malicious\n"
        "google.com,benign\n"
        "8.8.8.8,0\n"
        "9.9.9.9,1\n",
        encoding="utf-8",
    )
    values, labels = load_labeled_data(str(csv_path))
    assert labels == [1, 0, 0, 1]
    assert values[0] == "http://evil.xyz/a"


def test_training_on_analyst_labels(config, tmp_path):
    csv_path = tmp_path / "labels.csv"
    rows = ["indicator,label"]
    for host in ["paypal-verify-login.xyz", "apple-secure-update.tk", "bank-account-verify.ml"]:
        rows.append(f"http://{host}/verify,malicious")
    for host in ["github.com", "python.org", "wikipedia.org"]:
        rows.append(f"https://{host}/docs,benign")
    # Repeat to give the model enough rows to split.
    body = "\n".join(rows * 20)
    csv_path.write_text(body, encoding="utf-8")
    clf = IndicatorClassifier(config)
    report = clf.train(labels_path=str(csv_path))
    assert report.data_source.startswith("labels:")
    assert report.n_samples > 0
