"""End-to-end pipeline and CLI tests (offline, deterministic)."""

from __future__ import annotations

import json

from threatint.cli import main
from threatint.models import Verdict
from threatint.pipeline import run_pipeline
from threatint.reporting import render_console


def test_pipeline_runs_offline_end_to_end(config):
    result = run_pipeline(config=config, offline=True, corpus_size=600)

    assert result.raw_record_count > 0
    assert len(result.indicators) > 0
    assert len(result.source_reliability) == len(config.enabled_sources)

    # All indicators carry engineered features and a verdict.
    for ind in result.indicators:
        assert ind.features
        assert ind.verdict in (Verdict.MALICIOUS, Verdict.BENIGN, Verdict.UNKNOWN)

    # The deliberately-shared indicator appears in multiple feeds.
    shared = next(i for i in result.indicators if i.value == "secure-paypal-login.xyz")
    assert shared.source_count >= 3


def test_pipeline_produces_campaigns(config):
    result = run_pipeline(config=config, offline=True, corpus_size=600)
    assert len(result.campaigns) >= 2
    assert sum(c.size for c in result.campaigns) > 0
    # Campaign members are marked with the campaign id.
    for campaign in result.campaigns:
        for member in campaign.indicators:
            assert member.campaign_id == campaign.campaign_id


def test_pipeline_summary_shape(config):
    result = run_pipeline(config=config, offline=True, corpus_size=400)
    summary = result.summary()
    for key in ("raw_records", "indicators", "malicious", "campaigns", "by_type", "by_verdict", "sources"):
        assert key in summary
    assert summary["indicators"] == len(result.indicators)


def test_pipeline_no_train_leaves_unknown(config):
    result = run_pipeline(config=config, offline=True, train_classifier=False)
    assert all(i.verdict is Verdict.UNKNOWN for i in result.indicators)
    assert result.training_report is None
    # Clustering still runs on reliability + tags even without a classifier,
    # so analysts get grouped indicators rather than an empty report.
    assert len(result.campaigns) > 0


def test_render_console_contains_key_sections(config):
    result = run_pipeline(config=config, offline=True, corpus_size=400)
    text = render_console(result, top=5)
    assert "ThreatInt pipeline report" in text
    assert "source reliability" in text
    assert "classifier" in text


def test_cli_writes_outputs(config, tmp_path):
    json_path = tmp_path / "report.json"
    ind_path = tmp_path / "indicators.csv"
    camp_path = tmp_path / "campaigns.csv"

    code = main(
        [
            "--config", str(config.config_path),
            "--offline",
            "--corpus-size", "400",
            "--out-json", str(json_path),
            "--out-indicators", str(ind_path),
            "--out-campaigns", str(camp_path),
            "--quiet",
        ]
    )
    assert code == 0
    assert json_path.exists()
    assert ind_path.exists()
    assert camp_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "summary" in payload
    assert "indicators" in payload
    assert "campaigns" in payload

    # CSV header sanity.
    assert "indicator_id" in ind_path.read_text(encoding="utf-8").splitlines()[0]
    assert "campaign_id" in camp_path.read_text(encoding="utf-8").splitlines()[0]


def test_cli_bad_config_returns_error(tmp_path):
    code = main(["--config", str(tmp_path / "missing.yaml"), "--offline", "--quiet"])
    assert code == 2
