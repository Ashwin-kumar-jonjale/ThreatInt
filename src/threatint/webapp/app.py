"""ThreatInt web dashboard.

A thin read-only presentation layer over the pipeline. It runs the pipeline
once at startup (offline by default so the demo is deterministic and needs no
network) and serves the resulting indicators, campaigns and source
reliability as JSON plus a single-page console.

The pipeline is never exposed for remote reconfiguration: the only request
parameters are pagination/filter values, and all indicator text is escaped
client-side before rendering.
"""

from __future__ import annotations

import argparse
import logging
import os
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template, request

from threatint.config import load_config
from threatint.pipeline import PipelineResult, run_pipeline

logger = logging.getLogger("threatint.webapp")


def _indicator_rows(result: PipelineResult) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for ind in result.indicators:
        row = ind.to_dict()
        row["defanged"] = ind.value.replace("http", "hxxp").replace(".", "[.]")
        rows.append(row)
    return rows


def _campaign_rows(result: PipelineResult) -> List[Dict[str, Any]]:
    rows = []
    for campaign in result.campaigns:
        data = campaign.to_dict()
        data["members"] = [
            {
                "value": m.value,
                "indicator_type": m.indicator_type.value,
                "malicious_probability": round(m.malicious_probability, 4),
                "reliability_score": round(m.reliability_score, 4),
                "verdict": m.verdict.value,
                "source_count": m.source_count,
                "defanged": m.value.replace("http", "hxxp").replace(".", "[.]"),
            }
            for m in campaign.indicators
        ]
        rows.append(data)
    return rows


def create_app(result: PipelineResult, config) -> Flask:
    app = Flask(__name__)
    app.config["RESULT"] = result

    indicators = _indicator_rows(result)
    campaigns = _campaign_rows(result)
    summary = result.summary()
    reliability = [
        rel.to_dict()
        for rel in sorted(result.source_reliability.values(), key=lambda r: -r.score)
    ]

    @app.route("/")
    def index():
        return render_template(
            "dashboard.html",
            summary=summary,
            reliability=reliability,
            campaigns=campaigns,
            indicator_count=len(indicators),
            api_base="",
            static_data=None,
        )

    @app.route("/api/summary")
    def api_summary():
        return jsonify(summary)

    @app.route("/api/indicators")
    def api_indicators():
        verdict = request.args.get("verdict")
        itype = request.args.get("type")
        query = (request.args.get("q") or "").strip().lower()
        try:
            limit = min(int(request.args.get("limit", 100)), 500)
            offset = max(int(request.args.get("offset", 0)), 0)
        except ValueError:
            limit, offset = 100, 0

        filtered = indicators
        if verdict and verdict != "all":
            filtered = [r for r in filtered if r["verdict"] == verdict]
        if itype and itype != "all":
            filtered = [r for r in filtered if r["indicator_type"] == itype]
        if query:
            filtered = [r for r in filtered if query in r["value"].lower()]

        return jsonify(
            {
                "total": len(filtered),
                "limit": limit,
                "offset": offset,
                "items": filtered[offset : offset + limit],
            }
        )

    @app.route("/api/campaigns")
    def api_campaigns():
        return jsonify({"total": len(campaigns), "items": campaigns})

    @app.route("/api/sources")
    def api_sources():
        return jsonify({"items": reliability})

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "generated_at": summary["generated_at"]})

    return app


def build_result(config_path: str | None, offline: bool) -> PipelineResult:
    config = load_config(config_path)
    return run_pipeline(config=config, offline=offline, corpus_size=1200)


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatInt web dashboard")
    parser.add_argument("--config", default=None)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "12000")))
    parser.add_argument("--offline", action="store_true", default=True)
    parser.add_argument("--live", dest="offline", action="store_false")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger.info("running pipeline (offline=%s)...", args.offline)
    result = build_result(args.config, args.offline)
    logger.info(
        "pipeline ready: %d indicators, %d campaigns",
        len(result.indicators), len(result.campaigns),
    )

    app = create_app(result, load_config(args.config))
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
