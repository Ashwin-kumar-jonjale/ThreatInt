"""Static export of the dashboard.

Renders the same console the Flask app serves into a single self-contained
HTML file with all data inlined, so it can be published to GitHub Pages (or
any static host) with no backend. Filtering/pagination then run client-side.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from flask import Flask, render_template

from threatint.config import load_config
from threatint.pipeline import run_pipeline
from threatint.webapp.app import _campaign_rows, _indicator_rows

logger = logging.getLogger("threatint.webapp.static")


def render_static(config_path: str | None = None, offline: bool = True) -> str:
    config = load_config(config_path)
    result = run_pipeline(config=config, offline=offline, corpus_size=1200)
    static_data = {
        "summary": result.summary(),
        "reliability": [
            rel.to_dict()
            for rel in sorted(result.source_reliability.values(), key=lambda r: -r.score)
        ],
        "campaigns": _campaign_rows(result),
        "indicators": _indicator_rows(result),
    }
    app = Flask(__name__)
    with app.app_context():
        return render_template(
            "dashboard.html",
            summary=static_data["summary"],
            reliability=static_data["reliability"],
            campaigns=static_data["campaigns"],
            indicator_count=len(static_data["indicators"]),
            api_base="",
            static_data=static_data,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a static ThreatInt dashboard")
    parser.add_argument("--config", default=None)
    parser.add_argument("--out", default="dist/index.html")
    parser.add_argument("--offline", action="store_true", default=True)
    parser.add_argument("--live", dest="offline", action="store_false")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    html = render_static(args.config, args.offline)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    logger.info("wrote static dashboard -> %s (%d bytes)", out, len(html))


if __name__ == "__main__":
    main()
