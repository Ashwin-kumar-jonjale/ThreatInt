"""Human- and machine-readable reporting for pipeline results."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional

from threatint.pipeline import PipelineResult


def to_json(result: PipelineResult, max_indicators: Optional[int] = None) -> str:
    return json.dumps(result.to_dict(max_indicators=max_indicators), indent=2, default=str)


def write_json(result: PipelineResult, path: str, max_indicators: Optional[int] = None) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(to_json(result, max_indicators=max_indicators), encoding="utf-8")
    return target


def write_indicators_csv(result: PipelineResult, path: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "indicator_id", "value", "indicator_type", "verdict",
        "malicious_probability", "reliability_score", "source_count",
        "sources", "campaign_id", "tags",
    ]
    with open(target, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for ind in result.indicators:
            row = ind.to_dict()
            row["sources"] = "|".join(row.get("sources", []))
            row["tags"] = "|".join(row.get("tags", []))
            writer.writerow(row)
    return target


def write_campaigns_csv(result: PipelineResult, path: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = ["campaign_id", "label", "size", "mean_malicious_probability", "mean_reliability", "shared_tags"]
    with open(target, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for campaign in result.campaigns:
            row = campaign.to_dict()
            row["shared_tags"] = "|".join(row.get("shared_tags", []))
            writer.writerow(row)
    return target


def render_console(result: PipelineResult, top: int = 15) -> str:
    """A compact analyst-facing text report."""
    s = result.summary()
    lines = []
    lines.append("=" * 72)
    lines.append("ThreatInt pipeline report")
    lines.append("=" * 72)
    lines.append(f"generated at        : {s['generated_at']}")
    lines.append(f"raw records         : {s['raw_records']}")
    lines.append(f"unique indicators   : {s['indicators']}")
    lines.append(f"malicious           : {s['malicious']}")
    lines.append(f"campaigns           : {s['campaigns']}")
    lines.append(f"by type             : {s['by_type']}")
    lines.append(f"by verdict          : {s['by_verdict']}")

    training = s.get("training")
    if training:
        lines.append("")
        lines.append("classifier")
        lines.append(f"  model             : {training['model']} ({training['data_source']})")
        lines.append(
            f"  accuracy/f1/auc   : {training['accuracy']:.3f} / {training['f1']:.3f} / {training['roc_auc']:.3f}"
        )
        top_feats = sorted(training["feature_importance"].items(), key=lambda kv: -kv[1])[:5]
        if top_feats:
            lines.append(f"  top features      : {', '.join(f'{k}={v:.2f}' for k, v in top_feats)}")

    lines.append("")
    lines.append("source reliability")
    for name, rel in sorted(result.source_reliability.items(), key=lambda kv: -kv[1].score):
        lines.append(
            f"  {name:<20} score={rel.score:.3f} "
            f"precision={rel.precision:.2f} recall={rel.recall:.2f} "
            f"agreement={rel.agreement:.2f} volume={rel.volume}"
        )

    if result.campaigns:
        lines.append("")
        lines.append(f"campaigns (top {min(top, len(result.campaigns))})")
        for campaign in result.campaigns[:top]:
            lines.append(
                f"  {campaign.campaign_id}  size={campaign.size:<3} "
                f"p_mal={campaign.mean_malicious_probability:.2f}  {campaign.label}"
            )

    if result.indicators:
        lines.append("")
        lines.append(f"top indicators (by malicious probability, top {min(top, len(result.indicators))})")
        ranked = sorted(result.indicators, key=lambda i: -i.malicious_probability)[:top]
        for ind in ranked:
            lines.append(
                f"  {ind.malicious_probability:.2f}  {ind.verdict.value:<9} "
                f"{ind.indicator_type.value:<7} {ind.value[:48]:<48} "
                f"rel={ind.reliability_score:.2f} src={ind.source_count}"
            )

    lines.append("=" * 72)
    return "\n".join(lines)
