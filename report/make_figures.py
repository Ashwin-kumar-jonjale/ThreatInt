"""Generate all figures for the ThreatInt research report.

Everything is derived from the real offline pipeline run (report/data/result.json)
plus a deterministic replication of the classifier train/test split for the
confusion matrix and ROC curve. No fabricated numbers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threatint.collectors import build_collectors  # noqa: E402
from threatint.config import load_config  # noqa: E402
from threatint.features import FeatureExtractor  # noqa: E402
from threatint.ml.classifier import _make_estimator  # noqa: E402
from threatint.ml.synthetic import generate_corpus  # noqa: E402
from threatint.models import Indicator  # noqa: E402
from threatint.normalize import canonicalize, detect_type  # noqa: E402

DATA = json.loads((ROOT / "report" / "data" / "result.json").read_text())
FIG = ROOT / "report" / "figures"
FIG.mkdir(parents=True, exist_ok=True)
CFG = load_config(str(ROOT / "config" / "config.yaml"))

# -- palette ---------------------------------------------------------------
NAVY = "#1b3a5c"
STEEL = "#34668c"
SKY = "#5b9bd5"
CRIMSON = "#c0392b"
AMBER = "#e08a1e"
GREEN = "#2e8b57"
GREY = "#8a99a8"
PAPER = "#ffffff"
INK = "#1d2733"

plt.rcParams.update({
    "figure.facecolor": PAPER,
    "axes.facecolor": PAPER,
    "savefig.facecolor": PAPER,
    "font.size": 11,
    "axes.edgecolor": "#c8d2dc",
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "axes.titleweight": "bold",
    "font.family": "DejaVu Sans",
})

S = DATA["summary"]
STAGES = S["stages"]
SOURCES = S["sources"]
CAMPAIGNS = DATA["campaigns"]
INDICATORS = DATA["indicators"]
TRAIN = S["training"]


def save(fig, name):
    fig.savefig(FIG / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


def _box(ax, x, y, w, h, text, fc, ec, tc="white", fs=10, bold=True, radius=0.02):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0.004,rounding_size={radius}",
        linewidth=1.4, edgecolor=ec, facecolor=fc, mutation_aspect=1,
    ))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            color=tc, fontsize=fs, fontweight="bold" if bold else "normal", wrap=True)


def _arrow(ax, p0, p1, color=STEEL, style="-|>", lw=1.8, ls="-"):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle=style, mutation_scale=16,
                                 linewidth=lw, color=color, linestyle=ls,
                                 shrinkA=2, shrinkB=2))


# =========================================================================
# Fig 1 - architecture
# =========================================================================
def fig_architecture():
    fig, ax = plt.subplots(figsize=(13, 8.6))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")

    ax.text(50, 96.5, "ThreatInt — System Architecture", ha="center", fontsize=17,
            fontweight="bold", color=NAVY)
    ax.text(50, 92.5, "Layered design: entry points → orchestration → stages → models → outputs",
            ha="center", fontsize=10.5, color=GREY)

    def layer(y, h, title, color, boxes):
        ax.add_patch(FancyBboxPatch((2.5, y), 95, h, boxstyle="round,pad=0.3,rounding_size=0.6",
                                    linewidth=0, facecolor=color, alpha=0.07))
        ax.text(4.5, y + h - 1.6, title, ha="left", va="top", fontsize=10,
                fontweight="bold", color=color)
        n = len(boxes)
        gap = 2.0
        bw = (91 - gap * (n - 1)) / n
        for i, (name, sub) in enumerate(boxes):
            x = 4.5 + i * (bw + gap)
            _box(ax, x, y + 1.4, bw, h - 5.2, "", PAPER, color)
            ax.text(x + bw / 2, y + h - 5.4, name, ha="center", va="center",
                    fontsize=9.6, fontweight="bold", color=color)
            ax.text(x + bw / 2, y + h - 7.6, sub, ha="center", va="top",
                    fontsize=8.1, color=INK)

    layer(78, 12, "ENTRY POINTS", NAVY, [
        ("CLI  `threatint`", "argparse; batch runs\nand CI"),
        ("Web  `threatint-web`", "Flask console,\nlive JSON API"),
        ("Static  `threatint-static`", "single-file HTML\nfor GitHub Pages"),
    ])
    layer(63, 12, "ORCHESTRATION", STEEL, [
        ("pipeline.run_pipeline", "stage sequencing,\nPipelineResult"),
        ("config.load_config", "typed YAML config,\nsource registry"),
    ])
    layer(41, 18, "STAGES", SKY, [
        ("collectors", "Http/Offline,\nfixture fallback"),
        ("normalize", "refang, detect,\ncanonicalize"),
        ("verification", "source reliability\n+ consensus"),
        ("features", "21 interpretable\nfeatures"),
        ("ml.classifier", "RandomForest /\nGradientBoosting"),
        ("clustering", "DBSCAN over\ncomposite distance"),
    ])
    layer(26, 12, "DATA MODEL", GREEN, [
        ("RawRecord", "source-specific,\nprovenance kept"),
        ("Observation", "one claim per\nsource"),
        ("Indicator", "deduped, scored,\nclassified"),
        ("Campaign", "cluster of\nrelated IOCs"),
        ("SourceReliability", "precision/recall/\nagreement"),
    ])
    layer(9, 14, "OUTPUTS", AMBER, [
        ("reporting", "console / JSON /\nCSV"),
        ("webapp", "dashboard +\nREST JSON"),
        ("artifacts", "model.joblib +\nreport.json"),
        ("deployment", "Docker, GH Pages,\nCI"),
    ])

    _arrow(ax, (50, 78), (50, 75), color=GREY)
    _arrow(ax, (50, 63), (50, 59), color=GREY)
    _arrow(ax, (50, 41), (50, 38), color=GREY)
    _arrow(ax, (50, 26), (50, 23), color=GREY)
    save(fig, "fig1_architecture.png")


# =========================================================================
# Fig 2 - pipeline flow with live counts
# =========================================================================
def fig_pipeline():
    fig, ax = plt.subplots(figsize=(14, 5.4))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")
    ax.text(50, 93, "Pipeline Stages — counts from the offline reference run",
            ha="center", fontsize=15, fontweight="bold", color=NAVY)

    stages = [
        ("1  Collect", f"{STAGES['collect']['raw_records']} raw records\n"
                       f"{STAGES['collect']['distinct_sources']} feeds", NAVY),
        ("2  Normalize\n+ Dedup", f"{STAGES['verify']['indicators']} unique\nindicators", STEEL),
        ("3  Cross-verify", f"{STAGES['verify']['multi_source']} multi-source\ncorroborated", SKY),
        ("4  Featurize", f"{STAGES['features']['feature_count']} engineered\nfeatures", GREEN),
        ("5  Classify", f"{STAGES['classify']['malicious']} malicious\n"
                        f"{STAGES['classify']['benign']} benign", AMBER),
        ("6  Cluster", f"{STAGES['cluster']['campaigns']} campaigns\n"
                       f"{STAGES['cluster']['clustered_indicators']} members", CRIMSON),
        ("7  Report", "console · JSON\nCSV · dashboard", "#6b4c9a"),
    ]
    n = len(stages)
    bw, gap = 11.6, 2.6
    x0 = 2.5
    y, h = 38, 34
    for i, (name, sub, color) in enumerate(stages):
        x = x0 + i * (bw + gap)
        _box(ax, x, y, bw, h, "", PAPER, color)
        ax.text(x + bw / 2, y + h - 7, name, ha="center", va="center",
                fontsize=9.8, fontweight="bold", color=color)
        ax.text(x + bw / 2, y + h - 15, sub, ha="center", va="top",
                fontsize=8.6, color=INK)
        if i < n - 1:
            _arrow(ax, (x + bw, y + h / 2), (x + bw + gap, y + h / 2), color=GREY)

    ax.text(50, 20, "Deterministic: seed=42 · offline fixtures · every stage independently unit-tested",
            ha="center", fontsize=9.5, color=GREY, style="italic")
    save(fig, "fig2_pipeline_flow.png")


# =========================================================================
# Fig 3 - data reduction funnel
# =========================================================================
def fig_funnel():
    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    labels = ["Raw records\ncollected", "Unique indicators\n(after dedup)",
              "Cross-verified\n(≥2 sources)", "Classified\nmalicious",
              "Clustered into\ncampaigns"]
    vals = [STAGES["collect"]["raw_records"], STAGES["verify"]["indicators"],
            STAGES["verify"]["multi_source"], STAGES["classify"]["malicious"],
            STAGES["cluster"]["clustered_indicators"]]
    colors = [NAVY, STEEL, SKY, AMBER, CRIMSON]
    y = np.arange(len(labels))[::-1]
    bars = ax.barh(y, vals, color=colors, height=0.62, zorder=3)
    for b, v in zip(bars, vals):
        ax.text(v + 1.5, b.get_y() + b.get_height() / 2, str(v), va="center",
                fontsize=12, fontweight="bold", color=INK)
    ax.set_yticks(y); ax.set_yticklabels(labels, fontsize=10)
    ax.set_xlim(0, max(vals) * 1.18)
    ax.set_xlabel("count", fontsize=10)
    ax.set_title("Data reduction through the pipeline", fontsize=14, color=NAVY)
    ax.grid(axis="x", color="#e6ecf2", zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    save(fig, "fig3_funnel.png")


# =========================================================================
# Fig 4 - distributions
# =========================================================================
def fig_distributions():
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.2))
    by_type = S["by_type"]
    order = ["ipv4", "url", "sha256", "domain", "md5"]
    tk = [k for k in order if k in by_type]
    tv = [by_type[k] for k in tk]
    tc = [STEEL, SKY, GREEN, AMBER, CRIMSON][:len(tk)]
    w, _, at = axes[0].pie(tv, labels=[f"{k}\n{v}" for k, v in zip(tk, tv)],
                           colors=tc, autopct="%1.0f%%", startangle=90,
                           wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2),
                           textprops=dict(fontsize=9.5, color=INK))
    for a in at:
        a.set_color("white"); a.set_fontweight("bold"); a.set_fontsize(8.5)
    axes[0].set_title("Indicators by type", fontsize=13, color=NAVY)

    bv = S["by_verdict"]
    vk = [k for k in ["malicious", "benign", "unknown"] if k in bv]
    vv = [bv[k] for k in vk]
    vc = {"malicious": CRIMSON, "benign": GREEN, "unknown": GREY}
    w2, _, at2 = axes[1].pie(vv, labels=[f"{k}\n{v}" for k, v in zip(vk, vv)],
                             colors=[vc[k] for k in vk], autopct="%1.0f%%", startangle=90,
                             wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2),
                             textprops=dict(fontsize=9.5, color=INK))
    for a in at2:
        a.set_color("white"); a.set_fontweight("bold"); a.set_fontsize=8.5
    axes[1].set_title("Indicators by verdict", fontsize=13, color=NAVY)
    fig.suptitle("Result composition", fontsize=15, fontweight="bold", color=NAVY, y=1.02)
    save(fig, "fig4_distributions.png")


# =========================================================================
# Fig 5 - source reliability
# =========================================================================
def fig_reliability():
    names = list(SOURCES.keys())
    metrics = ["prior", "precision", "recall", "agreement", "score"]
    labels = ["analyst\nprior", "precision", "recall", "agreement", "final\nscore"]
    colors = [GREY, STEEL, SKY, GREEN, CRIMSON]
    x = np.arange(len(names))
    width = 0.16
    fig, ax = plt.subplots(figsize=(12.5, 5.6))
    for i, (m, lab, c) in enumerate(zip(metrics, labels, colors)):
        vals = [SOURCES[n][m] for n in names]
        ax.bar(x + (i - 2) * width, vals, width, label=lab, color=c, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{n}\n(vol {SOURCES[n]['volume']})" for n in names], fontsize=9)
    ax.set_ylabel("value in [0,1]"); ax.set_ylim(0, 1.12)
    ax.legend(ncol=5, fontsize=9, frameon=False, loc="upper center")
    ax.set_title("Source reliability — static prior blended with dynamic consensus signals",
                 fontsize=13.5, color=NAVY)
    ax.grid(axis="y", color="#e6ecf2", zorder=0)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    save(fig, "fig5_source_reliability.png")


# =========================================================================
# Fig 6 - feature importance
# =========================================================================
def fig_importance():
    fi = {k: v for k, v in TRAIN["feature_importance"].items() if v > 0}
    top = sorted(fi.items(), key=lambda kv: kv[1])[-14:]
    names = [k for k, _ in top]
    vals = [v for _, v in top]
    fig, ax = plt.subplots(figsize=(10.5, 6))
    grad = [SKY if v < 0.1 else STEEL if v < 0.2 else CRIMSON for v in vals]
    ax.barh(names, vals, color=grad, zorder=3)
    for i, v in enumerate(vals):
        ax.text(v + 0.004, i, f"{v:.3f}", va="center", fontsize=8.6, color=INK)
    ax.set_xlabel("Gini importance")
    ax.set_xlim(0, max(vals) * 1.16)
    ax.set_title("Classifier feature importance (random forest, 21 features)",
                 fontsize=13.5, color=NAVY)
    ax.grid(axis="x", color="#e6ecf2", zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    save(fig, "fig6_feature_importance.png")


# =========================================================================
# Fig 7 - classifier evaluation (confusion + ROC), replicated deterministically
# =========================================================================
def _replicate_eval():
    from sklearn.metrics import confusion_matrix, roc_curve
    from sklearn.model_selection import train_test_split

    seed = int(CFG.pipeline.random_seed)
    values, labels = generate_corpus(n=1200, seed=seed)
    ex = FeatureExtractor(CFG)
    inds, ys = [], []
    for v, l in zip(values, labels):
        t = detect_type(v)
        if t is None:
            continue
        c = canonicalize(v, t)
        if c is None:
            continue
        inds.append(Indicator(value=c, indicator_type=t, source_count=1, reliability_score=0.5))
        ys.append(l)
    X = np.asarray(ex.transform(inds), dtype=float)
    y = np.array(ys, dtype=int)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=seed, stratify=y)
    est = _make_estimator(CFG.ml, seed)
    est.fit(Xtr, ytr)
    yp = est.predict(Xte)
    yprob = est.predict_proba(Xte)[:, 1]
    cm = confusion_matrix(yte, yp)
    fpr, tpr, _ = roc_curve(yte, yprob)
    return cm, fpr, tpr


def fig_eval():
    cm, fpr, tpr = _replicate_eval()
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.4))

    axes[0].imshow(cm, cmap="Blues", vmin=0)
    axes[0].set_xticks([0, 1]); axes[0].set_yticks([0, 1])
    axes[0].set_xticklabels(["pred benign", "pred malicious"], fontsize=9.5)
    axes[0].set_yticklabels(["true benign", "true malicious"], fontsize=9.5)
    for i in range(2):
        for j in range(2):
            axes[0].text(j, i, str(cm[i, j]), ha="center", va="center",
                         fontsize=17, fontweight="bold",
                         color="white" if cm[i, j] > cm.max() / 2 else INK)
    axes[0].set_title("Confusion matrix (held-out test set)", fontsize=12.5, color=NAVY)

    axes[1].plot(fpr, tpr, color=CRIMSON, lw=2.4, label=f"ROC (AUC = {TRAIN['roc_auc']:.3f})")
    axes[1].plot([0, 1], [0, 1], color=GREY, lw=1.2, ls="--", label="chance")
    axes[1].fill_between(fpr, tpr, color=CRIMSON, alpha=0.10)
    axes[1].set_xlabel("false positive rate"); axes[1].set_ylabel("true positive rate")
    axes[1].set_title("ROC curve", fontsize=12.5, color=NAVY)
    axes[1].legend(fontsize=9.5, frameon=False, loc="lower right")
    axes[1].grid(color="#e6ecf2")
    for s in ("top", "right"):
        axes[1].spines[s].set_visible(False)

    acc, prec, rec, f1 = TRAIN["accuracy"], TRAIN["precision"], TRAIN["recall"], TRAIN["f1"]
    fig.suptitle(
        f"Classifier evaluation — acc {acc:.3f} · precision {prec:.3f} · recall {rec:.3f} · F1 {f1:.3f}",
        fontsize=13.5, fontweight="bold", color=NAVY, y=1.02)
    save(fig, "fig7_classifier_eval.png")


# =========================================================================
# Fig 8 - campaigns
# =========================================================================
def fig_campaigns():
    camps = sorted(CAMPAIGNS, key=lambda c: c["size"])
    labels = [f"{c['campaign_id']}\n{c['label'].replace('campaign: ', '')[:28]}" for c in camps]
    sizes = [c["size"] for c in camps]
    pmal = [c["mean_malicious_probability"] for c in camps]
    fig, ax = plt.subplots(figsize=(12.5, 6))
    cmap = plt.cm.YlOrRd
    colors = [cmap(0.35 + 0.55 * p) for p in pmal]
    bars = ax.barh(range(len(camps)), sizes, color=colors, zorder=3, height=0.66)
    for i, (b, c) in enumerate(zip(bars, camps)):
        ax.text(b.get_width() + 0.15, b.get_y() + b.get_height() / 2,
                f"{c['size']}  (p̄={c['mean_malicious_probability']:.2f})",
                va="center", fontsize=9, color=INK)
    ax.set_yticks(range(len(camps))); ax.set_yticklabels(labels, fontsize=8.6)
    ax.set_xlabel("campaign size (member indicators)")
    ax.set_xlim(0, max(sizes) * 1.25)
    ax.set_title("Attack campaigns discovered by DBSCAN clustering", fontsize=13.5, color=NAVY)
    ax.grid(axis="x", color="#e6ecf2", zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=plt.Normalize(0.5, 1.0))
    cb = fig.colorbar(sm, ax=ax, pad=0.01, fraction=0.03)
    cb.set_label("mean malicious probability", fontsize=9)
    save(fig, "fig8_campaigns.png")


# =========================================================================
# Fig 9 - per-source contribution vs dedup
# =========================================================================
def fig_contribution():
    raw = {}
    for col in build_collectors(CFG, offline=True):
        raw[col.source.name] = len(col.fetch())
    uniq = {n: 0 for n in raw}
    for ind in INDICATORS:
        for src in ind.get("sources", []):
            if src in uniq:
                uniq[src] += 1
    names = list(raw.keys())
    x = np.arange(len(names)); w = 0.38
    fig, ax = plt.subplots(figsize=(11.5, 5.4))
    b1 = ax.bar(x - w / 2, [raw[n] for n in names], w, label="raw records", color=STEEL, zorder=3)
    b2 = ax.bar(x + w / 2, [uniq[n] for n in names], w, label="unique indicators", color=SKY, zorder=3)
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.3, str(int(b.get_height())),
                    ha="center", fontsize=9, color=INK)
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=9.5)
    ax.set_ylabel("count")
    ax.set_title("Per-feed contribution and deduplication effect", fontsize=13.5, color=NAVY)
    ax.legend(frameon=False, fontsize=10)
    ax.grid(axis="y", color="#e6ecf2", zorder=0)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    save(fig, "fig9_contribution.png")


if __name__ == "__main__":
    fig_architecture()
    fig_pipeline()
    fig_funnel()
    fig_distributions()
    fig_reliability()
    fig_importance()
    fig_eval()
    fig_campaigns()
    fig_contribution()
    print("\nall figures written to", FIG)
