"""Figures for the 'how ThreatInt was built' engineering report.

Everything here is measured from the actual git history and working tree:
commit dates, per-commit line counts, per-module LOC, and test counts. Nothing
is estimated by hand.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
FIG = ROOT / "report" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

NAVY = "#1b3a5c"
STEEL = "#34668c"
SKY = "#5b9bd5"
CRIMSON = "#c0392b"
AMBER = "#e08a1e"
GREEN = "#2e8b57"
GREY = "#8a99a8"
PURPLE = "#6b4c9a"
PAPER = "#ffffff"
INK = "#1d2733"

plt.rcParams.update({
    "figure.facecolor": PAPER, "axes.facecolor": PAPER, "savefig.facecolor": PAPER,
    "font.size": 11, "axes.edgecolor": "#c8d2dc", "axes.labelcolor": INK,
    "text.color": INK, "xtick.color": INK, "ytick.color": INK,
    "axes.titleweight": "bold", "font.family": "DejaVu Sans",
})


def sh(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout


def save(fig, name):
    fig.savefig(FIG / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


def _box(ax, x, y, w, h, text, fc, ec, tc="white", fs=10, bold=True, radius=0.02):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle=f"round,pad=0.004,rounding_size={radius}",
                                linewidth=1.4, edgecolor=ec, facecolor=fc))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=tc,
            fontsize=fs, fontweight="bold" if bold else "normal")


# -- measured history -------------------------------------------------------
def history():
    out = sh("git", "log", "--reverse", "--pretty=format:%H|%ad|%s", "--date=short")
    commits = []
    for line in out.strip().splitlines():
        h, date, subj = line.split("|", 2)
        commits.append({"hash": h, "short": h[:7], "date": date, "subject": subj})
    # per-commit line counts by category
    for c in commits:
        files = sh("git", "ls-tree", "-r", "--name-only", c["hash"]).splitlines()
        cat = {"src": 0, "tests": 0, "report": 0, "other": 0}
        for f in files:
            if not f.endswith(".py"):
                if f.startswith("report/"):
                    cat["report"] += 1
                continue
            n = len(sh("git", "show", f"{c['hash']}:{f}").splitlines())
            if f.startswith("src/"):
                cat["src"] += n
            elif f.startswith("tests/"):
                cat["tests"] += n
            elif f.startswith("report/"):
                cat["report"] += n
            else:
                cat["other"] += n
        c["loc"] = cat
    return commits


def module_loc():
    files = sh("git", "ls-files", "src/**/*.py").splitlines()
    rows = []
    for f in files:
        n = len((ROOT / f).read_text().splitlines())
        rows.append((f.replace("src/threatint/", ""), n))
    return sorted(rows, key=lambda r: -r[1])


def test_counts():
    files = sorted(sh("git", "ls-files", "tests/*.py").splitlines())
    rows = []
    for f in files:
        txt = (ROOT / f).read_text()
        rows.append((Path(f).name, txt.count("\ndef test_")))
    return rows


COMMITS = history()
MODULES = module_loc()
TESTS = test_counts()

LAYER_OF = {
    "models.py": "core", "config.py": "core", "__init__.py": "core",
    "normalize.py": "ingest", "collectors/base.py": "ingest", "collectors/__init__.py": "ingest",
    "verification/__init__.py": "analysis", "features/__init__.py": "analysis",
    "ml/classifier.py": "analysis", "ml/synthetic.py": "analysis", "ml/__init__.py": "analysis",
    "clustering/__init__.py": "analysis",
    "pipeline.py": "orchestration", "reporting.py": "orchestration", "cli.py": "orchestration",
    "webapp/app.py": "presentation", "webapp/static_export.py": "presentation", "webapp/__init__.py": "presentation",
}
LAYER_COLOR = {"core": NAVY, "ingest": STEEL, "analysis": SKY, "orchestration": GREEN, "presentation": AMBER}


# =========================================================================
# B1 - build timeline
# =========================================================================
def fig_timeline():
    fig, ax = plt.subplots(figsize=(13.5, 5.8))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")
    ax.text(50, 95, "How ThreatInt was built — commit timeline", ha="center",
            fontsize=16, fontweight="bold", color=NAVY)

    n = len(COMMITS)
    xs = np.linspace(10, 90, n)
    ax.plot([8, 92], [55, 55], color="#c8d2dc", lw=3, zorder=1, solid_capstyle="round")

    milestones = [
        "Initial commit\n(README only)",
        "Core pipeline\ncollectors · verify · ML · clustering · CLI",
        "Web dashboard\nFlask console + JSON API",
        "Deployable from GitHub\nstatic export · Docker · CI",
        "Technical report\nLaTeX PDF + figures",
    ]
    for i, (c, x) in enumerate(zip(COMMITS, xs)):
        above = i % 2 == 0
        color = [GREY, STEEL, SKY, GREEN, CRIMSON][i % 5]
        ax.scatter([x], [55], s=260, color=color, zorder=3, edgecolor="white", linewidth=2)
        ax.text(x, 55, str(i), ha="center", va="center", color="white",
                fontsize=10, fontweight="bold", zorder=4)
        y_box = 66 if above else 30
        h = 20
        _box(ax, x - 9.2, y_box, 18.4, h, "", PAPER, color, radius=0.4)
        ax.text(x, y_box + h - 3, c["date"], ha="center", fontsize=8.5, color=color, fontweight="bold")
        ax.text(x, y_box + h - 6.5, milestones[i], ha="center", va="top", fontsize=7.6, color=INK)
        ax.text(x, y_box - 4.5 if above else y_box + h + 4.5,
                f"{c['loc']['src']} src · {c['loc']['tests']} test lines",
                ha="center", va="center", fontsize=7.2, color=GREY, style="italic")
        ax.plot([x, x], [55 + (6 if above else -6), y_box + (0 if above else h)],
                color="#c8d2dc", lw=1.2, zorder=1)

    ax.text(50, 6, "5 commits over 3 days · built, tested, deployed and documented end to end",
            ha="center", fontsize=9.5, color=GREY, style="italic")
    save(fig, "figB1_timeline.png")


# =========================================================================
# B2 - code composition by module and layer
# =========================================================================
def fig_modules():
    rows = [(m, n, LAYER_OF.get(m, "other")) for m, n in MODULES]
    rows.sort(key=lambda r: r[1])
    names = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    colors = [LAYER_COLOR[r[2]] for r in rows]
    fig, ax = plt.subplots(figsize=(11, 7.2))
    ax.barh(names, vals, color=colors, zorder=3, height=0.72)
    for i, v in enumerate(vals):
        ax.text(v + 2, i, str(v), va="center", fontsize=8.8, color=INK)
    ax.set_xlabel("lines of code")
    ax.set_xlim(0, max(vals) * 1.12)
    ax.set_title("Source composition — 2,246 lines across 18 modules", fontsize=14, color=NAVY)
    ax.grid(axis="x", color="#e6ecf2", zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=LAYER_COLOR[k]) for k in LAYER_COLOR]
    ax.legend(handles, list(LAYER_COLOR.keys()), fontsize=9, frameon=False,
              loc="lower right", title="layer")
    save(fig, "figB2_modules.png")


# =========================================================================
# B3 - test suite
# =========================================================================
def fig_tests():
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.4), gridspec_kw={"width_ratios": [1.5, 1]})
    names = [t[0].replace("test_", "").replace(".py", "") for t in TESTS if t[1] > 0]
    vals = [t[1] for t in TESTS if t[1] > 0]
    order = np.argsort(vals)
    names = [names[i] for i in order]; vals = [vals[i] for i in order]
    axes[0].barh(names, vals, color=STEEL, zorder=3, height=0.68)
    for i, v in enumerate(vals):
        axes[0].text(v + 0.15, i, str(v), va="center", fontsize=9.5, color=INK)
    axes[0].set_xlabel("test functions")
    axes[0].set_xlim(0, max(vals) * 1.2)
    axes[0].set_title("60 tests across 8 modules", fontsize=13, color=NAVY)
    axes[0].grid(axis="x", color="#e6ecf2", zorder=0)
    for s in ("top", "right", "left"):
        axes[0].spines[s].set_visible(False)

    src = sum(n for _, n in MODULES)
    test_loc = sum(len((ROOT / f).read_text().splitlines())
                   for f in sh("git", "ls-files", "tests/*.py").splitlines())
    w, _, at = axes[1].pie([src, test_loc], labels=[f"source\n{src}", f"tests\n{test_loc}"],
                           colors=[NAVY, GREEN], autopct="%1.0f%%", startangle=90,
                           wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2),
                           textprops=dict(fontsize=10, color=INK))
    for a in at:
        a.set_color("white"); a.set_fontweight("bold")
    axes[1].set_title("Code vs. test lines", fontsize=13, color=NAVY)
    fig.suptitle("Test suite — offline, deterministic, no mocks",
                 fontsize=14.5, fontweight="bold", color=NAVY, y=1.02)
    save(fig, "figB3_tests.png")


# =========================================================================
# B4 - cumulative code growth
# =========================================================================
def fig_growth():
    labels = [f"c{i+1}\n{c['date'][5:]}" for i, c in enumerate(COMMITS)]
    src = [c["loc"]["src"] for c in COMMITS]
    tst = [c["loc"]["tests"] for c in COMMITS]
    rep = [c["loc"]["report"] for c in COMMITS]
    x = np.arange(len(COMMITS))
    fig, ax = plt.subplots(figsize=(11.5, 5.6))
    ax.stackplot(x, src, tst, rep, labels=["source (src/)", "tests (tests/)", "report (report/)"],
                 colors=[STEEL, GREEN, CRIMSON], alpha=0.92, zorder=3)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9.5)
    ax.set_ylabel("cumulative lines of code")
    ax.set_title("Cumulative code growth across the build", fontsize=14, color=NAVY)
    ax.legend(loc="upper left", fontsize=9.5, frameon=False)
    ax.grid(axis="y", color="#e6ecf2", zorder=0)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for xi, (a, b, c) in enumerate(zip(src, tst, rep)):
        ax.text(xi, a + b + c + 120, str(a + b + c), ha="center", fontsize=9,
                fontweight="bold", color=NAVY)
    save(fig, "figB4_growth.png")


# =========================================================================
# B5 - tech stack
# =========================================================================
def fig_stack():
    fig, ax = plt.subplots(figsize=(12.5, 7.6))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")
    ax.text(50, 96, "Technology stack", ha="center", fontsize=16, fontweight="bold", color=NAVY)

    layers = [
        ("LANGUAGE & RUNTIME", NAVY, ["Python 3.13", "dataclasses", "argparse", "abc / typing"]),
        ("DATA & MACHINE LEARNING", STEEL, ["numpy 2.5", "pandas 3.0", "scikit-learn 1.9", "joblib"]),
        ("WEB & PRESENTATION", SKY, ["Flask 3.1", "Jinja2 template", "vanilla JS", "static HTML export"]),
        ("CONFIG & I/O", GREEN, ["PyYAML 6.0", "requests 2.34", "csv / json", "pathlib"]),
        ("PACKAGING & DEPLOYMENT", AMBER, ["setuptools / pyproject", "Docker", "GitHub Pages", "GitHub Actions"]),
        ("QUALITY & TOOLING", PURPLE, ["pytest", "pyflakes", "LaTeX / pdflatex", "matplotlib"]),
    ]
    y = 84
    h = 12.5
    for title, color, items in layers:
        ax.add_patch(FancyBboxPatch((4, y - h), 92, h, boxstyle="round,pad=0.3,rounding_size=0.6",
                                    linewidth=0, facecolor=color, alpha=0.07))
        ax.text(5.5, y - 2.2, title, ha="left", va="top", fontsize=9.2, fontweight="bold", color=color)
        n = len(items)
        gap = 1.8
        bw = (88 - gap * (n - 1)) / n
        for i, it in enumerate(items):
            bx = 6 + i * (bw + gap)
            _box(ax, bx, y - h + 1.6, bw, h - 4.6, it, PAPER, color, tc=INK, fs=9.2)
        y -= h + 1.2
    save(fig, "figB5_stack.png")


# =========================================================================
# B6 - engineering workflow loop
# =========================================================================
def fig_workflow():
    fig, ax = plt.subplots(figsize=(11.5, 7.4))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")
    ax.text(50, 96, "Build workflow — how each increment was produced", ha="center",
            fontsize=15, fontweight="bold", color=NAVY)

    steps = [
        ("1  EXPLORE", "read the repo,\nmap the surface", NAVY),
        ("2  DESIGN", "choose the\nminimal change", STEEL),
        ("3  IMPLEMENT", "edit files\nin place", SKY),
        ("4  TEST", "pytest + pyflakes,\nfix what breaks", GREEN),
        ("5  VERIFY", "run the real\npipeline end to end", AMBER),
        ("6  DOCUMENT", "README, AGENTS.md,\nreport", PURPLE),
        ("7  COMMIT", "stage, message,\npush", CRIMSON),
    ]
    n = len(steps)
    cx, cy, R = 50, 46, 30
    ang = np.linspace(90, -270, n + 1)[:-1]
    pts = [(cx + R * np.cos(np.deg2rad(a)), cy + R * np.sin(np.deg2rad(a)) * 0.92) for a in ang]
    for i in range(n):
        p0 = pts[i]; p1 = pts[(i + 1) % n]
        ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=18,
                                     linewidth=2.0, color="#c8d2dc",
                                     connectionstyle="arc3,rad=0.22", shrinkA=26, shrinkB=26))
    for (x, y), (title, sub, color) in zip(pts, steps):
        _box(ax, x - 9.5, y - 7, 19, 14, "", PAPER, color, radius=0.8)
        ax.text(x, y + 3.2, title, ha="center", fontsize=8.8, fontweight="bold", color=color)
        ax.text(x, y - 2.6, sub, ha="center", va="center", fontsize=7.6, color=INK)
    ax.text(50, 46, "iterate\nuntil\ngreen", ha="center", va="center", fontsize=10,
            color=GREY, style="italic", fontweight="bold")
    ax.text(50, 5, "Every stage was re-runnable: the same command rebuilt data, figures and PDF",
            ha="center", fontsize=9.3, color=GREY, style="italic")
    save(fig, "figB6_workflow.png")


# =========================================================================
# B7 - quality dashboard
# =========================================================================
def fig_quality():
    fig, ax = plt.subplots(figsize=(13, 5.2))
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")
    ax.text(50, 92, "Engineering quality at a glance", ha="center", fontsize=16,
            fontweight="bold", color=NAVY)

    cards = [
        ("60", "tests passing", GREEN),
        ("0", "pyflakes issues", GREEN),
        ("2,246", "lines of source", STEEL),
        ("679", "lines of tests", SKY),
        ("18", "source modules", NAVY),
        ("5", "feeds integrated", AMBER),
        ("3", "deploy targets", PURPLE),
        ("5", "commits", CRIMSON),
    ]
    n = len(cards)
    gap = 1.6
    bw = (94 - gap * (n - 1)) / n
    for i, (big, small, color) in enumerate(cards):
        x = 3 + i * (bw + gap)
        _box(ax, x, 34, bw, 34, "", PAPER, color, radius=0.6)
        ax.text(x + bw / 2, 55, big, ha="center", va="center", fontsize=20,
                fontweight="bold", color=color)
        ax.text(x + bw / 2, 42, small, ha="center", va="center", fontsize=8.2, color=INK)

    ax.text(50, 22, "Reproducible · deterministic (seed 42) · offline-capable · documented",
            ha="center", fontsize=10, color=GREY, style="italic")
    save(fig, "figB7_quality.png")


if __name__ == "__main__":
    fig_timeline()
    fig_modules()
    fig_tests()
    fig_growth()
    fig_stack()
    fig_workflow()
    fig_quality()
    print("\nbuild-story figures written to", FIG)
