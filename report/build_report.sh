#!/usr/bin/env bash
# Build the ThreatInt research report PDF.
#
#   1. run the pipeline and dump data
#   2. regenerate all figures
#   3. compile the LaTeX (twice, for the TOC and cross-references)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PY:-.venv/bin/python}"

echo "==> capturing pipeline data"
"$PY" - <<'PY'
import json
from threatint.config import load_config
from threatint.pipeline import run_pipeline
from threatint.reporting import render_console

cfg = load_config("config/config.yaml")
res = run_pipeline(config=cfg, offline=True, corpus_size=1200)
import pathlib
pathlib.Path("report/data").mkdir(parents=True, exist_ok=True)
json.dump(res.to_dict(), open("report/data/result.json", "w"), indent=2, default=str)
open("report/data/console.txt", "w").write(render_console(res, top=20))
print("data written")
PY

echo "==> generating figures"
"$PY" report/make_figures.py

echo "==> compiling LaTeX"
cd report
pdflatex -interaction=nonstopmode -halt-on-error threatint_report.tex > /tmp/tex1.log 2>&1 || {
    echo "first pass failed; tail:"; tail -30 /tmp/tex1.log; exit 1; }
pdflatex -interaction=nonstopmode -halt-on-error threatint_report.tex > /tmp/tex2.log 2>&1 || {
    echo "second pass failed; tail:"; tail -30 /tmp/tex2.log; exit 1; }

echo "==> done: report/threatint_report.pdf"
ls -lh threatint_report.pdf
