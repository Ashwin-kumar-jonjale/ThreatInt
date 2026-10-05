# AGENTS.md — ThreatInt

## What this repo is

An automated threat-intelligence pipeline: collect indicators from feeds →
normalize/dedup → cross-verify source reliability → featurize → ML classify →
cluster into campaigns → report. Greenfield Python project (src layout).

## Layout

- `src/threatint/` — package (`pip install -e .`; console script `threatint`)
  - `models.py` — data models. NOTE: this is the *data-model* module; the ML
    package is `ml/` (renamed to avoid a module/package clash).
  - `normalize.py` — refang/validate/canonicalize/extract.
  - `collectors/base.py` — `BaseCollector`, `OfflineCollector`, `HttpCollector`.
  - `verification/` — source reliability + indicator trust scoring.
  - `features/` — `FEATURE_NAMES` + `FeatureExtractor` (fixed vector order).
  - `ml/` — `classifier.py`, `synthetic.py` (bootstrap corpus).
  - `clustering/` — composite-distance DBSCAN + campaign labelling.
  - `pipeline.py` — stage orchestration (`run_pipeline`, `PipelineResult`).
  - `reporting.py` — console/JSON/CSV output.
  - `webapp/` — Flask dashboard (`app.py`), static exporter
    (`static_export.py`), `templates/dashboard.html`. Console scripts
    `threatint-web` (live) and `threatint-static` (single-file export).
  - `data/` — bundled fixture CSVs (offline mode).
- `config/config.yaml` — feeds, thresholds, model, clustering knobs.
- `scripts/generate_fixtures.py` — deterministic fixture regeneration.
- `Dockerfile` — serves the live console; bakes `/app/dist/index.html`.
- `.github/workflows/` — `ci.yml` (lint+tests) and `publish-dashboard.yml`
  (static dashboard → GitHub Pages on push to `main`).
- `tests/` — pytest suite.

## Commands

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q                 # full suite (offline, deterministic)
.venv/bin/threatint --offline                 # reproducible end-to-end run
.venv/bin/threatint                           # live feeds, per-source fixture fallback
.venv/bin/threatint-web --offline             # web dashboard on :12000
.venv/bin/python scripts/generate_fixtures.py # regenerate fixtures (fixed seed)
.venv/bin/python -m pyflakes src/threatint scripts tests
```

## Conventions / gotchas

- **Never** make network access mandatory: every source has a fixture and
  `HttpCollector` falls back on any fetch error. Keep `--offline` working.
- Determinism matters: ML and clustering seed from `pipeline.random_seed`.
  Tests assert on offline output, so don't introduce unseeded randomness.
- `FEATURE_NAMES` order is a contract shared by classifier and clustering.
  Changing it invalidates saved models in `artifacts/`.
- Clustering uses a *precomputed* composite distance
  (`0.6*cosine + 0.4*(1-tag_jaccard)`), tuned `eps: 0.22` for the fixture set.
  Re-tune if features or fixtures change materially.
- Indicators are untrusted input: validate/parse before use; filter private
  and loopback IPs. No secrets in code/config — tokens come from env vars.
- `artifacts/` and `.venv/` are gitignored; don't commit them.
