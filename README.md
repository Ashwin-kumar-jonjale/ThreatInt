# ThreatInt

Automated threat-intelligence pipeline that replaces manual, error-prone
cross-checking of hundreds of daily alerts. It collects malicious indicators
(IPs, domains, URLs, hashes) from multiple trusted feeds, cross-verifies how
much each source can be trusted, classifies indicators with machine learning,
and clusters related indicators into attack campaigns.

```
 collect ──▶ normalize ──▶ cross-verify ──▶ featurize ──▶ classify ──▶ cluster ──▶ report
  feeds      dedup/validate   source trust     vectors      ML verdict   campaigns    JSON/CSV
```

## Why it exists

Analysts spend their day re-deriving the same conclusions: "is this IP really
bad?", "which of these 300 alerts belong together?". ThreatInt automates the
mechanical parts — collection, deduplication, corroboration counting, scoring,
grouping — so analysts only review the ranked output.

## Features

- **Multi-source collection** — pluggable collectors with an offline fixture
  fallback so a flaky or forbidden feed degrades to last-known-good data
  instead of aborting the run.
- **Normalization & validation** — refangs defanged indicators
  (`hxxp://`, `1[.]2[.]3[.]4`), canonicalizes URLs/domains, validates types,
  and rejects benign/private noise.
- **Cross-verification** — every feed gets a dynamic reliability score
  (precision, recall, inter-source agreement) blended with an analyst prior;
  every indicator gets a reliability-weighted trust score with a corroboration
  bonus.
- **ML classification** — a scikit-learn classifier predicts malicious
  probability from interpretable lexical/structural features, trained on
  analyst labels when available or a seeded synthetic bootstrap corpus
  otherwise.
- **Campaign clustering** — DBSCAN over a composite distance blending lexical
  similarity with threat-tag overlap, so related indicators group into named
  campaigns while isolated indicators stay as noise.
- **Auditable output** — JSON, indicators CSV, campaigns CSV, and a console
  report; the trained model and its evaluation metrics are persisted.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Quick start

Run fully offline against the bundled fixtures (reproducible, no network):

```bash
.venv/bin/threatint --offline
```

Run against live feeds (falls back to fixtures per-source on failure):

```bash
.venv/bin/threatint \
    --out-json artifacts/report.json \
    --out-indicators artifacts/indicators.csv \
    --out-campaigns artifacts/campaigns.csv
```

Train on your own analyst-reviewed labels instead of the synthetic corpus:

```bash
.venv/bin/threatint --labels data/analyst_labels.csv
```

`analyst_labels.csv` needs two columns:

```csv
indicator,label
http://paypal-verify-login.xyz/verify,malicious
https://github.com/,benign
```

Reuse a previously trained model (skip retraining):

```bash
.venv/bin/threatint --use-saved-model --model-path artifacts/classifier.joblib
```

## Web dashboard

A read-only operations console over a pipeline run — useful for eyeballing
results without touching the CLI.

```bash
.venv/bin/pip install -e ".[web]"
.venv/bin/threatint-web --offline --port 12000
# or: scripts/run_webapp.sh 12000 [--live]
```

It runs the pipeline once at startup (offline by default, so it is
deterministic and needs no network) and serves:

- an **Indicators** table with malicious probability, verdict, type, source
  count, reliability and campaign — filterable by verdict/type and free text,
- **Campaigns** as cards showing members, shared tags and aggregate scores,
- **Source Reliability** with per-feed precision/recall/agreement/volume.

JSON endpoints (`/api/summary`, `/api/indicators`, `/api/campaigns`,
`/api/sources`, `/healthz`) are available for automation. Indicator values are
rendered defanged (e.g. `hxxp://evil[.]xyz`) and escaped client-side.

### Deploy it

**GitHub Pages (static, no server).** `.github/workflows/publish-dashboard.yml`
renders the dashboard to a single self-contained HTML file and publishes it to
Pages on every push to `main`. Enable it once under
**Settings → Pages → Build and deployment → Source: GitHub Actions**, and the
console goes live at `https://<owner>.github.io/<repo>/`. No secrets, no
network — the pipeline runs offline against the fixtures.

To build the same file locally:

```bash
.venv/bin/threatint-static --offline --out dist/index.html
```

**Docker.** The `Dockerfile` installs the package, bakes a static dashboard
into the image, and serves the live Flask console:

```bash
docker build -t threatint .
docker run -p 12000:12000 threatint
# open http://localhost:12000
```

The baked static file lives at `/app/dist/index.html` inside the image if you
only want to copy it out for a static host.

## Technical research report

A deep, research-style write-up of the whole system — architecture, data model,
a module-by-module function reference, the reliability/consensus mathematics,
experimental results, security, limitations and future work — lives in
`report/`.

- Source: `report/threatint_report.tex`
- Built PDF: `report/threatint_report.pdf` (20 pages, 9 figures)

Every quantitative figure and chart is generated from a real deterministic
offline run, not fabricated. Rebuild it with:

```bash
bash report/build_report.sh   # captures data, regenerates figures, compiles PDF
```

This needs `pdflatex` (TeX Live) and `matplotlib`; the script runs the pipeline
and `report/make_figures.py` first, so the numbers in the PDF always match the
current code.

## CLI reference

| Flag | Purpose |
| --- | --- |
| `--config PATH` | Config file (defaults to `config/config.yaml`). |
| `--offline` | Use bundled fixtures only; never touch the network. |
| `--labels PATH` | Supervised training data (`indicator,label`). |
| `--model-path PATH` | Where to save/load the classifier. |
| `--use-saved-model` | Load a saved model instead of retraining. |
| `--no-train` | Skip training (verdicts stay `unknown`; clustering still runs). |
| `--corpus-size N` | Synthetic bootstrap corpus size. |
| `--out-json PATH` | Full results as JSON. |
| `--out-indicators PATH` | Indicators as CSV. |
| `--out-campaigns PATH` | Campaigns as CSV. |
| `--top N` | Rows shown in the console report. |
| `--quiet` / `-v` | Less / more logging. |

## Configuration

`config/config.yaml` controls feeds, thresholds and model settings.

```yaml
pipeline:
  min_sources_for_verification: 2   # corroboration threshold
  malicious_threshold: 0.5          # malicious probability cutoff
  min_reliability_for_clustering: 0.35
  random_seed: 42

sources:
  - name: abusech_feodo
    kind: ipv4
    reliability_prior: 0.9          # analyst-assigned trust prior
    url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
    fixture: abusech_feodo.csv      # offline fallback

ml:
  model: random_forest              # or gradient_boosting
  n_estimators: 300
  model_path: artifacts/classifier.joblib

clustering:
  eps: 0.22                         # composite-distance neighbourhood
  min_samples: 2
```

Add a source by appending an entry and dropping a matching fixture CSV in
`src/threatint/data/`. Use `api_key_env` to pull a token from an environment
variable (never hard-code credentials).

## How the pieces work

| Module | Responsibility |
| --- | --- |
| `threatint.normalize` | Refang, validate, canonicalize, extract indicators. |
| `threatint.collectors` | `OfflineCollector` / `HttpCollector` + factory. |
| `threatint.verification` | Source reliability + indicator trust scoring. |
| `threatint.features` | Fixed-order numeric feature vectors. |
| `threatint.ml.classifier` | Train / predict / persist the ML model. |
| `threatint.ml.synthetic` | Seeded bootstrap corpus generator. |
| `threatint.clustering` | Composite-distance DBSCAN + campaign labelling. |
| `threatint.pipeline` | Stage orchestration and `PipelineResult`. |
| `threatint.reporting` | Console / JSON / CSV rendering. |

### Source reliability

Each feed's score blends its analyst prior with dynamic signals measured
against the cross-source consensus:

- **precision** — share of a feed's reports that reached consensus
  (reported by ≥ `min_sources_for_verification` distinct sources),
- **recall** — share of all consensus indicators the feed reported,
- **agreement** — mean pairwise Jaccard overlap with every other feed.

A volume factor dampens feeds with very few reports so they stay near their
prior rather than being judged on a tiny sample.

### Indicator trust

An indicator's reliability is the reliability-weighted average of the
confidences of the sources that reported it, plus a saturating corroboration
bonus once independent sources agree.

### Clustering

Pairwise distance is `0.6 · cosine(feature vectors) + 0.4 · (1 − tag Jaccard)`.
DBSCAN then groups neighbours and treats sparse indicators as noise.
Benign-verdict indicators are excluded, so a benign host is never reported as
part of an attack campaign.

## Reproducibility

The bundled fixtures are generated deterministically:

```bash
.venv/bin/python scripts/generate_fixtures.py
```

Every run seeds ML and clustering from `pipeline.random_seed`, so
`--offline` runs produce identical results on any machine.

## Tests

```bash
.venv/bin/python -m pytest -q
```

The suite covers normalization edge cases, verification math, feature
extraction, classifier quality/persistence, clustering semantics, and the
full offline pipeline plus CLI.

## Security notes

- No credentials are stored in code or config; API tokens are read from
  environment variables via `api_key_env`.
- Feeds are fetched over HTTPS only.
- Indicators are treated as untrusted input: URLs, domains and hashes are
  parsed and validated before use, and private/loopback addresses are filtered.
- The offline fixture path means the pipeline can run in air-gapped or
  restricted environments with no outbound network access.
