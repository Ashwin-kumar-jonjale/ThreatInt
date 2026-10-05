"""Web dashboard tests: the Flask layer over the pipeline result."""

from __future__ import annotations

import pytest

pytest.importorskip("flask")

from threatint.pipeline import run_pipeline
from threatint.webapp.app import create_app


@pytest.fixture(scope="module")
def client(config):
    result = run_pipeline(config=config, offline=True, corpus_size=600)
    app = create_app(result, config)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def test_index_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "ThreatInt" in body
    assert "Operations Console" in body


def test_summary_endpoint(client):
    resp = client.get("/api/summary")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["indicators"] > 0
    assert "malicious" in data
    assert "campaigns" in data


def test_indicators_endpoint_pagination_and_filters(client):
    data = client.get("/api/indicators?limit=5").get_json()
    assert data["total"] > 0
    assert len(data["items"]) <= 5
    assert all("defanged" in item for item in data["items"])

    malicious = client.get("/api/indicators?verdict=malicious&limit=100").get_json()
    assert all(item["verdict"] == "malicious" for item in malicious["items"])

    urls = client.get("/api/indicators?type=url&limit=100").get_json()
    assert all(item["indicator_type"] == "url" for item in urls["items"])


def test_campaigns_and_sources_endpoints(client):
    camps = client.get("/api/campaigns").get_json()
    assert camps["total"] == len(camps["items"])
    assert camps["total"] > 0
    assert all("members" in c for c in camps["items"])

    sources = client.get("/api/sources").get_json()
    assert len(sources["items"]) > 0
    assert all("score" in s for s in sources["items"])


def test_healthz(client):
    data = client.get("/healthz").get_json()
    assert data["status"] == "ok"
    assert data["generated_at"]


def test_static_export_is_self_contained(config):
    from threatint.webapp.static_export import render_static

    html = render_static(offline=True)
    assert "ThreatInt" in html
    assert "Operations Console" in html
    # Data is inlined, so the page needs no backend.
    assert '"indicators"' in html
    assert "camp-" in html
