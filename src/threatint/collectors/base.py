"""Collector base classes.

A collector's only job is to turn a source into ``RawRecord`` objects. It must
never assume the network is available: every collector supports an offline
fixture path so the pipeline is reproducible and testable in CI.
"""

from __future__ import annotations

import csv
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from threatint.config import Config, SourceConfig
from threatint.models import RawRecord
from threatint.normalize import detect_type, extract_indicators, refang

logger = logging.getLogger(__name__)


def _parse_ts(value: Any) -> datetime:
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _split_tags(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(v) for v in value]
    else:
        items = str(value).replace(";", ",").replace("|", ",").split(",")
    return [t.strip().lower() for t in items if t and t.strip()]


class BaseCollector(ABC):
    """Common behavior for all collectors."""

    def __init__(self, source: SourceConfig, config: Config):
        self.source = source
        self.config = config
        self.log = logging.getLogger(f"threatint.collectors.{source.name}")

    @abstractmethod
    def fetch(self) -> List[RawRecord]:
        """Return raw records for this source."""

    # -- helpers -----------------------------------------------------------
    def _make_record(
        self,
        indicator: str,
        observed_at: Any = None,
        tags: Any = None,
        confidence: Optional[float] = None,
        raw: Optional[Dict[str, Any]] = None,
    ) -> Optional[RawRecord]:
        indicator = refang(str(indicator)).strip()
        itype = detect_type(indicator)
        if itype is None:
            return None
        return RawRecord(
            source=self.source.name,
            indicator=indicator,
            indicator_type=itype,
            observed_at=_parse_ts(observed_at),
            tags=_split_tags(tags),
            confidence=float(confidence) if confidence is not None else self.source.reliability_prior,
            raw=raw or {},
        )

    def _fixture_path(self) -> Optional[Path]:
        if not self.source.fixture or not self.config.data_dir:
            return None
        path = Path(self.config.data_dir) / self.source.fixture
        return path if path.exists() else None

    def _read_fixture(self) -> List[RawRecord]:
        """Parse a generic fixture CSV.

        Expected columns (case-insensitive, order-independent):
            indicator, type, observed_at, tags, confidence
        Extra columns are preserved in ``raw``.
        """
        path = self._fixture_path()
        if path is None:
            return []
        records: List[RawRecord] = []
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                norm = { (k or "").strip().lower(): v for k, v in row.items() }
                value = norm.get("indicator") or norm.get("value") or norm.get("url") or norm.get("ioc")
                if not value:
                    continue
                records.append(
                    self._make_record(
                        value,
                        observed_at=norm.get("observed_at") or norm.get("date") or norm.get("first_seen"),
                        tags=norm.get("tags") or norm.get("tag") or norm.get("threat"),
                        confidence=norm.get("confidence") or None,
                        raw=norm,
                    )
                )
        return [r for r in records if r is not None]


class OfflineCollector(BaseCollector):
    """Reads records from a bundled fixture CSV.

    Used when a source has no live URL, when the network is unavailable, or
    when ``--offline`` is passed for reproducible runs.
    """

    def fetch(self) -> List[RawRecord]:
        records = self._read_fixture()
        self.log.info("offline collector loaded %d records from %s", len(records), self.source.fixture)
        return records


class HttpCollector(BaseCollector):
    """Fetches a remote feed and parses it as CSV, falling back to fixtures.

    The fallback is deliberate: a flaky feed should degrade to last-known-good
    local data rather than abort the whole pipeline.
    """

    def __init__(self, source: SourceConfig, config: Config, timeout: int = 20):
        super().__init__(source, config)
        self.timeout = timeout

    def fetch(self) -> List[RawRecord]:
        if not self.source.url:
            return OfflineCollector(self.source, self.config).fetch()
        try:
            import requests
        except ImportError:  # pragma: no cover - requests is a hard dep
            return OfflineCollector(self.source, self.config).fetch()

        headers = {"User-Agent": "ThreatInt/0.1 (+threat-intel-pipeline)"}
        api_key = None
        if self.source.api_key_env:
            import os

            api_key = os.environ.get(self.source.api_key_env)
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

        try:
            resp = requests.get(self.source.url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as exc:  # network/HTTP errors
            self.log.warning("live fetch failed (%s); using fixture fallback", exc)
            return OfflineCollector(self.source, self.config).fetch()

        return self._parse_text(resp.text)

    def _parse_text(self, text: str) -> List[RawRecord]:
        import io

        records: List[RawRecord] = []
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        if rows and reader.fieldnames and len(reader.fieldnames) > 1:
            for row in rows:
                norm = {(k or "").strip().lower(): v for k, v in row.items()}
                value = norm.get("indicator") or norm.get("value") or norm.get("url") or norm.get("ioc") or norm.get("domain") or norm.get("ip_address")
                if not value:
                    continue
                rec = self._make_record(
                    value,
                    observed_at=norm.get("observed_at") or norm.get("date") or norm.get("first_seen"),
                    tags=norm.get("tags") or norm.get("tag") or norm.get("threat"),
                    confidence=norm.get("confidence") or None,
                    raw=norm,
                )
                if rec:
                    records.append(rec)
        else:
            # Not tabular; extract every indicator we can find in the text.
            for value, itype in extract_indicators(text):
                rec = self._make_record(value)
                if rec:
                    records.append(rec)
        return records


def build_collectors(config: Config, offline: bool = False) -> List[BaseCollector]:
    """Instantiate collectors for all enabled sources."""
    collectors: List[BaseCollector] = []
    for source in config.enabled_sources:
        if offline or not source.url:
            collectors.append(OfflineCollector(source, config))
        else:
            collectors.append(HttpCollector(source, config))
    return collectors
