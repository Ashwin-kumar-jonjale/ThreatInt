"""Configuration loading and validation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
# Packaged copy used when the repo layout is not available (installed wheel).
PACKAGED_CONFIG_PATH = Path(__file__).resolve().parent / "data" / "config.yaml"


@dataclass
class SourceConfig:
    name: str
    kind: str
    reliability_prior: float = 0.5
    url: str = ""
    fixture: Optional[str] = None
    api_key_env: Optional[str] = None
    enabled: bool = True


@dataclass
class PipelineConfig:
    min_sources_for_verification: int = 2
    malicious_threshold: float = 0.5
    min_reliability_for_clustering: float = 0.35
    random_seed: int = 42


@dataclass
class Config:
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    sources: List[SourceConfig] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)
    ml: Dict[str, Any] = field(default_factory=dict)
    clustering: Dict[str, Any] = field(default_factory=dict)
    config_path: Optional[Path] = None
    data_dir: Optional[Path] = None

    @property
    def enabled_sources(self) -> List[SourceConfig]:
        return [s for s in self.sources if s.enabled]

    def get_source(self, name: str) -> Optional[SourceConfig]:
        for s in self.sources:
            if s.name == name:
                return s
        return None


def _resolve_config_path(path: Optional[str] = None) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    env = os.environ.get("THREATINT_CONFIG")
    if env:
        return Path(env).expanduser().resolve()
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    if PACKAGED_CONFIG_PATH.exists():
        return PACKAGED_CONFIG_PATH
    raise FileNotFoundError("No config.yaml found; pass --config explicitly")


def load_config(path: Optional[str] = None) -> Config:
    """Load and validate a YAML config file into typed dataclasses."""
    cfg_path = _resolve_config_path(path)
    with open(cfg_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be a mapping, got {type(raw).__name__}")

    pipeline_raw = raw.get("pipeline", {}) or {}
    pipeline = PipelineConfig(
        min_sources_for_verification=int(pipeline_raw.get("min_sources_for_verification", 2)),
        malicious_threshold=float(pipeline_raw.get("malicious_threshold", 0.5)),
        min_reliability_for_clustering=float(pipeline_raw.get("min_reliability_for_clustering", 0.35)),
        random_seed=int(pipeline_raw.get("random_seed", 42)),
    )

    sources: List[SourceConfig] = []
    for entry in raw.get("sources", []) or []:
        if "name" not in entry or "kind" not in entry:
            raise ValueError(f"Source entry missing name/kind: {entry!r}")
        sources.append(
            SourceConfig(
                name=str(entry["name"]),
                kind=str(entry["kind"]),
                reliability_prior=float(entry.get("reliability_prior", 0.5)),
                url=str(entry.get("url", "")),
                fixture=entry.get("fixture"),
                api_key_env=entry.get("api_key_env"),
                enabled=bool(entry.get("enabled", True)),
            )
        )

    data_dir = cfg_path.parent.parent / "src" / "threatint" / "data"
    if not data_dir.exists():
        data_dir = Path(__file__).resolve().parent / "data"

    return Config(
        pipeline=pipeline,
        sources=sources,
        features=raw.get("features", {}) or {},
        ml=raw.get("ml", {}) or {},
        clustering=raw.get("clustering", {}) or {},
        config_path=cfg_path,
        data_dir=data_dir,
    )
