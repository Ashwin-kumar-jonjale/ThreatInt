"""Indicator normalization, extraction and validation.

Threat feeds are messy: they use defanged notation (``hxxp://``, ``1[.]2[.]3[.]4``),
mix types in a single field, carry URLs with credentials, and disagree on
casing. This module turns any of that into canonical, validated indicators.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from threatint.models import IndicatorType

# Defanging patterns commonly used in threat reports.
_DEFANG_SUBS: List[Tuple[str, str]] = [
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hXXps://", "https://"),
    ("hXXp://", "http://"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("[@]", "@"),
    ("[://]", "://"),
    ("://.", "://"),
    ("\\.", "."),
]

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63})\b"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Domains that show up everywhere and are never useful as indicators.
_BENIGN_DOMAINS = {
    "localhost",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "invalid",
    "local",
}
_BENIGN_TLDS = {"local", "localhost", "test", "invalid", "example"}


def refang(value: str) -> str:
    """Reverse common defanging so indicators can be parsed."""
    if not value:
        return ""
    out = value.strip()
    for bad, good in _DEFANG_SUBS:
        out = out.replace(bad, good)
    return out


def defang(value: str) -> str:
    """Produce a safe-to-share rendering of an indicator."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_valid_domain(value: str) -> bool:
    value = value.strip().strip(".").lower()
    if not value or len(value) > 253:
        return False
    if value in _BENIGN_DOMAINS:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if tld in _BENIGN_TLDS or not tld.isalpha():
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    return True


def _is_valid_hash(value: str, length: int) -> bool:
    return len(value) == length and re.fullmatch(r"[a-fA-F0-9]+", value) is not None


def _canonical_url(value: str) -> Optional[str]:
    value = refang(value).strip().rstrip(".,;)\"]'")
    if not value:
        return None
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https", "ftp"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    if not (_is_valid_domain(host) or _is_valid_ipv4(host)):
        return None
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    # Drop query/fragment noise? Keep path; strip tracking-ish fragments.
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


def canonicalize(value: str, indicator_type: IndicatorType) -> Optional[str]:
    """Return the canonical form of ``value`` or ``None`` if invalid."""
    if value is None:
        return None
    value = refang(str(value)).strip()
    if not value:
        return None

    if indicator_type is IndicatorType.IPV4:
        value = value.strip("[]").split(":")[0]
        return value if _is_valid_ipv4(value) else None
    if indicator_type is IndicatorType.DOMAIN:
        value = value.lower().strip().strip(".")
        if value.startswith("http://") or value.startswith("https://"):
            value = urlsplit(value).hostname or ""
            value = value.lower()
        return value if _is_valid_domain(value) else None
    if indicator_type is IndicatorType.URL:
        return _canonical_url(value)
    if indicator_type is IndicatorType.MD5:
        value = value.lower()
        return value if _is_valid_hash(value, 32) else None
    if indicator_type is IndicatorType.SHA256:
        value = value.lower()
        return value if _is_valid_hash(value, 64) else None
    return None


def detect_type(value: str) -> Optional[IndicatorType]:
    """Best-effort inference of an indicator's type."""
    if not value:
        return None
    v = refang(str(value)).strip()
    if not v:
        return None
    if _URL_RE.match(v):
        return IndicatorType.URL
    if _is_valid_ipv4(v.split(":")[0].strip("[]")):
        return IndicatorType.IPV4
    if _is_valid_hash(v, 64):
        return IndicatorType.SHA256
    if _is_valid_hash(v, 32):
        return IndicatorType.MD5
    host = v
    if "/" in v:
        host = urlsplit(v if "://" in v else f"http://{v}").hostname or v
    if _is_valid_domain(host):
        return IndicatorType.DOMAIN
    return None


def extract_indicators(text: str) -> List[Tuple[str, IndicatorType]]:
    """Extract all indicators from a free-text blob.

    Order matters: URLs first (so their host isn't double-counted as a bare
    domain), then hashes, then IPs, then remaining domains.
    """
    if not text:
        return []
    found: List[Tuple[str, IndicatorType]] = []
    seen: set[Tuple[str, IndicatorType]] = set()

    def add(value: str, itype: IndicatorType) -> None:
        canon = canonicalize(value, itype)
        if canon is None:
            return
        key = (canon, itype)
        if key in seen:
            return
        seen.add(key)
        found.append(key)

    refanged = refang(text)

    url_spans: List[Tuple[int, int]] = []
    for m in _URL_RE.finditer(refanged):
        add(m.group(0), IndicatorType.URL)
        url_spans.append(m.span())

    def in_url(span: Tuple[int, int]) -> bool:
        return any(s <= span[0] < e for s, e in url_spans)

    for m in _SHA256_RE.finditer(refanged):
        if not in_url(m.span()):
            add(m.group(0), IndicatorType.SHA256)
    for m in _MD5_RE.finditer(refanged):
        if not in_url(m.span()):
            add(m.group(0), IndicatorType.MD5)
    for m in _IPV4_RE.finditer(refanged):
        if not in_url(m.span()):
            add(m.group(0), IndicatorType.IPV4)
    for m in _DOMAIN_RE.finditer(refanged):
        if not in_url(m.span()):
            add(m.group(0), IndicatorType.DOMAIN)

    return found


def is_public_ip(value: str) -> bool:
    return _is_public_ip(value)
