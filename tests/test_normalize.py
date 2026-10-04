"""Tests for normalization, validation and indicator extraction."""

from __future__ import annotations

import pytest

from threatint.models import IndicatorType
from threatint.normalize import (
    canonicalize,
    defang,
    detect_type,
    extract_indicators,
    is_public_ip,
    refang,
)


def test_refang_reverses_defanging():
    assert refang("hxxp://evil[.]com/path") == "http://evil.com/path"
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("bad(.)domain(.)tk") == "bad.domain.tk"


def test_defang_roundtrip():
    assert defang("http://evil.com") == "hxxp://evil[.]com"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", IndicatorType.IPV4),
        ("1.2.3.4", IndicatorType.IPV4),
        ("evil-domain.xyz", IndicatorType.DOMAIN),
        ("http://evil-domain.xyz/a/b", IndicatorType.URL),
        ("https://phish.tk/login", IndicatorType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.MD5),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IndicatorType.SHA256),
    ],
)
def test_detect_type(value, expected):
    assert detect_type(value) is expected


def test_detect_type_rejects_garbage():
    assert detect_type("") is None
    assert detect_type("not an indicator") is None
    assert detect_type("12345") is None


def test_canonicalize_ipv4_strips_port():
    assert canonicalize("8.8.8.8:8080", IndicatorType.IPV4) == "8.8.8.8"


def test_canonicalize_url_lowercases_host_and_drops_fragment():
    got = canonicalize("HTTP://EVIL.COM/Path#frag", IndicatorType.URL)
    assert got == "http://evil.com/Path"


def test_canonicalize_url_rejects_bad_scheme():
    assert canonicalize("ftp://", IndicatorType.URL) is None
    assert canonicalize("javascript:alert(1)", IndicatorType.URL) is None


def test_canonicalize_domain_rejects_benign_and_invalid():
    assert canonicalize("localhost", IndicatorType.DOMAIN) is None
    assert canonicalize("example.com", IndicatorType.DOMAIN) is None
    assert canonicalize("no-tld", IndicatorType.DOMAIN) is None
    assert canonicalize("-bad.com", IndicatorType.DOMAIN) is None
    assert canonicalize("good-domain.xyz", IndicatorType.DOMAIN) == "good-domain.xyz"


def test_canonicalize_hashes_validate_length_and_charset():
    assert canonicalize("D41D8CD98F00B204E9800998ECF8427E", IndicatorType.MD5) == "d41d8cd98f00b204e9800998ecf8427e"
    assert canonicalize("zzzz", IndicatorType.MD5) is None


def test_is_public_ip_filters_private_and_loopback():
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("192.168.1.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("10.0.0.1")


def test_extract_indicators_finds_multiple_types():
    text = "C2 at 185.220.101.34 and hxxp://evil[.]xyz/a plus hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    types = {t for _, t in extract_indicators(text)}
    assert IndicatorType.IPV4 in types
    assert IndicatorType.URL in types
    assert IndicatorType.SHA256 in types


def test_extract_indicators_does_not_double_count_url_host():
    found = extract_indicators("http://only-host.xyz/path")
    types = [t for _, t in found]
    assert IndicatorType.URL in types
    assert IndicatorType.DOMAIN not in types


def test_extract_indicators_deduplicates():
    found = extract_indicators("8.8.8.8 and 8.8.8.8 and 8.8.8.8")
    assert found.count(("8.8.8.8", IndicatorType.IPV4)) == 1
