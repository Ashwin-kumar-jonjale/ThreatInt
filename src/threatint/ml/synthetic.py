"""Deterministic synthetic corpus generator for classifier bootstrap.

Real deployments train on analyst-reviewed labels. Until those exist, the
pipeline needs *something* to fit so the plumbing is exercised end-to-end.
This module generates a seeded, clearly-synthetic corpus with separable
malicious/benign distributions. It is bootstrap data only and is always
replaced once ``--labels`` points at reviewed data.

The generator deliberately encodes the same lexical intuitions a human
analyst uses (DGA-like strings, phishing keywords, abused TLDs, high-risk
ports) so the learned model is interpretable rather than arbitrary.
"""

from __future__ import annotations

import random
from typing import List, Tuple

_BENIGN_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "cloudflare.com", "amazonaws.com",
    "wikipedia.org", "python.org", "stackoverflow.com", "apple.com", "mozilla.org",
    "nytimes.com", "bbc.co.uk", "redhat.com", "ubuntu.com", "docker.com",
    "pypi.org", "npmjs.com", "gitlab.com", "office.com", "linkedin.com",
]
_BENIGN_TLDS = ["com", "org", "net", "io", "edu", "gov", "co.uk", "dev"]

_SUSPICIOUS_TLDS = ["zip", "xyz", "top", "tk", "gq", "ml", "cf", "work", "click", "country"]
_PHISH_WORDS = [
    "login", "verify", "secure", "account", "update", "bank", "invoice",
    "pay", "wallet", "crypto", "admin", "signin", "webscr", "free",
]
_BRANDS = ["paypal", "microsoft", "apple", "amazon", "netflix", "dhl", "fedex", "hsbc", "chase"]
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_SAFE_PATHS = ["/", "/index.html", "/docs", "/api/v1/users", "/about", "/images/logo.png", "/blog/post-1"]


def _rand_token(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(n))


def _benign_domain(rng: random.Random) -> str:
    if rng.random() < 0.6:
        return rng.choice(_BENIGN_DOMAINS)
    return f"{_rand_token(rng, rng.randint(3, 8))}.{rng.choice(_BENIGN_TLDS)}"


def _malicious_domain(rng: random.Random) -> str:
    tld = rng.choice(_SUSPICIOUS_TLDS)
    style = rng.random()
    if style < 0.45:  # DGA-like
        return f"{_rand_token(rng, rng.randint(12, 28))}.{tld}"
    if style < 0.8:  # brand + keyword impersonation
        return f"{rng.choice(_BRANDS)}-{rng.choice(_PHISH_WORDS)}{rng.randint(1, 99)}.{tld}"
    return f"{rng.choice(_PHISH_WORDS)}.{rng.choice(_BRANDS)}-{_rand_token(rng, 4)}.{tld}"


def _benign_ip(rng: random.Random) -> str:
    return f"{rng.choice([8, 13, 52, 104, 151, 172])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _malicious_ip(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _benign_url(rng: random.Random) -> str:
    host = _benign_domain(rng)
    scheme = "https" if rng.random() < 0.85 else "http"
    return f"{scheme}://{host}{rng.choice(_SAFE_PATHS)}"


def _malicious_url(rng: random.Random) -> str:
    host = _malicious_domain(rng)
    path = rng.choice(
        [f"/{rng.choice(_PHISH_WORDS)}", f"/{rng.choice(_PHISH_WORDS)}/verify",
         f"/{_rand_token(rng, 10)}.php", f"/account/{rng.choice(_PHISH_WORDS)}"]
    )
    port = rng.choice(["", ":8080", ":8443", ":4444"])
    return f"http://{host}{port}{path}"


def _hash(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def generate_corpus(n: int = 1200, seed: int = 42) -> Tuple[List[str], List[int]]:
    """Return ``(values, labels)`` with labels 1=malicious, 0=benign."""
    rng = random.Random(seed)
    values: List[str] = []
    labels: List[int] = []

    per_class = max(1, n // 2)
    for _ in range(per_class):
        roll = rng.random()
        if roll < 0.35:
            values.append(_benign_domain(rng))
        elif roll < 0.55:
            values.append(_benign_ip(rng))
        elif roll < 0.8:
            values.append(_benign_url(rng))
        else:
            values.append(_hash(rng, 64 if rng.random() < 0.5 else 32))
        labels.append(0)

    for _ in range(per_class):
        roll = rng.random()
        if roll < 0.35:
            values.append(_malicious_domain(rng))
        elif roll < 0.55:
            values.append(_malicious_ip(rng))
        elif roll < 0.85:
            values.append(_malicious_url(rng))
        else:
            values.append(_hash(rng, 64 if rng.random() < 0.5 else 32))
        labels.append(1)

    combined = list(zip(values, labels))
    rng.shuffle(combined)
    values, labels = [c[0] for c in combined], [c[1] for c in combined]
    return values, labels
