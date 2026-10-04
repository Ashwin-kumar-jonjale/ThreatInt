"""Generate the bundled fixture feeds used for offline/reproducible runs.

These fixtures stand in for live feeds (abuse.ch Feodo, URLhaus, PhishTank,
AlienVault OTX) plus an internal honeypot. They deliberately overlap on a
handful of indicators so cross-verification and clustering have real signal
to work with. The output is fully deterministic (fixed seed).

Usage:  python scripts/generate_fixtures.py
"""

from __future__ import annotations

import csv
import os
import random
from datetime import datetime, timedelta, timezone

SEED = 1337
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "threatint", "data")
BASE_TIME = datetime(2026, 9, 20, tzinfo=timezone.utc)

SHARED_IPS = ["185.220.101.34", "45.155.205.233", "193.32.162.91", "91.240.118.172", "141.98.10.99"]
SHARED_DOMAINS = [
    "secure-paypal-login.xyz",
    "micros0ft-verify.top",
    "account-update-bank.tk",
    "crypto-wallet-drain.ml",
]
SHARED_URLS = [
    "http://secure-paypal-login.xyz/verify/account.php",
    "http://micros0ft-verify.top/login/update.php",
    "http://account-update-bank.tk/webscr/signin",
    "http://crypto-wallet-drain.ml/free/wallet",
]


def ts(days_ago: int) -> str:
    return (BASE_TIME - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(name: str, rows, fields) -> None:
    path = os.path.abspath(os.path.join(DATA_DIR, name))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def rand_ip(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def rand_token(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def main() -> None:
    rng = random.Random(SEED)
    os.makedirs(DATA_DIR, exist_ok=True)
    fields = ["indicator", "type", "observed_at", "tags", "confidence"]

    # abuse.ch Feodo tracker: botnet C2 IPs.
    feodo = []
    for ip in SHARED_IPS:
        feodo.append({"indicator": ip, "type": "ipv4", "observed_at": ts(rng.randint(1, 10)), "tags": "botnet,c2,emotet", "confidence": "0.95"})
    for _ in range(18):
        feodo.append({"indicator": rand_ip(rng), "type": "ipv4", "observed_at": ts(rng.randint(1, 20)), "tags": "botnet,c2,trickbot", "confidence": "0.9"})
    write("abusech_feodo.csv", feodo, fields)

    # URLhaus: malware distribution URLs.
    urlhaus = []
    for url in SHARED_URLS:
        urlhaus.append({"indicator": url, "type": "url", "observed_at": ts(rng.randint(1, 10)), "tags": "malware,loader", "confidence": "0.85"})
    for domain in SHARED_DOMAINS:
        urlhaus.append({"indicator": domain, "type": "domain", "observed_at": ts(rng.randint(1, 10)), "tags": "malware,payload", "confidence": "0.8"})
    for _ in range(14):
        host = f"{rand_token(rng, rng.randint(10, 22))}.{rng.choice(['zip', 'top', 'xyz', 'click'])}"
        urlhaus.append({"indicator": f"http://{host}/{rand_token(rng, 8)}.bin", "type": "url", "observed_at": ts(rng.randint(1, 25)), "tags": "malware,payload", "confidence": "0.82"})
    write("urlhaus.csv", urlhaus, fields)

    # PhishTank: phishing URLs.
    phishtank = []
    for url in SHARED_URLS[:3]:
        phishtank.append({"indicator": url, "type": "url", "observed_at": ts(rng.randint(1, 7)), "tags": "phishing,credential", "confidence": "0.88"})
    for domain in SHARED_DOMAINS[:3]:
        phishtank.append({"indicator": domain, "type": "domain", "observed_at": ts(rng.randint(1, 7)), "tags": "phishing,credential", "confidence": "0.86"})
    for _ in range(12):
        brand = rng.choice(["paypal", "apple", "netflix", "dhl", "hsbc", "chase", "amazon"])
        host = f"{brand}-{rng.choice(['login', 'verify', 'secure', 'update'])}{rng.randint(1, 99)}.{rng.choice(['tk', 'gq', 'ml', 'cf'])}"
        phishtank.append({"indicator": f"http://{host}/{rng.choice(['signin', 'verify', 'webscr'])}", "type": "url", "observed_at": ts(rng.randint(1, 18)), "tags": "phishing,credential", "confidence": "0.84"})
    write("phishtank.csv", phishtank, fields)

    # AlienVault OTX: mixed pulses (IPs, domains, hashes).
    otx = []
    for ip in SHARED_IPS[:3]:
        otx.append({"indicator": ip, "type": "ipv4", "observed_at": ts(rng.randint(1, 12)), "tags": "apt,c2", "confidence": "0.75"})
    for domain in SHARED_DOMAINS[:3]:
        otx.append({"indicator": domain, "type": "domain", "observed_at": ts(rng.randint(1, 12)), "tags": "apt,phishing", "confidence": "0.72"})
    for _ in range(8):
        digest = "".join(rng.choice("0123456789abcdef") for _ in range(64))
        otx.append({"indicator": digest, "type": "sha256", "observed_at": ts(rng.randint(1, 30)), "tags": "malware,apt", "confidence": "0.7"})
    for _ in range(6):
        otx.append({"indicator": rand_ip(rng), "type": "ipv4", "observed_at": ts(rng.randint(1, 30)), "tags": "scanner", "confidence": "0.6"})
    write("alienvault_otx.csv", otx, fields)

    # Internal honeypot: mixed, lower confidence.
    honeypot = []
    for ip in SHARED_IPS:
        honeypot.append({"indicator": ip, "type": "ipv4", "observed_at": ts(rng.randint(1, 5)), "tags": "honeypot,exploit", "confidence": "0.7"})
    for domain in SHARED_DOMAINS:
        honeypot.append({"indicator": domain, "type": "domain", "observed_at": ts(rng.randint(1, 5)), "tags": "honeypot,exploit", "confidence": "0.68"})
    for url in SHARED_URLS:
        honeypot.append({"indicator": url, "type": "url", "observed_at": ts(rng.randint(1, 5)), "tags": "honeypot,exploit", "confidence": "0.66"})
    for _ in range(10):
        honeypot.append({"indicator": rand_ip(rng), "type": "ipv4", "observed_at": ts(rng.randint(1, 15)), "tags": "honeypot,bruteforce", "confidence": "0.6"})
    write("internal_honeypot.csv", honeypot, fields)

    print("fixtures written to", os.path.abspath(DATA_DIR))
    for f in sorted(os.listdir(DATA_DIR)):
        print("  ", f)


if __name__ == "__main__":
    main()
