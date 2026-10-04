"""ThreatInt: automated threat-intelligence pipeline.

Collects malicious indicators (IPs, domains, URLs, hashes) from multiple
trusted sources, cross-verifies source reliability, classifies indicators
with machine learning, and clusters related indicators into attack campaigns.
"""

__version__ = "0.1.0"

from threatint.models import Campaign, Indicator, Observation, SourceReliability

__all__ = ["Indicator", "Observation", "Campaign", "SourceReliability", "__version__"]
