"""Replayable SPF header forensics on top of pyspf.

The package re-checks historical ``Received-SPF`` and
``Authentication-Results`` claims against trusted connection / envelope
metadata and a fixed, offline DNS view instead of trusting the ``pass``
result written into the header.
"""

from .dns_view import OfflineDNSView, OfflineDNSMissing, offline_dns
from .headers import HeaderClaim, extract_claims
from .recheck import (
    TrustedInput,
    RecheckFinding,
    RecheckReport,
    SPFRechecker,
    recheck_headers,
)

__all__ = [
    "OfflineDNSView",
    "OfflineDNSMissing",
    "offline_dns",
    "HeaderClaim",
    "extract_claims",
    "TrustedInput",
    "RecheckFinding",
    "RecheckReport",
    "SPFRechecker",
    "recheck_headers",
]
