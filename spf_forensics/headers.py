"""Parse historical SPF claims out of raw mail headers without trusting them.

Two header families carry historical SPF decisions:

* ``Received-SPF`` (RFC 7208, section 9.2)
* ``Authentication-Results`` (RFC 8601, formerly RFC 5451), method ``spf``

The parser only *describes* what a header claims.  Every value extracted from
a header is kept separate from the trusted connection / envelope metadata and
the exact raw header text is retained verbatim so that later recomputation can
never overwrite the original evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

import spf

KNOWN_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
_SPF_RESULT_RE = re.compile(r"\bspf\s*=\s*([A-Za-z]+)", re.IGNORECASE)
_KV_RE = re.compile(r'([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|([^\s;()]+))')


@dataclass
class HeaderClaim:
    """One self-reported SPF statement found in the supplied headers."""

    index: int
    header_type: str                      # "received-spf" | "authentication-results"
    raw: str                              # exact, verbatim header (folded as received)
    unfolded: str                         # whitespace-unfolded value, for parsing only
    authserv_id: Optional[str] = None
    claimed_result: Optional[str] = None  # lower-cased SPF result token, None if unparseable
    claimed_identity: Optional[str] = None  # "mailfrom" | "helo" | None
    header_client_ip: Optional[str] = None
    header_envelope_from: Optional[str] = None
    header_helo: Optional[str] = None
    header_receiver: Optional[str] = None
    header_mechanism: Optional[str] = None
    parse_error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def parse_failed(self) -> bool:
        return self.parse_error is not None

    def as_evidence(self) -> dict:
        """Serialise the self-reported identity only; trusted data lives elsewhere."""
        return {
            "index": self.index,
            "header_type": self.header_type,
            "authserv_id": self.authserv_id,
            "raw_header": self.raw,
            "claimed_result": self.claimed_result,
            "claimed_identity": self.claimed_identity,
            "header_client_ip": self.header_client_ip,
            "header_envelope_from": self.header_envelope_from,
            "header_helo": self.header_helo,
            "header_receiver": self.header_receiver,
            "header_mechanism": self.header_mechanism,
            "parse_error": self.parse_error,
            "warnings": list(self.warnings),
        }


def _split_raw_headers(raw) -> List[tuple]:
    """Split a raw header block into (name, unfolded value, exact raw) tuples.

    Folded whitespace (RFC 5322 section 2.2.3) is joined for parsing, while the
    original folded line sequence is preserved separately as evidence.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="surrogateescape")
    # A full message may have been passed; only the header section matters.
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    header_section = raw.split("\n\n", 1)[0]

    blocks: List[List[str]] = []
    for line in header_section.split("\n"):
        if not line:
            continue
        if line[0] in (" ", "\t") and blocks:
            blocks[-1].append(line)
        else:
            blocks.append([line])

    out = []
    for block in blocks:
        joined = " ".join(part.strip() for part in block)
        if ":" not in joined:
            continue
        name, value = joined.split(":", 1)
        out.append((name.strip().lower(), value.strip(), "\n".join(block)))
    return out


def _kv_tokens(text: str) -> dict:
    tokens = {}
    for match in _KV_RE.finditer(text):
        key = match.group(1).lower()
        value = match.group(2) if match.group(2) is not None else match.group(3)
        tokens.setdefault(key, value)
    return tokens


def _explicit_identity(tokens: dict) -> Optional[str]:
    """Only an explicit ``identity`` field counts; presence of an address is
    not enough to claim a specific evaluated identity (RFC 7208 section 9.2)."""
    if "identity" in tokens:
        identity = tokens["identity"].lower()
        return identity if identity in ("mailfrom", "helo") else None
    return None


def _parse_received_spf(claim: HeaderClaim):
    tokens = _kv_tokens(claim.unfolded)
    first = claim.unfolded.split(None, 1)[0].lower() if claim.unfolded.strip() else ""
    valid_result_prefix = first in KNOWN_RESULTS
    if not valid_result_prefix:
        claim.parse_error = "Received-SPF does not start with a valid result token: %r" % first
    try:
        probe = spf.query("0.0.0.0", "", "")
        probe.parse_header_spf(claim.unfolded)
        claim.claimed_result = getattr(probe, "result", None)
        claim.claimed_identity = getattr(probe, "ident", None)
        claim.header_client_ip = getattr(probe, "c", None)
        claim.header_envelope_from = getattr(probe, "s", None) or None
        claim.header_helo = getattr(probe, "h", None) or None
        claim.header_receiver = getattr(probe, "r", None) or None
        claim.header_mechanism = getattr(probe, "mechanism", None)
    except Exception as exc:  # malformed Received-SPF: keep raw evidence, parse loosely
        claim.parse_error = "%s: %s" % (type(exc).__name__, exc)
        claim.claimed_result = first or None
        claim.header_client_ip = tokens.get("client-ip")
        claim.header_envelope_from = tokens.get("envelope-from")
        claim.header_helo = tokens.get("helo")
        claim.header_receiver = tokens.get("receiver")
        claim.header_mechanism = tokens.get("mechanism")

    # pyspf may accept garbage result tokens; validate against the RFC set.
    if claim.claimed_result and claim.claimed_result not in KNOWN_RESULTS:
        claim.warnings.append("unknown result token %r" % claim.claimed_result)
    # Only an explicit identity= field determines the evaluated identity.
    claim.claimed_identity = _explicit_identity(tokens)
    if claim.claimed_identity is None:
        claim.warnings.append("header does not state which identity was evaluated")


def _parse_authentication_results(claim: HeaderClaim, tokens: dict):
    spf_token_count = len(_SPF_RESULT_RE.findall(claim.unfolded))
    try:
        import authres

        # authres requires the full field, including the header name.
        full_header = "Authentication-Results: " + claim.unfolded
        parsed = authres.AuthenticationResultsHeader.parse(full_header)
        claim.authserv_id = parsed.authserv_id
        spf_results = [res for res in parsed.results if res.method == "spf"]
        if not spf_results:
            claim.parse_error = "Authentication-Results header contains no spf method"
            spf_results = []
        # First SPF result object populates this claim; extras become warnings.
        if spf_results:
            primary = spf_results[0]
            claim.claimed_result = primary.result.lower()
            for prop in primary.properties:
                if prop.name == "mailfrom":
                    claim.header_envelope_from = prop.value
                elif prop.name == "helo":
                    claim.header_helo = prop.value
        if spf_token_count > 1 or len(spf_results) > 1:
            claim.warnings.append(
                "%d spf results in one Authentication-Results header; only the first is bound"
                % max(spf_token_count, len(spf_results))
            )
    except Exception as exc:
        claim.parse_error = "%s: %s" % (type(exc).__name__, exc)
        match = _SPF_RESULT_RE.search(claim.unfolded)
        claim.claimed_result = match.group(1).lower() if match else None
        authserv = claim.unfolded.split(";", 1)[0].strip()
        claim.authserv_id = authserv or None
        if spf_token_count > 1:
            claim.warnings.append(
                "%d spf= tokens in one Authentication-Results header; only the first is bound"
                % spf_token_count
            )

    # authres does not model parenthesised comments; recover the common
    # forensic tokens (client-ip, helo, envelope sender) with a guarded regex.
    claim.header_client_ip = claim.header_client_ip or tokens.get("client-ip")
    claim.header_helo = claim.header_helo or tokens.get("helo") or tokens.get("smtp.helo")
    claim.header_envelope_from = (
        claim.header_envelope_from
        or tokens.get("envelope-from")
        or tokens.get("smtp.mailfrom")
        or tokens.get("mailfrom")
    )
    claim.header_receiver = tokens.get("receiver")
    claim.header_mechanism = tokens.get("mechanism")
    if claim.claimed_result is None:
        claim.warnings.append("could not extract an spf result from the header")
    elif claim.claimed_result not in KNOWN_RESULTS:
        claim.warnings.append("unknown result token %r" % claim.claimed_result)
    # A-R has no identity= field; only an explicit smtp.helo property marks a
    # helo-identity evaluation (RFC 8601).  Everything else stays unknown and
    # defaults to mailfrom at re-check time rather than being guessed here.
    if tokens.get("identity", "").lower() == "helo" or (
        (tokens.get("helo") or tokens.get("smtp.helo"))
        and not (tokens.get("smtp.mailfrom") or tokens.get("mailfrom") or tokens.get("envelope-from"))
    ):
        claim.claimed_identity = "helo"
    else:
        claim.claimed_identity = None
    if claim.claimed_identity is None:
        claim.warnings.append("header does not state which identity was evaluated")


def extract_claims(raw) -> List[HeaderClaim]:
    """Extract every SPF claim from a raw header block or full message.

    Header order is preserved via :attr:`HeaderClaim.index` so multiple
    conflicting statements (e.g. a downstream forgery followed by an upstream
    gateway result) all survive for separate recomputation.
    """
    claims: List[HeaderClaim] = []
    for name, value, exact in _split_raw_headers(raw):
        if name not in ("received-spf", "authentication-results"):
            continue
        claim = HeaderClaim(
            index=len(claims),
            header_type=name,
            raw=exact,
            unfolded=value,
        )
        tokens = _kv_tokens(value)
        if name == "received-spf":
            _parse_received_spf(claim)
        else:
            # Skip A-R headers whose spf token is absent entirely; still keep
            # them when a token exists but surrounding syntax is broken.
            if "spf" not in value.lower():
                claim.parse_error = "no spf method present"
                claim.warnings.append("header retained as evidence but not re-checkable")
            _parse_authentication_results(claim, tokens)
        claims.append(claim)
    return claims
