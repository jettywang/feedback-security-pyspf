"""Replayable re-evaluation of historical SPF header claims.

The forensic flow never lets a header overwrite trusted connection metadata:

1. Trusted inputs (real client IP, envelope sender, HELO name) are held in a
   separate :class:`TrustedInput` object and are the *only* values fed to the
   SPF evaluation.  Addresses advertised inside the header are compared after
   the fact and recorded as conflicts, never substituted.
2. SPF is recomputed through pyspf against a fixed :class:`OfflineDNSView`,
   so a run is deterministic and performs no network lookups.
3. The original claim, the exact inputs actually used, the recomputation
   conditions and every DNS query are all retained on the report.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import spf

from .dns_view import OfflineDNSView, offline_dns
from .headers import HeaderClaim, extract_claims

# RFC 7208 result vocabulary emitted by pyspf.
RESULT_SET = ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")

# This caveat must travel with every report: an offline snapshot only proves
# what the *current supplied view* authorises, not what DNS answered historically.
DNS_CAVEAT = (
    "Recomputation used the supplied offline DNS view only. Matching results prove "
    "consistency with that view; they cannot prove that historical DNS answers at "
    "the time of original delivery were identical (records may have changed or expired)."
)


@dataclass(frozen=True)
class TrustedInput:
    """Connection and envelope data from a trusted logging path, not from mail headers."""

    client_ip: str
    helo: Optional[str] = None
    mail_from: Optional[str] = None          # empty string / None => null sender (bounce)
    receiver: Optional[str] = None

    def __post_init__(self):
        try:
            ipaddress.ip_address(self.client_ip)
        except ValueError as exc:
            raise ValueError("trusted client_ip is not a valid IP address: %r" % self.client_ip) from exc

    @property
    def null_sender(self) -> bool:
        return self.mail_from is None or self.mail_from == ""

    def as_record(self) -> dict:
        return {
            "client_ip": self.client_ip,
            "helo": self.helo,
            "mail_from": self.mail_from,
            "null_sender": self.null_sender,
            "receiver": self.receiver,
        }


@dataclass
class RecheckFinding:
    """Verdict for one historical header claim."""

    claim_index: int
    header_type: str
    claimed_result: Optional[str]
    recomputed_primary: Dict[str, object]
    consistency: str                        # "consistent" | "inconsistent" | "indeterminate"
    reasons: List[str] = field(default_factory=list)
    evidence_conflicts: List[str] = field(default_factory=list)
    checks: List[Dict[str, object]] = field(default_factory=list)
    raw_header: str = ""
    parse_error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "claim_index": self.claim_index,
            "header_type": self.header_type,
            "raw_header": self.raw_header,
            "parse_error": self.parse_error,
            "claimed_result": self.claimed_result,
            "recomputed_primary": self.recomputed_primary,
            "consistency": self.consistency,
            "reasons": list(self.reasons),
            "evidence_conflicts": list(self.evidence_conflicts),
            "checks": list(self.checks),
        }


@dataclass
class RecheckReport:
    """Immutable-ish bundle emitted for one re-check run; original evidence is preserved."""

    trusted_input: Dict[str, object]
    dns_view: Dict[str, object]
    dns_caveat: str
    findings: List[RecheckFinding]
    overall_consistency: str

    def as_dict(self) -> dict:
        return {
            "trusted_input": self.trusted_input,
            "dns_view": self.dns_view,
            "dns_caveat": self.dns_caveat,
            "overall_consistency": self.overall_consistency,
            "findings": [finding.as_dict() for finding in self.findings],
        }


class SPFRechecker:
    """Recompute SPF claims against trusted metadata and one offline DNS view."""

    def __init__(self, trusted: TrustedInput, view: OfflineDNSView):
        self.trusted = trusted
        self.view = view

    def _run_one_identity(self, identity: str) -> Dict[str, object]:
        """Execute one pyspf evaluation for mailfrom or helo identity."""
        trusted = self.trusted
        if identity == "helo":
            if not trusted.helo:
                return {
                    "identity": "helo",
                    "status": "skipped",
                    "reason": "no trusted HELO name available",
                }
            sender, helo = "", trusted.helo        # pyspf switches to helo identity on empty s
        else:
            if trusted.null_sender and trusted.helo:
                # RFC 7208 section 2.4: null MAIL FROM means the helo identity is checked.
                identity = "helo"
                sender, helo = "", trusted.helo
            elif trusted.mail_from:
                sender, helo = trusted.mail_from, trusted.helo
            else:
                return {
                    "identity": "mailfrom",
                    "status": "skipped",
                    "reason": "no trusted MAIL FROM or HELO available",
                }

        mark = self.view.mark_log()
        query = spf.query(
            i=trusted.client_ip,
            s=sender,
            h=helo,
            receiver=trusted.receiver,
        )
        try:
            with offline_dns(self.view):
                result, code, explanation = query.check()
            status = "ok"
            error = None
        except spf.TempError as exc:
            result, code, explanation, status = "temperror", 451, str(exc), "error"
            error = "TempError: %s" % exc
        except spf.PermError as exc:
            result, code, explanation, status = "permerror", 550, str(exc), "error"
            error = "PermError: %s" % exc

        return {
            "identity": identity,
            "status": status,
            "inputs_used": {
                "client_ip": trusted.client_ip,
                "sender": sender,
                "helo": helo,
                "receiver": trusted.receiver,
            },
            "evaluated_domain": query.d,
            "result": result,
            "smtp_code": code,
            "explanation": explanation,
            "error": error,
            "mechanism": getattr(query, "mechanism", None),
            "dns_queries": self.view.log_since(mark),
            "pyspf_version": spf.__version__,
        }

    def evaluate_claim(self, claim: HeaderClaim) -> RecheckFinding:
        checks = [self._run_one_identity("mailfrom"), self._run_one_identity("helo")]
        usable = [check for check in checks if check.get("status") in ("ok", "error")]

        # Pick the primary identity: the one the header says it evaluated when
        # available, otherwise RFC 7208 default (mailfrom, helo for null sender).
        primary = self._select_primary(claim, checks)

        finding = RecheckFinding(
            claim_index=claim.index,
            header_type=claim.header_type,
            claimed_result=claim.claimed_result,
            recomputed_primary=primary,
            consistency="indeterminate",
            raw_header=claim.raw,
            parse_error=claim.parse_error,
            checks=checks,
        )
        self._record_identity_choice(claim, primary, finding.reasons)
        self._record_evidence_conflicts(claim, finding.evidence_conflicts)
        self._classify(claim, primary, usable, finding)
        return finding

    @staticmethod
    def _select_primary(claim: HeaderClaim, checks: List[dict]) -> dict:
        by_identity = {check["identity"]: check for check in checks}
        wanted = claim.claimed_identity or "mailfrom"
        candidate = by_identity.get(wanted)
        if candidate and candidate.get("status") in ("ok", "error"):
            return candidate
        for check in checks:  # fall back to whatever could be evaluated
            if check.get("status") in ("ok", "error"):
                return check
        return checks[0] if checks else {"status": "unavailable"}

    def _record_identity_choice(self, claim: HeaderClaim, primary: dict, reasons: List[str]):
        if claim.claimed_identity is None:
            reasons.append(
                "header lacks an identity field; evaluated %s per RFC 7208 default rules"
                % primary.get("identity")
            )
        elif claim.claimed_identity != primary.get("identity"):
            reasons.append(
                "header claimed identity %r but %s was the only evaluable trusted identity"
                % (claim.claimed_identity, primary.get("identity"))
            )
        if primary.get("identity") == "helo":
            reasons.append("HELO identity selected (null MAIL FROM or explicit helo claim)")

    def _record_evidence_conflicts(self, claim: HeaderClaim, conflicts: List[str]):
        """Header-advertised values must never override the trusted source."""
        if claim.header_client_ip:
            if claim.header_client_ip != self.trusted.client_ip:
                conflicts.append(
                    "header client-ip %r conflicts with trusted source %r; trusted value used"
                    % (claim.header_client_ip, self.trusted.client_ip)
                )
        if claim.header_helo and self.trusted.helo and claim.header_helo != self.trusted.helo:
            conflicts.append(
                "header helo %r conflicts with trusted HELO %r; trusted value used"
                % (claim.header_helo, self.trusted.helo)
            )
        if (
            claim.header_envelope_from
            and self.trusted.mail_from
            and claim.header_envelope_from.lower() != self.trusted.mail_from.lower()
        ):
            conflicts.append(
                "header envelope-from %r conflicts with trusted MAIL FROM %r; trusted value used"
                % (claim.header_envelope_from, self.trusted.mail_from)
            )

    @staticmethod
    def _classify(claim: HeaderClaim, primary: dict, usable: List[dict], finding: RecheckFinding):
        if claim.parse_failed:
            finding.consistency = "indeterminate"
            finding.reasons.append("header could not be fully parsed: %s" % claim.parse_error)
            finding.reasons.append(
                "recomputation from trusted inputs still performed; claimed result not verifiable"
            )
            return
        if not usable:
            finding.consistency = "indeterminate"
            finding.reasons.append("no trusted identity could be evaluated")
            return

        recomputed = primary.get("result")
        if primary.get("status") == "error" or recomputed in ("temperror", "permerror"):
            finding.consistency = "indeterminate"
            finding.reasons.append(
                "recomputation returned %s, so the historical claim cannot be confirmed or refuted"
                % recomputed
            )
            finding.reasons.append("explanation: %s" % primary.get("explanation"))
            return
        if claim.claimed_result is None:
            finding.consistency = "indeterminate"
            finding.reasons.append("header carried no parseable SPF result token")
            return

        if claim.claimed_result == recomputed:
            finding.consistency = "consistent"
            mechanism = primary.get("mechanism")
            basis = "recomputed %s for identity=%s domain=%s against trusted client_ip=%s" % (
                recomputed,
                primary.get("identity"),
                primary.get("evaluated_domain"),
                primary.get("inputs_used", {}).get("client_ip"),
            )
            if mechanism:
                basis += " matched mechanism %s" % mechanism
            finding.reasons.append("claimed result matches recomputation: " + basis)
        else:
            finding.consistency = "inconsistent"
            finding.reasons.append(
                "header claims %r but recomputation with the trusted source and offline view "
                "returns %r (%s)"
                % (claim.claimed_result, recomputed, primary.get("explanation"))
            )
            finding.reasons.append(
                "inputs used: ip=%s sender=%r helo=%r"
                % (
                    primary.get("inputs_used", {}).get("client_ip"),
                    primary.get("inputs_used", {}).get("sender"),
                    primary.get("inputs_used", {}).get("helo"),
                )
            )

    def recheck(self, raw_headers) -> RecheckReport:
        """Full replayable run over a raw header block or message."""
        claims = extract_claims(raw_headers)
        findings = [self.evaluate_claim(claim) for claim in claims]

        if not findings:
            overall = "no_spf_claims"
        elif any(f.consistency == "inconsistent" for f in findings):
            overall = "inconsistent"
        elif all(f.consistency == "indeterminate" for f in findings):
            overall = "indeterminate"
        else:
            overall = "consistent"

        return RecheckReport(
            trusted_input=self.trusted.as_record(),
            dns_view=self.view.describe(),
            dns_caveat=DNS_CAVEAT,
            findings=findings,
            overall_consistency=overall,
        )


def recheck_headers(raw_headers, trusted: TrustedInput, view: OfflineDNSView) -> RecheckReport:
    """Convenience wrapper: build a rechecker and run it once."""
    return SPFRechecker(trusted, view).recheck(raw_headers)
