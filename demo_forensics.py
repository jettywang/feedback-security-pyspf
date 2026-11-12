#!/usr/bin/env python3
"""Demonstrate replayable SPF header forensics.

Run with the repository virtualenv so that pyspf and authres are importable:

    .venv/bin/python demo_forensics.py
"""

import json

from spf_forensics import OfflineDNSView, TrustedInput, recheck_headers


def build_view() -> OfflineDNSView:
    """Frozen DNS snapshot representing the records under investigation."""
    view = OfflineDNSView(view_id="incident-snapshot-2026-11-12", missing="empty")
    view.put("example.com", "TXT", [["v=spf1 ip4:192.0.2.10 -all"]])
    view.put("example.com", "A", ["192.0.2.10"])
    view.put("mx.example.com", "TXT", [["v=spf1 ip4:192.0.2.10 -all"]])
    return view


FORGED_HEADERS = """Received-SPF: pass (gateway.example.net: sender authenticated) client-ip=203.0.113.66;
 envelope-from="billing@example.com"; helo=mx.example.com; receiver=gateway.example.net;
 mechanism=ip4; identity=mailfrom
Authentication-Results: gateway.example.net;
 spf=pass smtp.mailfrom=example.com (helo=mx.example.com; client-ip=203.0.113.66)"""

LEGIT_HEADERS = """Received-SPF: pass (gateway.example.net: sender authenticated) client-ip=192.0.2.10;
 envelope-from="billing@example.com"; helo=mx.example.com; receiver=gateway.example.net;
 mechanism=ip4; identity=mailfrom"""


def show(title, report):
    print("=" * 78)
    print(title)
    print("=" * 78)
    print("overall:", report.overall_consistency)
    for finding in report.findings:
        primary = finding.recomputed_primary
        print(
            "  [%s] claim #%d (%s): claimed=%s recomputed=%s -> %s"
            % (
                finding.header_type,
                finding.claim_index,
                primary.get("identity"),
                finding.claimed_result,
                primary.get("result"),
                finding.consistency,
            )
        )
        for reason in finding.reasons:
            print("      -", reason)
        for conflict in finding.evidence_conflicts:
            print("      !", conflict)
    print("  caveat:", report.dns_caveat)
    print()


def main():
    view = build_view()

    # 1. Forged "pass": header advertises an authorised IP, but the trusted
    #    connection log shows an unauthorised source.
    forged_trusted = TrustedInput(
        client_ip="203.0.113.66",
        helo="mx.example.com",
        mail_from="billing@example.com",
        receiver="gateway.example.net",
    )
    forged_report = recheck_headers(FORGED_HEADERS, forged_trusted, view)
    show("FORGED PASS HEADER vs UNAUTHORISED TRUSTED ENVELOPE", forged_report)

    # 2. Legitimate, consistent mail: trusted source matches the SPF policy.
    legit_trusted = TrustedInput(
        client_ip="192.0.2.10",
        helo="mx.example.com",
        mail_from="billing@example.com",
        receiver="gateway.example.net",
    )
    legit_report = recheck_headers(LEGIT_HEADERS, legit_trusted, view)
    show("LEGITIMATE CONSISTENT MAIL", legit_report)

    print("Full structured report of the forged case (evidence bundle):")
    print(json.dumps(forged_report.as_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
