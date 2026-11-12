"""Tests for the replayable SPF forensic re-check flow."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spf

from spf_forensics import (
    HeaderClaim,
    OfflineDNSMissing,
    OfflineDNSView,
    SPFRechecker,
    TrustedInput,
    extract_claims,
    recheck_headers,
)
from spf_forensics.dns_view import offline_dns
from spf_forensics.recheck import DNS_CAVEAT


def base_view(missing="empty"):
    view = OfflineDNSView(view_id="unit-snapshot", missing=missing)
    view.put("example.com", "TXT", [["v=spf1 ip4:192.0.2.10 -all"]])
    view.put("example.com", "A", ["192.0.2.10"])
    view.put("mx.example.com", "TXT", [["v=spf1 ip4:192.0.2.10 -all"]])
    view.put("bounce.example.net", "TXT", [["v=spf1 ip4:198.51.100.7 -all"]])
    return view


class HeaderParsingTests(unittest.TestCase):
    def test_extracts_received_spf_and_auth_results(self):
        raw = (
            "Received-SPF: pass client-ip=192.0.2.10;\n"
            ' envelope-from="a@example.com"; helo=mx.example.com; identity=mailfrom\n'
            "Authentication-Results: gw.example.net;\n"
            " spf=fail smtp.mailfrom=example.com (client-ip=203.0.113.66)"
        )
        claims = extract_claims(raw)
        self.assertEqual(len(claims), 2)
        self.assertEqual(claims[0].header_type, "received-spf")
        self.assertEqual(claims[0].claimed_result, "pass")
        self.assertEqual(claims[0].claimed_identity, "mailfrom")
        self.assertEqual(claims[1].claimed_result, "fail")
        self.assertEqual(claims[1].header_client_ip, "203.0.113.66")
        # folded raw header preserved verbatim
        self.assertIn("\n", claims[0].raw)

    def test_missing_identity_is_flagged_not_guessed(self):
        claims = extract_claims(
            "Received-SPF: none client-ip=192.0.2.10; envelope-from=\"a@example.com\""
        )
        self.assertEqual(len(claims), 1)
        self.assertIsNone(claims[0].claimed_identity)
        self.assertTrue(any("identity" in w for w in claims[0].warnings))

    def test_malformed_header_keeps_raw_evidence(self):
        raw = "Received-SPF: @@@ broken ;;; client-ip=not-an-ip"
        claims = extract_claims(raw)
        self.assertEqual(len(claims), 1)
        self.assertTrue(claims[0].parse_failed)
        self.assertEqual(claims[0].raw, raw)

    def test_multiple_spf_results_in_one_auth_results(self):
        raw = (
            "Authentication-Results: gw.example.net; spf=pass smtp.mailfrom=example.com;\n"
            " spf=fail smtp.helo=mx.example.com"
        )
        claims = extract_claims(raw)
        self.assertEqual(len(claims), 1)
        self.assertTrue(any("spf results" in w for w in claims[0].warnings))


class OfflineDNSViewTests(unittest.TestCase):
    def test_lookup_contract_and_audit_log(self):
        view = base_view()
        answers = view.lookup("example.com.", "txt")
        self.assertEqual(answers[0][0], ("example.com", "TXT"))
        self.assertEqual(answers[0][1], (b"v=spf1 ip4:192.0.2.10 -all",))
        self.assertEqual(view.query_log[0]["name"], "example.com")
        self.assertTrue(view.query_log[0]["hit"])
        view.lookup("missing.example", "TXT")
        self.assertFalse(view.query_log[1]["hit"])

    def test_no_network_path_inside_context(self):
        view = base_view()
        with offline_dns(view):
            self.assertIs(spf.DNSLookup.__func__, view.lookup.__func__)
            self.assertIs(spf.DNSLookup.__self__, view)
            result, _ = spf.check2("192.0.2.10", "a@example.com", "mx.example.com")
        # restored to the original module-level function (no bound view)
        self.assertFalse(hasattr(spf.DNSLookup, "__self__"))
        self.assertEqual(result, "pass")
        # everything pyspf needed was served from the view
        self.assertTrue(all(entry["hit"] or entry["qtype"] == "PTR"
                            for entry in view.query_log))

    def test_strict_missing_policy_raises(self):
        view = OfflineDNSView(missing="strict")
        with self.assertRaises(OfflineDNSMissing):
            view.lookup("absent.example", "TXT")

    def test_temperror_missing_policy(self):
        view = OfflineDNSView(missing="temperror")
        with self.assertRaises(spf.TempError):
            view.lookup("absent.example", "TXT")

    def test_fingerprint_is_content_addressable(self):
        view_a, view_b = base_view(), base_view()
        self.assertEqual(view_a.fingerprint(), view_b.fingerprint())
        view_b.put("extra.example", "A", ["10.0.0.1"])
        self.assertNotEqual(view_a.fingerprint(), view_b.fingerprint())


class RecheckFlowTests(unittest.TestCase):
    FORGED = (
        "Received-SPF: pass client-ip=203.0.113.66;\n"
        ' envelope-from="billing@example.com"; helo=mx.example.com;\n'
        " receiver=gw.example.net; mechanism=ip4; identity=mailfrom\n"
        "Authentication-Results: gw.example.net;\n"
        " spf=pass smtp.mailfrom=example.com (client-ip=203.0.113.66)"
    )
    LEGIT = (
        "Received-SPF: pass client-ip=192.0.2.10;\n"
        ' envelope-from="billing@example.com"; helo=mx.example.com;\n'
        " mechanism=ip4; identity=mailfrom"
    )

    def test_forged_pass_is_inconsistent(self):
        trusted = TrustedInput(
            client_ip="203.0.113.66",
            helo="mx.example.com",
            mail_from="billing@example.com",
        )
        report = recheck_headers(self.FORGED, trusted, base_view())
        self.assertEqual(report.overall_consistency, "inconsistent")
        for finding in report.findings:
            self.assertEqual(finding.consistency, "inconsistent")
            self.assertEqual(finding.claimed_result, "pass")
            self.assertEqual(finding.recomputed_primary["result"], "fail")

    def test_legitimate_mail_is_consistent_with_basis(self):
        trusted = TrustedInput(
            client_ip="192.0.2.10",
            helo="mx.example.com",
            mail_from="billing@example.com",
        )
        report = recheck_headers(self.LEGIT, trusted, base_view())
        self.assertEqual(report.overall_consistency, "consistent")
        finding = report.findings[0]
        self.assertEqual(finding.recomputed_primary["result"], "pass")
        self.assertTrue(any("matched mechanism" in r for r in finding.reasons))

    def test_header_ip_never_overrides_trusted_source(self):
        # Header lies that the client was 192.0.2.10; trusted log says otherwise.
        raw = (
            "Received-SPF: pass client-ip=192.0.2.10;\n"
            ' envelope-from="billing@example.com"; helo=mx.example.com; identity=mailfrom'
        )
        trusted = TrustedInput(
            client_ip="203.0.113.66",
            helo="mx.example.com",
            mail_from="billing@example.com",
        )
        report = recheck_headers(raw, trusted, base_view())
        finding = report.findings[0]
        self.assertEqual(finding.consistency, "inconsistent")
        self.assertTrue(any("client-ip" in c for c in finding.evidence_conflicts))
        self.assertEqual(
            finding.recomputed_primary["inputs_used"]["client_ip"], "203.0.113.66"
        )

    def test_missing_identity_uses_mailfrom_default(self):
        raw = (
            "Received-SPF: pass client-ip=192.0.2.10;\n"
            ' envelope-from="billing@example.com"; helo=mx.example.com'
        )
        trusted = TrustedInput("192.0.2.10", "mx.example.com", "billing@example.com")
        report = recheck_headers(raw, trusted, base_view())
        primary = report.findings[0].recomputed_primary
        self.assertEqual(primary["identity"], "mailfrom")
        self.assertTrue(
            any("lacks an identity field" in r for r in report.findings[0].reasons)
        )

    def test_helo_identity_selected_for_null_sender(self):
        raw = (
            "Received-SPF: pass client-ip=198.51.100.7; helo=bounce.example.net;\n"
            " identity=helo; mechanism=ip4"
        )
        trusted = TrustedInput("198.51.100.7", "bounce.example.net", "")
        report = recheck_headers(raw, trusted, base_view())
        finding = report.findings[0]
        self.assertEqual(finding.recomputed_primary["identity"], "helo")
        self.assertEqual(finding.consistency, "consistent")

    def test_explicit_helo_claim_is_evaluated_with_helo_record(self):
        raw = (
            "Authentication-Results: gw.example.net;\n"
            " spf=pass smtp.helo=mx.example.com (client-ip=192.0.2.10)"
        )
        claims = extract_claims(raw)
        trusted = TrustedInput("192.0.2.10", "mx.example.com", "billing@example.com")
        finding = SPFRechecker(trusted, base_view()).evaluate_claim(claims[0])
        self.assertEqual(finding.recomputed_primary["identity"], "helo")
        self.assertEqual(finding.recomputed_primary["result"], "pass")

    def test_parse_failure_is_indeterminate_but_still_recomputes(self):
        raw = "Received-SPF: @@@ broken ;;;"
        trusted = TrustedInput("203.0.113.66", "mx.example.com", "billing@example.com")
        report = recheck_headers(raw, trusted, base_view())
        finding = report.findings[0]
        self.assertEqual(finding.consistency, "indeterminate")
        self.assertIsNotNone(finding.parse_error)
        self.assertEqual(finding.recomputed_primary["result"], "fail")
        self.assertEqual(finding.raw_header, raw)

    def test_dns_gap_yields_indeterminate_not_silent_match(self):
        view = OfflineDNSView(missing="empty")  # no records at all -> SPF "none"
        trusted = TrustedInput("203.0.113.66", "mx.example.com", "billing@example.com")
        raw = (
            "Received-SPF: pass client-ip=203.0.113.66;\n"
            ' envelope-from="billing@example.com"; helo=mx.example.com; identity=mailfrom'
        )
        report = recheck_headers(raw, trusted, view)
        finding = report.findings[0]
        self.assertEqual(finding.consistency, "inconsistent")
        self.assertEqual(finding.recomputed_primary["result"], "none")

    def test_evidence_bundle_preserves_original_and_conditions(self):
        trusted = TrustedInput("203.0.113.66", "mx.example.com", "billing@example.com")
        view = base_view()
        report = recheck_headers(self.FORGED, trusted, view)
        data = report.as_dict()
        self.assertEqual(data["dns_caveat"], DNS_CAVEAT)
        self.assertEqual(data["trusted_input"]["client_ip"], "203.0.113.66")
        self.assertEqual(data["dns_view"]["fingerprint_sha256"], view.fingerprint())
        for finding in data["findings"]:
            self.assertTrue(finding["raw_header"].startswith(
                ("Received-SPF", "Authentication-Results")
            ))
            self.assertTrue(finding["checks"][0]["dns_queries"])
            self.assertIn("inputs_used", finding["checks"][0])

    def test_replay_is_deterministic(self):
        trusted = TrustedInput("192.0.2.10", "mx.example.com", "billing@example.com")
        view1, view2 = base_view(), base_view()
        r1 = recheck_headers(self.LEGIT, trusted, view1).as_dict()
        r2 = recheck_headers(self.LEGIT, trusted, view2).as_dict()
        for bundle in (r1, r2):
            bundle.pop("dns_view")  # identical fingerprints, compare separately
        self.assertEqual(r1, r2)

    def test_invalid_trusted_ip_rejected(self):
        with self.assertRaises(ValueError):
            TrustedInput(client_ip="not-an-ip", helo="mx.example.com",
                         mail_from="a@example.com")

    def test_no_claims_message(self):
        report = recheck_headers(
            "Subject: nothing here\n",
            TrustedInput("192.0.2.10", "mx.example.com", "a@example.com"),
            base_view(),
        )
        self.assertEqual(report.overall_consistency, "no_spf_claims")


if __name__ == "__main__":
    unittest.main(verbosity=2)
