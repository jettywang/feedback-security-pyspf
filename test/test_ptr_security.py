# Security tests for the SPF "ptr" mechanism and the validated-PTR set that
# also backs the %{p} macro.  A PTR record is published by whoever controls the
# reverse zone of the connecting IP, so a reverse name on its own proves
# nothing.  RFC 7208 section 5.5 requires a forward confirmation (A/AAAA for the
# PTR name resolves back to the connecting IP) before the name may take part in
# authorization.  These tests pin that requirement down.
from __future__ import print_function
import socket
import unittest

import spf

CLIENT_IP4 = '192.0.2.10'
CLIENT_IP6 = '2001:db8::10'
OTHER_IP4 = '203.0.113.77'
OTHER_IP6 = '2001:db8::dead'


def arpa_name(ip):
    """Build the in-addr.arpa / ip6.arpa name the way spf.dns_ptr does."""
    probe = spf.query(i=ip, s='probe@example.org', h='helo')
    return '%s.%s.arpa' % (spf.reverse_dots(probe.i), probe.v)


class FakeDNS(object):
    """Recording, in-memory replacement for spf.DNSLookup.

    Zone records are (qtype, value) tuples.  A zone mapped to the string
    'TIMEOUT' raises spf.TempError, modelling a transient resolver failure
    (as opposed to a missing name, which is simply absent from the zone and
    therefore answered like NXDOMAIN / NoAnswer).
    """

    def __init__(self, zone):
        self.zone = zone
        self.calls = []

    def __call__(self, name, qtype, strict=True, timeout=None):
        name = name.lower()
        self.calls.append((name, qtype))
        records = self.zone.get(name, [])
        if records == 'TIMEOUT':
            raise spf.TempError('DNS timeout for %s %s' % (name, qtype))
        for rtype, value in records:
            if rtype != qtype:
                continue
            if rtype == 'AAAA':
                value = bytes(socket.inet_pton(socket.AF_INET6, value))
            elif rtype in ('TXT', 'SPF'):
                value = tuple(part.encode('utf-8') for part in value)
            # The cache key must carry the queried name, mirroring the real
            # DNS drivers (see DNSLookup_dnspython in spf.py).
            yield ((name, rtype), value)

    @property
    def queried_names(self):
        return [name for name, _ in self.calls]

    def names_for(self, qtype):
        return [name for name, qt in self.calls if qt == qtype]


def txt_record(domain, record):
    return (domain, [('TXT', (record,))])


class PtrSecurityTest(unittest.TestCase):

    def setUp(self):
        self._saved_lookup = spf.DNSLookup
        self.fake = None

    def tearDown(self):
        spf.DNSLookup = self._saved_lookup

    def make_query(self, zone, ip=CLIENT_IP4, mailfrom='sender@example.org',
                   strict=1):
        self.fake = FakeDNS(zone)
        spf.DNSLookup = self.fake
        return spf.query(i=ip, s=mailfrom, h='mail.example.org', strict=strict)

    def assertCallOrder(self, expected):
        self.assertEqual(self.fake.calls, expected)

    def test_single_unconfirmed_ptr_does_not_authorize(self):
        # The attacker fully controls the reverse name, but the forward A
        # record points somewhere else: one PTR alone must never authorize.
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), [('PTR', 'mail.attacker.example')]),
            ('mail.attacker.example', [('A', OTHER_IP4)]),
        ])
        q = self.make_query(zone)
        result, _, _ = q.check()
        self.assertEqual(result, 'fail')
        self.assertEqual(q.validated_ptrs(), [])
        # The implementation had to do the forward confirmation lookup and
        # reject the name on mismatch rather than skipping it.
        self.assertEqual(self.fake.names_for('A'), ['mail.attacker.example'])

    def test_multiple_ptr_candidates_each_forward_confirmed(self):
        # Several attacker-controlled names plus one legitimate, bidirectionally
        # consistent name.  Only the confirmed name survives validation.
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), [
                ('PTR', 'attacker1.evil.net'),
                ('PTR', 'attacker2.evil.net'),
                ('PTR', 'mail.example.org'),
            ]),
            ('attacker1.evil.net', [('A', OTHER_IP4)]),
            ('attacker2.evil.net', [('A', '198.51.100.7')]),
            ('mail.example.org', [('A', CLIENT_IP4)]),
        ])
        q = self.make_query(zone)
        result, _, _ = q.check()
        self.assertEqual(result, 'pass')
        self.assertEqual(q.validated_ptrs(), ['mail.example.org'])
        # Exact call order: SPF TXT, the PTR lookup, then one forward lookup
        # per PTR candidate in the order returned.
        self.assertCallOrder([
            ('example.org', 'TXT'),
            (arpa_name(CLIENT_IP4), 'PTR'),
            ('attacker1.evil.net', 'A'),
            ('attacker2.evil.net', 'A'),
            ('mail.example.org', 'A'),
        ])

    def test_ptr_order_swap_keeps_authorization(self):
        ptrs = [
            ('PTR', 'attacker1.evil.net'),
            ('PTR', 'attacker2.evil.net'),
            ('PTR', 'mail.example.org'),
        ]
        base = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            ('attacker1.evil.net', [('A', OTHER_IP4)]),
            ('attacker2.evil.net', [('A', '198.51.100.7')]),
            ('mail.example.org', [('A', CLIENT_IP4)]),
        ])

        def run(ptr_records):
            zone = dict(base)
            zone[arpa_name(CLIENT_IP4)] = list(ptr_records)
            q = self.make_query(zone)
            return q.check()[0], q.validated_ptrs(), list(self.fake.calls)

        first_result, first_ptrs, first_calls = run(ptrs)
        swapped_result, swapped_ptrs, swapped_calls = run(reversed(ptrs))
        self.assertEqual(first_result, swapped_result)
        self.assertEqual(first_result, 'pass')
        # Same validated name either way, and the forward-lookup order simply
        # follows the (swapped) PTR answer order.
        self.assertEqual(first_ptrs, swapped_ptrs)
        self.assertEqual(swapped_calls, [
            ('example.org', 'TXT'),
            (arpa_name(CLIENT_IP4), 'PTR'),
            ('mail.example.org', 'A'),
            ('attacker2.evil.net', 'A'),
            ('attacker1.evil.net', 'A'),
        ])
        # Three candidates in both runs: none is dropped before confirmation.
        self.assertEqual(len(self.fake.names_for('A')), 3)

    def test_suffix_lookalike_respects_label_boundary(self):
        # "mail.notexample.org" ends with the string "notexample.org", which in
        # turn contains "example.org", but it is not within the example.org
        # label boundary even though its A record confirms back to our IP.
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), [('PTR', 'mail.notexample.org')]),
            ('mail.notexample.org', [('A', CLIENT_IP4)]),
        ])
        q = self.make_query(zone)
        self.assertEqual(q.check()[0], 'fail')
        # The name is forward-validated, yet domainmatch must reject it:
        # validation and suffix authorization are separate gates.
        self.assertEqual(q.validated_ptrs(), ['mail.notexample.org'])
        self.assertFalse(
            spf.domainmatch(q.validated_ptrs(), 'example.org'))
        self.assertTrue(
            spf.domainmatch(['mail.example.org'], 'example.org'))

    def test_ip6_reverse_requires_aaaa_confirmation(self):
        arpa = arpa_name(CLIENT_IP6).lower()
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa, [
                ('PTR', 'evil.example.net'),
                ('PTR', 'mail.example.org'),
            ]),
            ('evil.example.net', [('AAAA', OTHER_IP6)]),
            ('mail.example.org', [('AAAA', CLIENT_IP6)]),
        ])
        q = self.make_query(zone, ip=CLIENT_IP6)
        self.assertEqual(q.check()[0], 'pass')
        self.assertEqual(q.validated_ptrs(), ['mail.example.org'])
        self.assertEqual(self.fake.names_for('AAAA'),
                         ['evil.example.net', 'mail.example.org'])
        self.assertEqual(self.fake.names_for('A'), [])

    def test_ip6_unconfirmed_ptr_rejected(self):
        arpa = arpa_name(CLIENT_IP6).lower()
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa, [('PTR', 'evil.example.net')]),
            ('evil.example.net', [('AAAA', OTHER_IP6)]),
        ])
        q = self.make_query(zone, ip=CLIENT_IP6)
        self.assertEqual(q.check()[0], 'fail')
        self.assertEqual(q.validated_ptrs(), [])

    def test_ptr_candidate_cap_is_enforced(self):
        # 12 PTR names: at most MAX_PTR (10) may receive forward lookups.
        names = ['n%02d.evil.net' % idx for idx in range(12)]
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:evil.net -all'),
            (arpa_name(CLIENT_IP4), [('PTR', name) for name in names]),
        ])
        for idx, name in enumerate(names):
            # Only the 6th candidate (still inside the first 10) confirms back.
            zone[name] = [('A',
                           CLIENT_IP4 if idx == 5 else OTHER_IP4)]
        q = self.make_query(zone)
        self.assertEqual(q.check()[0], 'pass')
        self.assertEqual(q.validated_ptrs(), ['n05.evil.net'])
        forward = self.fake.names_for('A')
        self.assertEqual(len(forward), spf.MAX_PTR)
        self.assertEqual(forward, names[:spf.MAX_PTR])
        # Candidates beyond the cap are never looked up, so they can never
        # enter the authorization match even if they would confirm.
        for name in names[spf.MAX_PTR:]:
            self.assertNotIn(name, self.fake.queried_names)

    def test_ptr_candidate_cap_harsh_mode_is_ambiguity(self):
        # strict=2 turns an over-limit PTR answer set into an AmbiguityWarning
        # before any forward lookup is attempted.
        names = ['n%02d.evil.net' % idx for idx in range(spf.MAX_PTR + 1)]
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr -all'),
            (arpa_name(CLIENT_IP4), [('PTR', name) for name in names]),
        ])
        for name in names:
            zone[name] = [('A', CLIENT_IP4)]
        q = self.make_query(zone, strict=2)
        self.assertEqual(q.check()[0], 'ambiguous')
        self.assertEqual(self.fake.names_for('A'), [])

    def test_transient_failure_is_not_treated_as_mismatch(self):
        # A timeout on the forward A lookup is a temperror, not a fail: the
        # unvalidated name must not be silently collapsed into "no match".
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), [('PTR', 'mail.example.org')]),
            ('mail.example.org', 'TIMEOUT'),
        ])
        q = self.make_query(zone)
        self.assertEqual(q.check()[0], 'temperror')
        self.assertEqual(self.fake.names_for('A'), ['mail.example.org'])

        # A timeout on the PTR lookup itself is likewise transient in the
        # default (strict) processing.
        zone[arpa_name(CLIENT_IP4)] = 'TIMEOUT'
        zone['mail.example.org'] = [('A', CLIENT_IP4)]
        q = self.make_query(zone)
        self.assertEqual(q.check()[0], 'temperror')

    def test_harsh_mode_collapses_ptr_timeout_to_ambiguity(self):
        # strict=2 wraps the PTR pre-check in a broad except that turns a
        # TempError into an AmbiguityWarning (see query.validated_ptrs).  Lock
        # that divergence down so it cannot silently change; the strict=1 path
        # above keeps the proper temperror distinction.
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), 'TIMEOUT'),
        ])
        q = self.make_query(zone, strict=2)
        self.assertEqual(q.check()[0], 'ambiguous')
        # No forward lookup happens when the PTR pre-check fails.
        self.assertEqual(self.fake.names_for('A'), [])

    def test_definitive_mismatch_is_fail_not_temperror(self):
        # NXDOMAIN/NoAnswer on the forward lookup, or an address that does not
        # point back, are definitive: the mechanism simply does not match and
        # evaluation continues to "-all" => fail.
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), [('PTR', 'ghost.example.org')]),
            # ghost.example.org intentionally absent from the zone.
        ])
        q = self.make_query(zone)
        self.assertEqual(q.check()[0], 'fail')
        self.assertEqual(q.validated_ptrs(), [])

        zone['ghost.example.org'] = [('A', OTHER_IP4)]
        q = self.make_query(zone)
        self.assertEqual(q.check()[0], 'fail')
        self.assertEqual(q.validated_ptrs(), [])

    def test_p_macro_only_exposes_forward_confirmed_names(self):
        # %{p} is derived from the same validated PTR set, so an attacker's
        # reverse-only name must not surface as the validated client domain.
        zone = dict([
            txt_record('example.org', 'v=spf1 ptr:example.org -all'),
            (arpa_name(CLIENT_IP4), [
                ('PTR', 'evil.example.net'),
                ('PTR', 'mail.example.org'),
            ]),
            ('evil.example.net', [('A', OTHER_IP4)]),
            ('mail.example.org', [('A', CLIENT_IP4)]),
        ])
        q = self.make_query(zone)
        self.assertEqual(q.getp(), 'mail.example.org')

        zone[arpa_name(CLIENT_IP4)] = [('PTR', 'evil.example.net')]
        q = self.make_query(zone)
        self.assertEqual(q.getp(), 'unknown')


if __name__ == '__main__':
    unittest.main()
