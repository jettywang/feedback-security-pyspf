# Tests for the call-level ExplanationPolicy.
#
# A recording fake DNS proves:
#  * disabling exp= lookups sends no explanation DNS queries
#  * DNS-query macros (domain-specs) are never redacted, display-only
#    macros in exp= text are
#  * the domain context of exp= is correct after nested include/redirect
#  * external explanations carry no raw secrets or CR/LF injection
#  * the SPF result is identical under every policy
from __future__ import print_function
import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import spf

# Sender with a special local part: a "secret" plus a newline that would
# inject an extra SMTP response line if echoed back raw.
SENDER = 'sec+ret\ninj@example.com'
HELO = 'mx.example.org'
FAIL_IP = '198.51.100.9'   # not listed anywhere -> fail via redirect target
PASS_IP = '192.0.2.9'      # listed by the redirect target -> pass

ZONE = {
  # base record: nested include, then redirect, plus its own exp=
  'example.com': [('TXT',
      ('v=spf1 include:_spf.example.com redirect=_spf2.example.net'
       ' exp=_exp.example.com',))],
  '_spf.example.com': [('TXT',
      ('v=spf1 ip4:203.0.113.0/24 -all exp=_exp.%{d}',))],
  '_exp._spf.example.com': [('TXT', ('included %{s}',))],
  '_spf2.example.net': [('TXT',
      ('v=spf1 ip4:192.0.2.0/24 -all exp=_exp.%{d}',))],
  '_exp._spf2.example.net': [('TXT',
      ('denied %{s} from %{i}\r\n550 injected',))],
  '_exp.example.com': [('TXT', ('base %{s}',))],
  # record for truncation tests
  'trunc.example.com': [('TXT', ('v=spf1 -all exp=_exp.trunc.example.com',))],
  # %- expands to the literal escape '%20' (a raw '%' would be invalid)
  '_exp.trunc.example.com': [('TXT', ('abcde%-fghi %{s}',))],
}

class Recorder(object):
  def __init__(self):
    self.queries = []
  def __call__(self, name, qtype, strict=True, timeout=20):
    name = name.lower()
    self.queries.append((name, qtype))
    for t, v in ZONE.get(name, []):
      if t == qtype:
        yield ((name, t), tuple(s.encode('utf-8') for s in v))
  def names(self, qtype='TXT'):
    return [n for n, t in self.queries if t == qtype]

class ExplanationPolicyTest(unittest.TestCase):
  def setUp(self):
    self.rec = Recorder()
    self.saved = spf.DNSLookup
    spf.DNSLookup = self.rec
  def tearDown(self):
    spf.DNSLookup = self.saved

  def run_query(self, ip=FAIL_IP, sender=SENDER, policy=None):
    q = spf.query(i=ip, s=sender, h=HELO, receiver='gateway.example',
                  exp_policy=policy)
    return q, q.check()

  def test_default_policy_fetches_exp_with_redirect_context(self):
    q, (res, code, exp) = self.run_query()
    self.assertEqual((res, code), ('fail', 550))
    # exp= of the redirect target was queried with its own domain context
    self.assertIn('_exp._spf2.example.net', self.rec.names())
    # nested include also fetched its exp= with the included domain context
    self.assertIn('_exp._spf.example.com', self.rec.names())
    # final explanation comes from the redirect target, not the base record
    # nor the included record
    self.assertTrue(exp.startswith('denied '), exp)
    # default policy reproduces historic behaviour: raw sender and the
    # CR/LF from the exp= text are exposed (this is what the privacy
    # policy protects against)
    self.assertIn('sec+ret\ninj@example.com', exp)
    self.assertIn('\r\n550 injected', exp)

  def test_lookup_disabled_sends_no_exp_queries(self):
    policy = spf.ExplanationPolicy(lookup_exp=False)
    q, (res, code, exp) = self.run_query(policy=policy)
    self.assertEqual((res, code), ('fail', 550))
    # no explanation DNS queries at all
    self.assertFalse([n for n in self.rec.names() if '_exp' in n])
    # authorization queries still happen
    self.assertIn('example.com', self.rec.names())
    self.assertIn('_spf2.example.net', self.rec.names())
    # built-in default explanation is used
    self.assertEqual(exp, 'SPF fail - not authorized')

  def test_privacy_policy_redacts_and_sanitizes(self):
    policy = spf.ExplanationPolicy.privacy()
    q, (res, code, exp) = self.run_query(policy=policy)
    self.assertEqual((res, code), ('fail', 550))
    # no raw secret, no newline injection, no connect IP
    self.assertNotIn('sec+ret', exp)
    self.assertNotIn('inj@example.com', exp)
    self.assertNotIn(FAIL_IP, exp)
    self.assertNotIn('\r', exp)
    self.assertNotIn('\n', exp)
    self.assertIn('<s-hidden>', exp)
    # DNS-query macros are never redacted: the exp= domain-spec still
    # expanded %{d} to the real redirect target domain
    self.assertIn('_exp._spf2.example.net', self.rec.names())

  def test_result_identical_across_policies(self):
    policies = [None, spf.ExplanationPolicy(lookup_exp=False),
                spf.ExplanationPolicy.privacy()]
    for ip in (PASS_IP, FAIL_IP):
      results = []
      for policy in policies:
        q, (res, code, exp) = self.run_query(ip=ip, policy=policy)
        results.append((res, code))
      self.assertEqual(results[0], results[1])
      self.assertEqual(results[0], results[2])
    # sanity: the two IPs really do differ in authorization
    self.assertEqual(results[0], ('fail', 550))

  def test_truncation_never_splits_escape(self):
    # unit level
    self.assertEqual(spf._truncate_explanation('abcde%20fghi', 7), 'abcde')
    self.assertEqual(spf._truncate_explanation('abcde%20fghi', 6), 'abcde')
    self.assertEqual(spf._truncate_explanation('abcde%20fghi', 8), 'abcde%20')
    self.assertEqual(spf._truncate_explanation('abcde%20fghi', 5), 'abcde')
    # integration: truncated exp= text ends on a complete escape
    policy = spf.ExplanationPolicy(max_length=7, sanitize_controls=True,
                                   redact_macros='s')
    q, (res, code, exp) = self.run_query(sender='x@trunc.example.com',
                                         policy=policy)
    self.assertEqual((res, code), ('fail', 550))
    self.assertEqual(exp, 'abcde')

  def test_check2_accepts_policy(self):
    policy = spf.ExplanationPolicy(lookup_exp=False)
    res, exp = spf.check2(i=FAIL_IP, s=SENDER, h=HELO, exp_policy=policy)
    self.assertEqual(res, 'fail')
    self.assertEqual(exp, 'SPF fail - not authorized')
    self.assertFalse([n for n in self.rec.names() if '_exp' in n])

if __name__ == '__main__':
  unittest.main()
