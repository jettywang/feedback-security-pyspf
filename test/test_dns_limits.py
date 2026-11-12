# Regression tests for the RFC 7208 section 4.6.4 DNS processing limits.
#
# These tests use the same in-memory DNS emulator as the YAML driven suite
# (testspf.DNSLookup); no external network access is performed.  Unlike the
# YAML tests, which only check the final SPF result, these cases keep three
# independent counters so that a limit cannot be evaded by cache hits or by
# nesting depth:
#
#   mechanism budget  - query.lookups, incremented once for every
#                       include/redirect/a/mx/ptr/exists term that is
#                       actually evaluated (the 10 per-check "do DNS" limit).
#   network calls     - real entries into DNSLookup, i.e. cache misses.
#   void lookups      - query.void_lookups, empty answers that are not
#                       explicitly ignored (the RFC 7208 limit of two).
#
# Each table-driven case pins down the full counter trajectory and the final
# SPF result.  A branch that wrongly resets the mechanism budget while
# descending into an include/redirect therefore changes both the trajectory
# and the result of the over-limit cases and fails the test, while legitimate
# reuse of a cached answer is still charged to the mechanism budget but is
# never counted as a second network call.
from __future__ import print_function
import os
import sys
import unittest

# The in-memory test emulator lives next to this file; make it importable both
# from the test directory and via package discovery from the repository root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import spf
import testspf

# The real in-memory DNS engine used by the rest of the test suite.
_REAL_DNS_LOOKUP = testspf.DNSLookup


class CountingQuery(spf.query):
  """query subclass recording the three independent counters.

  ``budget_steps`` logs the cumulative query.lookups value each time a
  mechanism/modifier asks for budget.  ``dns_steps`` logs one entry per call
  to query.dns() with whether it hit the cache.  ``void_steps`` records the
  empty answers counted against the void-lookup limit.
  """

  def __init__(self, *args, **kw):
    spf.query.__init__(self, *args, **kw)
    self.budget_steps = []
    self.dns_steps = []
    self.void_steps = []
    self.net_calls = []

  def check_lookups(self):
    spf.query.check_lookups(self)
    self.budget_steps.append(self.lookups)

  def dns(self, name, qtype, cnames=None, ignore_void=False):
    key = (str(name).lower().rstrip('.'), qtype)
    cached = key in self.cache
    result = spf.query.dns(self, name, qtype, cnames, ignore_void)
    if not result and not ignore_void:
      self.void_steps.append((key[0], qtype))
    self.dns_steps.append((key[0], qtype, 'cache' if cached else 'net',
                           len(result)))
    return result


def counting_dns_lookup(counter, name, qtype, strict=True, timeout=None,
                        level=0):
  # Only top-level invocations are new network transactions; the emulator's
  # own one-level CNAME chase re-enters this generator with level=1.
  if not level:
    counter.net_calls.append((name.lower(), qtype))
  for answer in _REAL_DNS_LOOKUP(name, qtype, strict, timeout, level):
    yield answer


# Explicit, human-readable expectations.  Every counter trajectory below is
# part of the specification rather than being derived from the implementation.
#
#   result       : final SPF result
#   budget_steps : query.lookups value after each *recorded* budget step
#   final_lookups: query.lookups once evaluation has finished (a step that
#                  raises PermError still increments the counter first, so the
#                  over-limit cases end one above their recorded trajectory)
#   net_calls    : (name, qtype) for each cache-miss DNS transaction
#   dns_steps    : (name, qtype, cache|net, answer count) per query.dns call
#   void_steps   : (name, qtype) for each counted empty answer
#   final_void   : query.void_lookups at the end of evaluation
def chain_zone(depth, leaf='v=spf1 ip4:192.0.2.10 -all'):
  zonedata = {
    'limit.test': [{'TXT': 'v=spf1 include:i1.limit.test -all'}],
  }
  for n in range(1, depth + 1):
    if n < depth:
      record = 'v=spf1 include:i%d.limit.test -all' % (n + 1)
    else:
      record = leaf
    zonedata['i%d.limit.test' % n] = [{'TXT': record}]
  return zonedata


LIMIT_CASES = [
  dict(
    id='include-chain-exactly-at-limit',
    description='Ten nested includes exhaust, but do not exceed, the budget',
    zonedata=chain_zone(10),
    result='pass',
    final_lookups=10,
    budget_steps=list(range(1, 11)),
    net_calls=[('limit.test', 'TXT')] + [
      ('i%d.limit.test' % n, 'TXT') for n in range(1, 11)],
    dns_steps=[('limit.test', 'TXT', 'net', 1)] + [
      ('i%d.limit.test' % n, 'TXT', 'net', 1) for n in range(1, 11)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='include-chain-one-over-limit',
    description='Eleven nested includes raise PermError on the 11th term',
    zonedata=chain_zone(11),
    result='permerror',
    budget_steps=list(range(1, 11)),
    # check_lookups increments to eleven and then raises, so the final counter
    # value is one past the last step the subclass was able to record.
    final_lookups=11,
    # The 11th check_lookups raises before i11's TXT record is fetched.
    net_calls=[('limit.test', 'TXT')] + [
      ('i%d.limit.test' % n, 'TXT') for n in range(1, 11)],
    dns_steps=[('limit.test', 'TXT', 'net', 1)] + [
      ('i%d.limit.test' % n, 'TXT', 'net', 1) for n in range(1, 11)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='ip4-short-circuits-queued-mx',
    description='A matching ip4 stops evaluation before eleven mx terms',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 ip4:192.0.2.10 ' + 'mx ' * 11 + '-all'}],
    },
    result='pass',
    budget_steps=[],
    final_lookups=0,
    net_calls=[('limit.test', 'TXT')],
    dns_steps=[('limit.test', 'TXT', 'net', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='include-chain-short-circuited-early',
    description='A passing include stops the remaining includes from running',
    zonedata={
      'limit.test': [{'TXT': 'v=spf1 include:i1.limit.test -all'}],
      'i1.limit.test': [{'TXT': 'v=spf1 include:i2.limit.test -all'}],
      'i2.limit.test': [{'TXT': 'v=spf1 include:i3.limit.test -all'}],
      'i3.limit.test': [{'TXT': 'v=spf1 ip4:192.0.2.10 -all'}],
      'i4.limit.test': [{'TXT': 'v=spf1 -all'}],
    },
    result='pass',
    budget_steps=[1, 2, 3],
    final_lookups=3,
    net_calls=[('limit.test', 'TXT'), ('i1.limit.test', 'TXT'),
               ('i2.limit.test', 'TXT'), ('i3.limit.test', 'TXT')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('i1.limit.test', 'TXT', 'net', 1),
               ('i2.limit.test', 'TXT', 'net', 1),
               ('i3.limit.test', 'TXT', 'net', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='duplicate-include-charged-twice-served-once',
    description='Same domain included twice: budget twice, one network call',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 include:shared.limit.test include:shared.limit.test -all'}],
      'shared.limit.test': [{'TXT': 'v=spf1 ip4:192.0.2.99 -all'}],
    },
    result='fail',
    budget_steps=[1, 2],
    final_lookups=2,
    net_calls=[('limit.test', 'TXT'), ('shared.limit.test', 'TXT')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('shared.limit.test', 'TXT', 'net', 1),
               ('shared.limit.test', 'TXT', 'cache', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='duplicate-a-charged-twice-served-once',
    description='Repeated a mechanism reuses the cached A without a new call',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 a:host.limit.test a:host.limit.test -all'}],
      'host.limit.test': [{'A': '192.0.2.55'}],
    },
    result='fail',
    budget_steps=[1, 2],
    final_lookups=2,
    net_calls=[('limit.test', 'TXT'), ('host.limit.test', 'A')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('host.limit.test', 'A', 'net', 1),
               ('host.limit.test', 'A', 'cache', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='redirect-charged-during-modifier-scan',
    description='redirect= consumes budget even before mechanism evaluation',
    zonedata=dict([
      ('limit.test', [{'TXT':
        'v=spf1 ' + ' '.join('a:h%d.limit.test' % n for n in range(10))
        + ' redirect=red.limit.test'}]),
      ('red.limit.test', [{'TXT': 'v=spf1 -all'}]),
    ] + [('h%d.limit.test' % n, [{'A': '192.0.2.%d' % (n + 1)}])
         for n in range(10)]),
    result='permerror',
    # The first ten steps come from the a mechanisms; the eleventh increment
    # (the redirect modifier scanned before mechanism evaluation) raises.
    budget_steps=list(range(1, 11)),
    final_lookups=11,
    # The tenth a records budget step ten and fetches h9; the redirect's
    # raising increment happens before any further DNS work, so only the
    # initial TXT and nine A lookups reach the network.
    net_calls=[('limit.test', 'TXT')] + [
      ('h%d.limit.test' % n, 'A') for n in range(9)],
    dns_steps=[('limit.test', 'TXT', 'net', 1)] + [
      ('h%d.limit.test' % n, 'A', 'net', 1) for n in range(9)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='redirect-reached-within-budget-uses-cache',
    description='A cached redirect target costs budget but no second call',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 include:red.limit.test redirect=red.limit.test'}],
      'red.limit.test': [{'TXT': 'v=spf1 -all'}],
    },
    result='fail',
    budget_steps=[1, 2],
    final_lookups=2,
    net_calls=[('limit.test', 'TXT'), ('red.limit.test', 'TXT')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('red.limit.test', 'TXT', 'net', 1),
               ('red.limit.test', 'TXT', 'cache', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='mx-one-budget-multiple-exchange-lookups',
    description='mx charges one term; MX and each exchange A are network calls',
    sender='foo@mx1.limit.test', host='192.0.2.77',
    zonedata={
      'mx1.limit.test': [
        {'TXT': 'v=spf1 mx -all'},
        {'MX': [10, 'ex1.limit.test']},
        {'MX': [20, 'ex2.limit.test']},
      ],
      'ex1.limit.test': [{'A': '192.0.2.77'}],
      'ex2.limit.test': [{'A': '192.0.2.78'}],
    },
    result='pass',
    budget_steps=[1],
    final_lookups=1,
    net_calls=[('mx1.limit.test', 'TXT'), ('mx1.limit.test', 'MX'),
               ('ex1.limit.test', 'A'), ('ex2.limit.test', 'A')],
    dns_steps=[('mx1.limit.test', 'TXT', 'net', 1),
               ('mx1.limit.test', 'MX', 'net', 2),
               ('ex1.limit.test', 'A', 'net', 1),
               ('ex2.limit.test', 'A', 'net', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='include-mx-include-cumulative-budget',
    description='Nested include, mx and a later include share one counter',
    sender='foo@limit.test', host='192.0.2.10',
    zonedata={
      'limit.test': [
        {'TXT':
         'v=spf1 include:a.limit.test mx include:b.limit.test -all'},
        {'MX': [5, 'mxhost.limit.test']},
      ],
      'a.limit.test': [{'TXT': 'v=spf1 -all'}],
      'b.limit.test': [{'TXT': 'v=spf1 -all'}],
      'mxhost.limit.test': [{'A': '192.0.2.8'}],
    },
    result='fail',
    budget_steps=[1, 2, 3],
    final_lookups=3,
    net_calls=[('limit.test', 'TXT'), ('a.limit.test', 'TXT'),
               ('limit.test', 'MX'), ('mxhost.limit.test', 'A'),
               ('b.limit.test', 'TXT')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('a.limit.test', 'TXT', 'net', 1),
               ('limit.test', 'MX', 'net', 1),
               ('mxhost.limit.test', 'A', 'net', 1),
               ('b.limit.test', 'TXT', 'net', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='ptr-forward-confirmed-match',
    description='ptr charges one term for PTR plus forward A validation',
    host='192.0.2.10',
    zonedata={
      'limit.test': [{'TXT': 'v=spf1 ptr:limit.test -all'}],
      '10.2.0.192.in-addr.arpa': [{'PTR': 'host.limit.test'}],
      'host.limit.test': [{'A': '192.0.2.10'}],
    },
    result='pass',
    budget_steps=[1],
    final_lookups=1,
    net_calls=[('limit.test', 'TXT'),
               ('10.2.0.192.in-addr.arpa', 'PTR'),
               ('host.limit.test', 'A')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('10.2.0.192.in-addr.arpa', 'PTR', 'net', 1),
               ('host.limit.test', 'A', 'net', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='duplicate-ptr-reuses-cached-records',
    description='Two ptr terms cost two budget slots but one PTR/A fetch',
    host='192.0.2.10',
    zonedata={
      # The validated name is under limit.test, so the other.limit.test
      # suffix never matches and both ptr terms are evaluated.
      'limit.test': [{'TXT':
        'v=spf1 ptr:other.limit.test ptr:other.limit.test -all'}],
      '10.2.0.192.in-addr.arpa': [{'PTR': 'host.limit.test'}],
      'host.limit.test': [{'A': '192.0.2.10'}],
    },
    result='fail',
    budget_steps=[1, 2],
    final_lookups=2,
    net_calls=[('limit.test', 'TXT'),
               ('10.2.0.192.in-addr.arpa', 'PTR'),
               ('host.limit.test', 'A')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('10.2.0.192.in-addr.arpa', 'PTR', 'net', 1),
               ('host.limit.test', 'A', 'net', 1),
               ('10.2.0.192.in-addr.arpa', 'PTR', 'cache', 1),
               ('host.limit.test', 'A', 'cache', 1)],
    void_steps=[],
    final_void=0,
  ),
  dict(
    id='void-lookups-exactly-at-limit',
    description='Two empty answers stay within the void limit',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 a:nx1.limit.test a:nx2.limit.test ?all'}],
    },
    result='neutral',
    budget_steps=[1, 2],
    final_lookups=2,
    net_calls=[('limit.test', 'TXT'),
               ('nx1.limit.test', 'A'), ('nx2.limit.test', 'A')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('nx1.limit.test', 'A', 'net', 0),
               ('nx2.limit.test', 'A', 'net', 0)],
    void_steps=[('nx1.limit.test', 'A'), ('nx2.limit.test', 'A')],
    final_void=2,
  ),
  dict(
    id='void-lookups-one-over-limit',
    description='A third empty answer trips the void lookup PermError',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 a:nx1.limit.test a:nx2.limit.test a:nx3.limit.test ?all'}],
    },
    result='permerror',
    # check_lookups runs before the dns() call that detects the third void.
    budget_steps=[1, 2, 3],
    final_lookups=3,
    # The third lookup still reaches the network; dns() raises only after the
    # empty answer comes back, so it never reaches the recorded dns trajectory.
    net_calls=[('limit.test', 'TXT'),
               ('nx1.limit.test', 'A'), ('nx2.limit.test', 'A'),
               ('nx3.limit.test', 'A')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('nx1.limit.test', 'A', 'net', 0),
               ('nx2.limit.test', 'A', 'net', 0)],
    # The third empty answer increments the counter to three and then raises,
    # so it is reflected in final_void but not in the recorded void_steps.
    void_steps=[('nx1.limit.test', 'A'), ('nx2.limit.test', 'A')],
    final_void=3,
  ),
  dict(
    id='void-lookups-accumulate-across-include-recursion',
    description='Void answers in a nested include share one void counter',
    zonedata={
      'limit.test': [{'TXT':
        'v=spf1 a:nx0.limit.test include:sub.limit.test ?all'}],
      'sub.limit.test': [{'TXT':
        'v=spf1 a:nx1.limit.test a:nx2.limit.test ?all'}],
    },
    result='permerror',
    # a:nx0, the include itself, then the two nested a mechanisms.
    budget_steps=[1, 2, 3, 4],
    final_lookups=4,
    # The third empty answer (nx2) is fetched before dns() raises, so it is
    # in net_calls but not in the completed dns/void trajectories.
    net_calls=[('limit.test', 'TXT'), ('nx0.limit.test', 'A'),
               ('sub.limit.test', 'TXT'), ('nx1.limit.test', 'A'),
               ('nx2.limit.test', 'A')],
    dns_steps=[('limit.test', 'TXT', 'net', 1),
               ('nx0.limit.test', 'A', 'net', 0),
               ('sub.limit.test', 'TXT', 'net', 1),
               ('nx1.limit.test', 'A', 'net', 0)],
    # One void in the outer record and one in the include are both counted;
    # resetting the counter while descending would miss the third entirely.
    void_steps=[('nx0.limit.test', 'A'), ('nx1.limit.test', 'A')],
    final_void=3,
  ),
]


class DNSLimitTests(unittest.TestCase):

  def setUp(self):
    self.saved_zonedata = testspf.zonedata

  def tearDown(self):
    testspf.zonedata = self.saved_zonedata

  def _run(self, case):
    testspf.zonedata = testspf.loadZone({'zonedata': case['zonedata']})
    q = CountingQuery(
      i=case.get('host', '192.0.2.10'),
      s=case.get('sender', 'foo@limit.test'),
      h='mail.example.com')
    q.set_default_explanation('DEFAULT')
    original_lookup = spf.DNSLookup
    spf.DNSLookup = lambda *a, **kw: counting_dns_lookup(q, *a, **kw)
    try:
      result, code, explanation = q.check()
    finally:
      spf.DNSLookup = original_lookup
    return q, result

  def test_limit_cases(self):
    for case in LIMIT_CASES:
      q, result = self._run(case)
      self.assertEqual(case['result'], result,
        '%s: result %r != %r' % (case['id'], result, case['result']))
      self.assertEqual(case['budget_steps'], q.budget_steps,
        '%s: mechanism budget trajectory' % case['id'])
      self.assertEqual(case['net_calls'], q.net_calls,
        '%s: network call trajectory' % case['id'])
      self.assertEqual(case['dns_steps'], q.dns_steps,
        '%s: dns() cache/network trajectory' % case['id'])
      self.assertEqual(case['void_steps'], q.void_steps,
        '%s: void lookup trajectory' % case['id'])
      # Terminal counter values are specified independently of the recorded
      # trajectories: a step that raises still increments the counter first.
      self.assertEqual(case['final_lookups'], q.lookups,
        '%s: final mechanism budget' % case['id'])
      self.assertEqual(case['final_void'], q.void_lookups,
        '%s: final void lookup count' % case['id'])
      # The recorded trajectory must agree with the terminal value wherever
      # evaluation did not terminate on the increment itself.
      self.assertEqual(len(case['budget_steps']), len(q.budget_steps),
        '%s: number of recorded budget steps' % case['id'])
      self.assertTrue(
        case['final_lookups'] >= len(case['budget_steps']),
        '%s: terminal budget cannot be below its trajectory' % case['id'])
      self.assertTrue(
        case['final_void'] >= len(case['void_steps']),
        '%s: terminal void count cannot be below its trajectory' % case['id'])
      # Network and cache classifications are two views of the same calls.
      # Every recorded cache miss is a network call; net_calls can be longer
      # only when dns() raised after the lookup (the void over-limit case),
      # in which case the raising call has no completed dns_steps entry.
      net_from_steps = [(s[0], s[1]) for s in q.dns_steps
                        if s[2] == 'net']
      self.assertEqual(net_from_steps, q.net_calls[:len(net_from_steps)],
        '%s: network counter and cache-miss trajectory disagree' % case['id'])
      self.assertIn(len(q.net_calls) - len(net_from_steps), (0, 1),
        '%s: at most one network call can terminate inside dns()'
        % case['id'])
      # A key may be visited several times; only the first visit is a network
      # transaction and every later visit must be served from cache.
      seen = set()
      for name, qtype, source, _answer_count in q.dns_steps:
        key = (name, qtype)
        if source == 'cache':
          self.assertIn(key, seen,
            '%s: %r served from cache before being fetched'
            % (case['id'], key))
        else:
          self.assertEqual('net', source)
          seen.add(key)
      # Any network call missing from dns_steps must be the raising lookup.
      for extra in q.net_calls[len(net_from_steps):]:
        self.assertEqual(case['result'], 'permerror',
          '%s: unrecorded network call outside a raising lookup'
          % case['id'])


class BudgetResetMutationTests(unittest.TestCase):
  """Demonstrate that the trajectories catch limit-evading implementations."""

  def setUp(self):
    self.saved_zonedata = testspf.zonedata

  def tearDown(self):
    testspf.zonedata = self.saved_zonedata

  def test_recursion_budget_reset_evades_limit_without_patch(self):
    # This query emulates the bug under test: the mechanism counter is reset
    # whenever evaluation descends into an include.  The eleven-include chain
    # then never reaches eleven on a single level and wrongly passes.
    class ResetBudgetQuery(CountingQuery):
      def check1(self, spf_record, domain, recursion):
        if recursion:
          self.lookups = 0
        return spf.query.check1(self, spf_record, domain, recursion)

    testspf.zonedata = testspf.loadZone({'zonedata': chain_zone(11)})
    q = ResetBudgetQuery(i='192.0.2.10', s='foo@limit.test',
                         h='mail.example.com')
    result, _, _ = q.check()
    expected = next(c for c in LIMIT_CASES
                    if c['id'] == 'include-chain-one-over-limit')
    # Sanity check on the mutation itself: without a shared counter, the
    # over-limit chain is no longer rejected.
    self.assertEqual('pass', result)
    self.assertNotEqual(expected['result'], result)
    self.assertNotEqual(expected['budget_steps'], q.budget_steps)
    self.assertNotEqual(expected['final_lookups'], q.lookups)


def suite():
  loader = unittest.TestLoader()
  return loader.loadTestsFromModule(__import__(__name__))


if __name__ == '__main__':
  unittest.TextTestRunner(verbosity=2).run(suite())
