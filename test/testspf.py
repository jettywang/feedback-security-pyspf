# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2006 Business Management Systems, Inc.

# This module is free software, and you may redistribute it and/or modify
# it under the same terms as Python itself, so long as this copyright message
# and disclaimer are retained in their original form.

# Run SPF test cases in the YAML format specified by the SPF council.
from __future__ import print_function
import unittest
import socket
import sys
import spf
import re
try:
  import yaml
except:
  print("yaml can be found at http://pyyaml.org/")
  print("Tested with PYYAML 3.04 up to 5.1.2")
  raise

zonedata = {}
RE_IP4 = re.compile(r'\.'.join(
    [r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)+'$')

def DNSLookup(name,qtype,strict=True,timeout=None,level=0):
  try:
    #print name,qtype
    timeout = True

    # emulate pydns-2.3.0 label processing
    a = []
    for label in name.split('.'):
      if label:
        if len(label) > 63:
          raise spf.TempError('DNS label too long')
        a.append(label)
    name = '.'.join(a)

    for i in zonedata[name.lower()]:
      if i == 'TIMEOUT':
        if timeout:
          raise spf.TempError('DNS timeout')
        return
      t,v,n = i
      if t == qtype:
        timeout = False
      if v == 'TIMEOUT':
        if t == qtype:
          raise spf.TempError('DNS timeout')
        continue
      # keep test zonedata human readable, but translate to simulate pydns
      if t == 'AAAA':
        v = bytes(socket.inet_pton(socket.AF_INET6,v))
      elif t in ('TXT','SPF'):
        v = tuple([s.encode('utf-8') for s in v])
      yield ((n,t),v)
      # emulate CNAME additional info for 1 level
      if not level and t == 'CNAME':
        for j in DNSLookup(v,qtype,strict,timeout,1):
          yield j
  except KeyError:
    if name.startswith('error.'):
      raise spf.TempError('DNS timeout')

spf.DNSLookup = DNSLookup

class SPFTest(object):
  def __init__(self,testid,scenario,data={}):
    self.id = testid
    self.scenario = scenario
    self.explanation = None
    self.bestguess = None
    self.spec = None
    self.header = None
    self.strict = True
    self.receiver = None
    self.comment = []
    if 'result' not in data:
      print(testid,'missing result')
    for k,v in list(data.items()):
      setattr(self,k,v)
    if type(self.comment) is str:
      self.comment = self.comment.splitlines()

def getrdata(r,name):
  "Unpack rdata given as list of maps to list of tuples."
  txt = []        # generated TXT records
  gen = True
  for m in r:
    try:
      for i in list(m.items()):
        t,v = i
        if t in ('TXT','SPF') and type(v) == str:
          v = (v,)
        if t == 'TXT':
          gen = False # no generated TXT records
        elif t == 'SPF' and gen:
          txt.append(('TXT',v,name))
        if v != ('NONE',):
          yield (t,v,name)
    except:
      yield m
  if gen:
    for i in txt:
      yield i

def loadZone(data):
  return dict([
    (d.lower(), list(getrdata(r,d))) for d,r in list(data['zonedata'].items())
  ])

class SPFScenario(object):
  def __init__(self,filename=None,data={}):
    self.id = None
    self.filename = filename
    self.comment = []
    self.zonedata = {}
    self.tests = {}
    if data:
      self.zonedata= loadZone(data)
      #print self.zonedata
      for t,v in list(data['tests'].items()):
        self.tests[t] = SPFTest(t,self,v)
      if 'id' in data:
        self.id = data['id']
      if 'comment' in data:
        self.comment = data['comment'].splitlines()

  def addDNS(self,name,val):
    self.zonedata.setdefault(name,[]).append(val)

  def addTest(self,test):
    self.tests[test.id] = test

def loadYAML(fname):
  "Load testcases in YAML format.  Return map of SPFTests by name."
  fp = open(fname,'rb')
  try:
    tests = {}
    for s in yaml.safe_load_all(fp):
      scenario = SPFScenario(fname,data=s)
      for k,v in list(scenario.tests.items()):
        tests[k] = v
    return tests
  finally: fp.close()

oldresults = { 'unknown': 'permerror', 'error': 'temperror' }

verbose = 0
warnings = []

class SPFTestCase(unittest.TestCase):

  def __init__(self,t):
    unittest.TestCase.__init__(self)
    self._spftest = t
    self._testMethodName = 'runTest'
    self._testMethodDoc = str(t.spec)

  def id(self):
    t = self._spftest
    return t.id + ' in ' + t.scenario.filename

  def setUp(self):
    global zonedata
    self.savezonedata = zonedata

  def tearDown(self):
    global zonedata
    zonedata = self.savezonedata

  def warn(self,msg):
    global warnings
    warnings.append(msg)

  def runTest(self):
    global zonedata
    t = self._spftest
    zonedata = t.scenario.zonedata
    q = spf.query(i=t.host, s=t.mailfrom, h=t.helo, strict=t.strict)
    q.verbose = verbose
    q.set_default_explanation('DEFAULT')
    res,code,exp = q.check()
    #print q.mechanism
    if res in oldresults:
      res = oldresults[res]
    ok = True
    msg = ''
    if res != t.result and res not in t.result:
      if verbose: msg += ' '.join((t.result,'!=',res))+'\n'
      ok = False
    elif res != t.result and res != t.result[0]:
      self.warn("WARN: %s in %s, %s: %s preferred to %s" % (
	  t.id,t.scenario.filename,t.spec,t.result[0],res))
    if t.explanation is not None and t.explanation != exp:
      if verbose: msg += ' '.join((t.explanation,'!=',exp))+'\n'
      ok = False
    if t.header:
      self.assertEqual(t.header,q.get_header(res,receiver=t.receiver))
    if q.perm_error and t.bestguess is not None \
        and q.perm_error.ext[0] != t.bestguess:
      ok = False
    if not ok:
      print('Session cache:',q.cache)
      if verbose and not t.explanation: msg += exp+'\n'
      if verbose > 1: msg += t.scenario.zonedata
      self.fail(msg+"%s in %s failed, %s" % (t.id,t.scenario.filename,t.spec))

class SPFTestCases(unittest.TestCase):

  def testInvalidSPF(self):
    i, s, h = '1.2.3.4','sender@domain','helo'
    q = spf.query(i=i, s=s, h=h, receiver='localhost', strict=False)
    res,code,txt = q.check('v=spf1...')
    self.assertEqual('none',res)
    q = spf.query(i=i, s=s, h=h, receiver='localhost', strict=2)
    res,code,txt = q.check('v=spf1...')
    self.assertEqual('ambiguous',res)


class FakeResolver(object):
  """A callable DNS view for one tenant, recording every lookup it serves."""
  def __init__(self, zone):
    self.zone = zone
    self.queries = []
    self.raise_on = {}
    self.raise_after = {}

  def __call__(self, name, qtype, strict=True, timeout=None):
    name = name.lower()
    key = (name, qtype)
    self.queries.append(key)
    if key in self.raise_on:
      raise self.raise_on[key]
    for i, v in self.zone.get(name, []):
      if i != qtype:
        continue
      if v == 'TIMEOUT':
        raise spf.TempError('DNS timeout')
      if qtype in ('TXT', 'SPF') and isinstance(v, tuple):
        v = tuple(s.encode('utf-8') for s in v)
      yield ((name, i), v)
      if key in self.raise_after:
        raise self.raise_after[key]


# Tenant "blue" and tenant "green" publish the same record for the same
# domain, but their DNS views provide opposite answers for every lookup.
# include returns fail (neutral at the include site), then redirect= is
# exercised; its mx and ptr lookups authorize only the blue client.
TENANT_RECORD = ('v=spf1 include:inc.example.net'
                 ' redirect=shared.example.net exp=exp.shared.example.net')
BLUE_ZONE = {
  'tenant.example.com': [('TXT', (TENANT_RECORD,))],
  'inc.example.net': [('TXT', ('v=spf1 -all',))],
  'shared.example.net': [('TXT', ('v=spf1 mx ptr -all',)),
                         ('MX', (10, 'mx.blue.example.net'))],
  'mx.blue.example.net': [('A', '192.0.2.10')],
  '3.2.0.192.in-addr.arpa': [('PTR', 'ptr.blue.shared.example.net')],
  'ptr.blue.shared.example.net': [('A', '192.0.2.3')],
  'exp.shared.example.net': [('TXT', ('blue explanation',))],
}
GREEN_ZONE = {
  'tenant.example.com': [('TXT', (TENANT_RECORD,))],
  'inc.example.net': [('TXT', ('v=spf1 -all',))],
  'shared.example.net': [('TXT', ('v=spf1 mx ptr -all',)),
                         ('MX', (10, 'mx.green.example.net'))],
  'mx.green.example.net': [('A', '198.51.100.10')],
  '3.2.0.192.in-addr.arpa': [('PTR', 'ptr.green.shared.example.net')],
  'ptr.green.shared.example.net': [('A', '198.51.100.3')],
  'exp.shared.example.net': [('TXT', ('green explanation',))],
}
PATHS = ('tenant.example.com', 'inc.example.net', 'shared.example.net',
  'mx.blue.example.net', '3.2.0.192.in-addr.arpa',
  'ptr.blue.shared.example.net', 'exp.shared.example.net')
GREEN_PATHS = ('tenant.example.com', 'inc.example.net', 'shared.example.net',
  'mx.green.example.net', '3.2.0.192.in-addr.arpa',
  'ptr.green.shared.example.net', 'exp.shared.example.net')


def harnessZone(zone):
  "Convert a FakeResolver zone to the zonedata format used by DNSLookup."
  return dict((name, [(t, v, name) for t, v in rrs])
              for name, rrs in zone.items())


class ResolverIsolationTest(unittest.TestCase):

  def outcome(self, resolver, spftext=None, ip='192.0.2.3'):
    q = spf.query(i=ip, s='user@tenant.example.com',
                  h='mx.tenant.example.com', resolver=resolver, querytime=0)
    return q.check(spftext)

  def testInterleavedViewsStayIsolated(self):
    # Interleave two tenants that share domain names but authorize
    # oppositely.  Every check must be stable and every lookup of one
    # check must stay inside that tenant's view.
    blue = FakeResolver(BLUE_ZONE)
    green = FakeResolver(GREEN_ZONE)
    for n in range(3):
      bres = self.outcome(blue)
      gres = self.outcome(green)
      self.assertEqual(('pass', 250, spf.EXPLANATIONS['pass']), bres)
      self.assertEqual(('fail', 550, spf.EXPLANATIONS['fail']), gres)
    for resolver, zone in ((blue, BLUE_ZONE), (green, GREEN_ZONE)):
      for key in resolver.queries:
        self.assertIn(key[0], zone, key)
    # The recursive check must really touch every mechanism and exp=.
    qtypes = set(qtype for _, qtype in blue.queries)
    self.assertTrue(set(['TXT', 'MX', 'PTR', 'A']) <= qtypes, qtypes)
    for name in PATHS:
      self.assertIn(name, set(n for n, _ in blue.queries), name)
    for name in GREEN_PATHS:
      self.assertIn(name, set(n for n, _ in green.queries), name)
    self.assertIn(('exp.shared.example.net', 'TXT'), blue.queries)
    self.assertIn(('exp.shared.example.net', 'TXT'), green.queries)

  def testExplanationUsesCallerResolver(self):
    record = 'v=spf1 -all exp=exp.shared.example.net'
    blue = FakeResolver(BLUE_ZONE)
    green = FakeResolver(GREEN_ZONE)
    self.assertEqual(('fail', 550, 'blue explanation'),
      self.outcome(blue, record))
    self.assertEqual(('fail', 550, 'green explanation'),
      self.outcome(green, record))

  def testFailedLookupsAreNotTreatedAsNoRecords(self):
    for zone in (BLUE_ZONE, GREEN_ZONE):
      # Exception raised by the resolver call itself.
      r = FakeResolver(zone)
      r.raise_on[('tenant.example.com', 'TXT')] = RuntimeError('view offline')
      self.assertEqual(('temperror', 451,
        'SPF Temporary Error: DNS view offline'), self.outcome(r))
      # Exception raised part way through answer iteration.
      r = FakeResolver(zone)
      r.raise_after[('tenant.example.com', 'TXT')] = \
        RuntimeError('truncated reply')
      self.assertEqual(('temperror', 451,
        'SPF Temporary Error: DNS truncated reply'), self.outcome(r))
      # An empty answer is a real answer: it must not become temperror.
      empty = FakeResolver({})
      self.assertEqual(('none', 250, ''), self.outcome(empty))

  def testCacheAndBudgetArePerRequest(self):
    blue = FakeResolver(BLUE_ZONE)
    green = FakeResolver(GREEN_ZONE)
    q1 = spf.query(i='192.0.2.3', s='user@tenant.example.com',
                   h='mx.tenant.example.com', resolver=blue, querytime=20)
    q2 = spf.query(i='192.0.2.3', s='user@tenant.example.com',
                   h='mx.tenant.example.com', resolver=green, querytime=20)
    self.assertIsNot(q1.cache, q2.cache)
    self.assertEqual(20, q1.querytime)
    self.assertEqual(('pass', 250, spf.EXPLANATIONS['pass']), q1.check())
    blue_cache = dict(q1.cache)
    self.assertEqual(('fail', 550, spf.EXPLANATIONS['fail']), q2.check())
    # The second request did not see or alter the first tenant's answers.
    self.assertEqual(blue_cache, q1.cache)
    self.assertNotEqual(blue_cache, q2.cache)
    # The two budgets were consumed independently, not shared.
    self.assertGreater(q1.querytime, 19)
    self.assertGreater(q2.querytime, 19)
    # A request refused for its own exhausted budget does not affect
    # an interleaved request that still has budget left.
    exhausted = spf.query(i='192.0.2.3', s='user@tenant.example.com',
                          h='mx.tenant.example.com', resolver=blue,
                          querytime=20)
    exhausted.querytime = -1
    self.assertEqual(('temperror', 451,
      'SPF Temporary Error: DNS Error: exceeded max query lookup time'),
      exhausted.check())
    self.assertGreater(q1.querytime, 19)
    self.assertEqual(0, exhausted.lookups)
    # Reusing one query object with a different resolver must start a new
    # request rather than reuse the previous DNS view's answers.
    blue_green = FakeResolver(GREEN_ZONE)
    q1.resolver = blue_green
    q1.querytime = -1
    self.assertEqual(('fail', 550, spf.EXPLANATIONS['fail']), q1.check())
    self.assertGreater(q1.querytime, 19)
    self.assertIn(('shared.example.net', 'TXT'), blue_green.queries)

  def testLegacyGlobalLookupStillWorks(self):
    global zonedata
    saved = zonedata
    try:
      zonedata = harnessZone(BLUE_ZONE)
      q = spf.query(i='192.0.2.3', s='user@tenant.example.com',
                    h='mx.tenant.example.com')
      self.assertEqual(('pass', 250, spf.EXPLANATIONS['pass']), q.check())
    finally:
      zonedata = saved
    self.assertEqual(('pass', spf.EXPLANATIONS['pass']),
      spf.check2(i='192.0.2.3', s='user@tenant.example.com',
                 h='mx.tenant.example.com', resolver=FakeResolver(BLUE_ZONE)))
    self.assertEqual(('pass', 250, spf.EXPLANATIONS['pass']),
      spf.check(i='192.0.2.3', s='user@tenant.example.com',
                h='mx.tenant.example.com', resolver=FakeResolver(BLUE_ZONE)))
    self.assertEqual(('fail', spf.EXPLANATIONS['fail']),
      spf.check2(i='192.0.2.3', s='user@tenant.example.com',
                 h='mx.tenant.example.com', resolver=FakeResolver(GREEN_ZONE)))

def makeSuite(filename):
  suite = unittest.TestSuite()
  for t in loadYAML(filename).values():
    suite.addTest(SPFTestCase(t))
  return suite

def docsuite():
  suite = unittest.defaultTestLoader.loadTestsFromTestCase(SPFTestCases)
  suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(
    ResolverIsolationTest))
  try:
    import authres
  except:
    print("no authres module: skipping doctests")
    return suite
  import doctest
  suite.addTest(doctest.DocTestSuite(spf))
  return suite

def suite(skipdoc=False): 
  suite = docsuite()
  suite.addTest(makeSuite('test.yml'))
  suite.addTest(makeSuite('rfc7208-tests.yml'))
  suite.addTest(makeSuite('rfc4408-tests.yml'))
  return suite

if __name__ == '__main__':
  tc = None
  doctest = False
  for i in sys.argv[1:]:
    if i == '-v':
      verbose += 1
      continue
    if i == '-d':
      doctest = True
      continue
    # a specific test selected by id from YAML files
    if not tc:
      tc = unittest.TestSuite()
      t0 = loadYAML('rfc7208-tests.yml')
      t1 = loadYAML('rfc4408-tests.yml')
      t2 = loadYAML('test.yml')
    if i in t0:
      tc.addTest(SPFTestCase(t0[i]))
    if i in t1:
      tc.addTest(SPFTestCase(t1[i]))
    if i in t2:
      tc.addTest(SPFTestCase(t2[i]))
  if not tc:
    # load zonedata for doctests
    with open('doctest.yml','rb') as fp:
      zonedata = loadZone(next(yaml.safe_load_all(fp)))
    if doctest:
      tc = docsuite()   # doctests only
    else:
      tc = suite()	# all tests, including doctests
  runner = unittest.TextTestRunner()
  res = runner.run(tc)
  for s in warnings:
    print(s)
  if not res.wasSuccessful():
    sys.exit(1)
