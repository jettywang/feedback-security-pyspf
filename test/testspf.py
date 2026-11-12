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

def makeSuite(filename):
  suite = unittest.TestSuite()
  for t in loadYAML(filename).values():
    suite.addTest(SPFTestCase(t))
  return suite


class TraceZone(object):
  """Minimal zone for structured trace tests, restored on exit."""

  def __init__(self, data):
    self.data = data
    self.zone = {}
    for name, records in data.items():
      entries = []
      for t, v in records:
        if t == 'TIMEOUT' or v == 'TIMEOUT':
          entries.append('TIMEOUT')
          break
        if t in ('TXT', 'SPF'):
          v = tuple(v)
        entries.append((t, v, name))
      self.zone[name.lower()] = entries

  def __enter__(self):
    global zonedata
    self.saved = zonedata
    zonedata = self.zone
    return self

  def __exit__(self, *exc):
    global zonedata
    zonedata = self.saved


def _query(ip, sender, strict=True, trace=True, **kw):
  return spf.query(i=ip, s=sender, h='helo.example', strict=strict,
                   trace=trace, **kw)


class SPFTraceTests(unittest.TestCase):
  """Structured evaluation traces must explain the final result."""

  def _entries(self, q, type):
    return [e for e in q.trace.entries if e['type'] == type]

  def _queries(self, q):
    return [(x['name'], x['qtype']) for x in q.trace.queries]

  def testNestedIncludePassReconstructsResult(self):
    zone = {
      'outer.example.com': [('TXT', ['v=spf1 include:mid.example.com '
                                      'include:never.example.com -all'])],
      'mid.example.com': [('TXT', ['v=spf1 include:deep.example.com -all'])],
      'deep.example.com': [('TXT', ['v=spf1 ip4:192.0.2.3 -all'])],
    }
    with TraceZone(zone):
      q = _query('192.0.2.3', 'user@outer.example.com')
      res, code, exp = q.check()
    self.assertEqual('pass', res)
    self.assertEqual('pass', q.trace.result)
    records = self._entries(q, 'record')
    # Outer record -> include:mid -> include:deep, each with its own domain.
    self.assertEqual(['outer.example.com', 'mid.example.com',
                      'deep.example.com'],
                     [r['domain'] for r in records])
    self.assertEqual(['top', 'include', 'include'], [r['via'] for r in records])
    # Final result names the matching mechanism.
    result = self._entries(q, 'result')[0]
    self.assertEqual('include:mid.example.com', result['mechanism'])
    # Include transformation is distinct from a redirect delegation.
    outer_inc = [e for e in self._entries(q, 'mechanism')
                 if e.get('source') == 'include:mid.example.com'][0]
    self.assertEqual('include', outer_inc['transform'])
    self.assertEqual('pass', outer_inc['included_result'])
    self.assertEqual('pass', outer_inc['normalized_result'])
    self.assertIs(outer_inc['matched'], True)
    # Domains visited: exactly the three records, not the skipped include.
    self.assertEqual([('outer.example.com', 'TXT'), ('mid.example.com', 'TXT'),
                      ('deep.example.com', 'TXT')], self._queries(q))
    self.assertNotIn(('never.example.com', 'TXT'), self._queries(q))
    # Once the inner record matched, the outer -all is never evaluated.
    for e in self._entries(q, 'mechanism'):
      if e.get('domain') == 'outer.example.com' and e.get('source') == '-all':
        self.assertEqual('skipped', e['stage'])

  def testRedirectFailureAttributesDelegation(self):
    zone = {
      'redirect.example.com': [('TXT', ['v=spf1 redirect=nx.example.com'])],
    }
    with TraceZone(zone):
      q = _query('192.0.2.3', 'user@redirect.example.com')
      res, code, exp = q.check()
    self.assertEqual('permerror', res)
    self.assertIn('redirect domain has no SPF record', exp)
    errors = self._entries(q, 'error')
    self.assertEqual(1, len(errors))
    err = errors[0]
    self.assertEqual('PermError', err['error'])
    self.assertEqual('nx.example.com', err['domain'])
    self.assertEqual('permanent', err['phase'])
    self.assertIs(err['fatal'], True)
    # The redirect modifier is a whole-record delegation, not an include.
    redirects = [e for e in self._entries(q, 'modifier')
                 if e.get('modifier') == 'redirect']
    self.assertEqual(1, len(redirects))
    self.assertEqual('nx.example.com', redirects[0]['domain'])
    self.assertIs(redirects[0]['delegation'], True)
    self.assertEqual('error', redirects[0]['stage'])
    result = self._entries(q, 'result')[0]
    self.assertEqual(err['id'], result['error_source']['id'])
    self.assertEqual('nx.example.com', result['error_source']['domain'])
    self.assertEqual([('redirect.example.com', 'TXT'),
                      ('nx.example.com', 'TXT')], self._queries(q))

  def testShortCircuitSkipsExpensiveBranch(self):
    zone = {
      'skip.example.com': [('TXT', ['v=spf1 ip4:192.0.2.3 '
                                     'exists:expensive.example.com -all'])],
      'expensive.example.com': [('A', '192.0.2.9')],
    }
    with TraceZone(zone):
      q = _query('192.0.2.3', 'user@skip.example.com')
      res, code, exp = q.check()
    self.assertEqual('pass', res)
    self.assertEqual('ip4:192.0.2.3', self._entries(q, 'result')[0]['mechanism'])
    skipped = [e for e in self._entries(q, 'mechanism')
               if e.get('source') == 'exists:expensive.example.com']
    self.assertEqual(1, len(skipped))
    self.assertEqual('skipped', skipped[0]['stage'])
    self.assertNotIn(('expensive.example.com', 'A'), self._queries(q))
    self.assertEqual([('skip.example.com', 'TXT')], self._queries(q))

  def testTemporaryErrorPointsAtSource(self):
    zone = {
      'temperror.example.com': [('TXT', ['v=spf1 include:slow.example.com '
                                          '-all'])],
      'slow.example.com': [('TIMEOUT', None)],
    }
    with TraceZone(zone):
      q = _query('192.0.2.3', 'user@temperror.example.com')
      res, code, exp = q.check()
    self.assertEqual('temperror', res)
    err = self._entries(q, 'error')[0]
    self.assertEqual('TempError', err['error'])
    self.assertEqual('dns', err['phase'])
    self.assertEqual('slow.example.com', err['domain'])
    self.assertEqual('include:slow.example.com', err['mechanism'])
    # Attribution stays on the include frame, not the top-level record.
    self.assertEqual([{'id': 0, 'domain': 'temperror.example.com',
                       'via': 'top'}], err['frame_path'])
    self.assertEqual(err['id'], self._entries(q, 'result')[0]
                     ['error_source']['id'])

  def testPermanentSyntaxErrorPointsAtInnerRecord(self):
    zone = {
      'bad.example.com': [('TXT', ['v=spf1 include:badin.example.com -all'])],
      'badin.example.com': [('TXT', ['v=spf1 ip4:192.0.0.n ?all'])],
    }
    with TraceZone(zone):
      q = _query('192.0.2.3', 'user@bad.example.com')
      res, code, exp = q.check()
    self.assertEqual('permerror', res)
    self.assertIn('Invalid IP4 address', exp)
    err = self._entries(q, 'error')[0]
    self.assertEqual('badin.example.com', err['domain'])
    self.assertEqual('ip4:192.0.0.n', err['mechanism'])
    self.assertEqual(['bad.example.com', 'badin.example.com'],
                     [p['domain'] for p in err['frame_path']])
    self.assertEqual('include', err['frame_path'][-1]['via'])

  def testRedirectLoopTraceTerminates(self):
    zone = {
      'loop.example.com': [('TXT', ['v=spf1 redirect=loop-b.example.com'])],
      'loop-b.example.com': [('TXT', ['v=spf1 redirect=loop.example.com'])],
    }
    with TraceZone(zone):
      q = _query('192.0.2.3', 'user@loop.example.com')
      res, code, exp = q.check()
    self.assertEqual('permerror', res)
    err = self._entries(q, 'error')[0]
    self.assertEqual('Too many DNS lookups', err['message'])
    self.assertEqual('loop.example.com', err['domain'])
    self.assertIs(err['fatal'], True)

  def testTraceOffByDefaultAndNoSenderSecrets(self):
    q = _query('192.0.2.3', 'secret@example.com', trace=False)
    res, code, exp = q.check('v=spf1 ip4:192.0.2.3 -all')
    self.assertEqual('pass', res)
    self.assertIsNone(q.trace)
    q2 = _query('192.0.2.3', 'secret@example.com')
    res, code, exp = q2.check('v=spf1 ip4:192.0.2.3 -all')
    self.assertEqual('pass', res)
    self.assertIsNotNone(q2.trace)
    self.assertIsNone(q2.trace.sender)
    self.assertIsNone(q2.trace.local_part)
    self.assertIsNone(q2.trace.helo)
    self.assertEqual('example.com', q2.trace.sender_domain)
    # Opt in explicitly to sender details.
    q3 = _query('192.0.2.3', 'secret@example.com', trace_sender=True)
    q3.check('v=spf1 ip4:192.0.2.3 -all')
    self.assertEqual('secret@example.com', q3.trace.sender)
    self.assertEqual('secret', q3.trace.local_part)

  def testTraceExportedStructurally(self):
    q = _query('192.0.2.3', 'user@example.com')
    q.check('v=spf1 ip4:192.0.2.3 -all')
    data = q.trace.to_dict()
    self.assertEqual('pass', data['result'])
    self.assertEqual('ip4:192.0.2.3', data['entries'][-1]['mechanism'])
    import json
    json.dumps(data)  # must be strictly JSON serializable
    self.assertEqual(5, len(q.trace))
    self.assertEqual('pass', q.trace['result'])

  def testCheck2ReturnsTrace(self):
    def fake(name, qtype, strict=True, timeout=None):
      return [((name, qtype), (b'v=spf1 ip4:192.0.2.3 -all',))]
    saved = spf.DNSLookup
    spf.DNSLookup = fake
    try:
      res, exp, trace = spf.check2(i='192.0.2.3', s='user@example.com',
                                   h='helo.example', trace=True)
    finally:
      spf.DNSLookup = saved
    self.assertEqual('pass', res)
    self.assertIsInstance(trace, spf.EvaluationTrace)
    self.assertEqual('pass', trace.result)
    self.assertEqual('example.com', trace.sender_domain)

def docsuite():
  suite = unittest.defaultTestLoader.loadTestsFromTestCase(SPFTestCases)
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
  suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(
      SPFTraceTests))
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
