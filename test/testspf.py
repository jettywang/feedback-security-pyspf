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

class DNSAdditionalCacheTests(unittest.TestCase):
  """Regression tests for reuse of DNS additional data.

  A resolver response can mix answer records with additional records for
  unrelated owners.  Only records attributable to the queried name (or,
  for MX, to an exchange in the queried zone) may enter the session cache.
  """

  def setUp(self):
    self.save_lookup = spf.DNSLookup
    self.zone = {}
    self.calls = []

  def tearDown(self):
    spf.DNSLookup = self.save_lookup

  def add(self, name, qtype, *records):
    self.zone[(name.lower(), qtype)] = list(records)

  def install(self):
    zone, calls = self.zone, self.calls
    def fake(name, qtype, strict=True, timeout=None):
      calls.append((name.lower(), qtype))
      return zone.get((name.lower(), qtype), [])
    spf.DNSLookup = fake

  def check(self, ip, sender, strict=True):
    self.install()
    q = spf.query(i=ip, s=sender, h='mail.example.com', strict=strict)
    return q, q.check()

  def test_cname_additional_cannot_reauthorize(self):
    # The attacker's include response carries a CNAME for an unrelated
    # trusted domain.  If that CNAME is cached, a:trusted.example follows
    # it to attacker-pool.example and wrongly passes.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 include:attacker.example a:trusted.example -all',)))
    self.add('attacker.example', 'TXT',
        (('attacker.example', 'TXT'), (b'v=spf1 ip4:203.0.113.1 -all',)),
        (('trusted.example', 'CNAME'), 'attacker-pool.example'))
    self.add('attacker-pool.example', 'A',
        (('attacker-pool.example', 'A'), '192.0.2.66'))
    self.add('trusted.example', 'A',
        (('trusted.example', 'A'), '198.51.100.10'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertNotIn(('trusted.example', 'CNAME'), q.cache)
    self.assertEqual(['198.51.100.10'], q.cache[('trusted.example', 'A')])

  def test_txt_additional_cannot_reauthorize(self):
    # Minimal fail -> pass sample: the attacker's own SPF TXT response
    # carries an SPF TXT for an unrelated trusted domain.  Reusing that
    # record as the answer to include:trusted.example authorizes the
    # attacker.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'),
         (b'v=spf1 include:attacker.example include:trusted.example -all',)))
    self.add('attacker.example', 'TXT',
        (('attacker.example', 'TXT'), (b'v=spf1 ip4:203.0.113.1 -all',)),
        (('trusted.example', 'TXT'), (b'v=spf1 ip4:192.0.2.66 -all',)))
    self.add('trusted.example', 'TXT',
        (('trusted.example', 'TXT'), (b'v=spf1 ip4:198.51.100.10 -all',)))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertEqual([(b'v=spf1 ip4:198.51.100.10 -all',)],
                     q.cache[('trusted.example', 'TXT')])

  def test_mx_rr_additional_cannot_reauthorize(self):
    # A TXT response that carries an MX for another domain must not seed
    # a later mx: query for that domain.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 include:attacker.example mx:trusted.example -all',)))
    self.add('attacker.example', 'TXT',
        (('attacker.example', 'TXT'), (b'v=spf1 ip4:203.0.113.1 -all',)),
        (('trusted.example', 'MX'), (10, 'mail.attacker.example')))
    self.add('trusted.example', 'MX',
        (('trusted.example', 'MX'), (10, 'mail.trusted.example')))
    self.add('mail.attacker.example', 'A',
        (('mail.attacker.example', 'A'), '192.0.2.66'))
    self.add('mail.trusted.example', 'A',
        (('mail.trusted.example', 'A'), '198.51.100.10'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertEqual([(10, 'mail.trusted.example')],
                     q.cache[('trusted.example', 'MX')])

  def test_ptr_additional_cannot_reauthorize(self):
    # The PTR answer is controlled by the client; it must not smuggle a
    # CNAME for a domain the client does not control.  If that alias were
    # cached, the later a:trusted.example lookup would follow it to the
    # attacker's pool and wrongly pass.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 ptr:trusted.example a:trusted.example -all',)))
    self.add('66.2.0.192.in-addr.arpa', 'PTR',
        (('66.2.0.192.in-addr.arpa', 'PTR'), 'client.attacker.example'),
        (('trusted.example', 'CNAME'), 'attacker-pool.example'))
    self.add('client.attacker.example', 'A',
        (('client.attacker.example', 'A'), '192.0.2.66'))
    self.add('attacker-pool.example', 'A',
        (('attacker-pool.example', 'A'), '192.0.2.66'))
    self.add('trusted.example', 'A',
        (('trusted.example', 'A'), '198.51.100.10'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertNotIn(('trusted.example', 'CNAME'), q.cache)
    self.assertEqual(['198.51.100.10'], q.cache[('trusted.example', 'A')])

  def test_mx_exchange_additional_outside_bailiwick(self):
    # The attacker's own MX response names an exchange in another zone
    # and supplies its address.  That address is not attributable to the
    # attacker's authority, so a later a:trusted.example must look it up.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 mx:attacker.example a:trusted.example -all',)))
    self.add('attacker.example', 'MX',
        (('attacker.example', 'MX'), (10, 'trusted.example')),
        (('trusted.example', 'A'), '192.0.2.66'))
    self.add('trusted.example', 'A',
        (('trusted.example', 'A'), '198.51.100.10'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertEqual(['198.51.100.10'], q.cache[('trusted.example', 'A')])

  def test_same_owner_other_type_is_keyed_and_not_reused(self):
    # A TXT response for attacker.example also carries an A for the same
    # owner.  Record types have separate cache keys and the A is not
    # treated as an answer to a later A query for that name.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 include:attacker.example a:attacker.example -all',)))
    self.add('attacker.example', 'TXT',
        (('attacker.example', 'TXT'), (b'v=spf1 ip4:203.0.113.1 -all',)),
        (('attacker.example', 'A'), '192.0.2.66'))
    self.add('attacker.example', 'A',
        (('attacker.example', 'A'), '198.51.100.10'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertIn(('attacker.example', 'TXT'), q.cache)
    self.assertEqual(['198.51.100.10'], q.cache[('attacker.example', 'A')])
    self.assertIn(('attacker.example', 'A'), self.calls)

  def test_case_normalized_cache_keys(self):
    # Mixed-case owners and CNAME targets must normalize to one key so a
    # second query cannot observe a differently-cased poisoned entry.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 include:attacker.example a:trusted.example -all',)))
    self.add('attacker.example', 'TXT',
        (('attacker.example', 'TXT'), (b'v=spf1 ip4:203.0.113.1 -all',)),
        (('TRUSTED.Example.', 'CNAME'), 'ATTACKER-POOL.Example.'))
    self.add('attacker-pool.example', 'A',
        (('attacker-pool.example', 'A'), '192.0.2.66'))
    self.add('trusted.example', 'A',
        (('trusted.example', 'A'), '198.51.100.10'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('fail', res)
    self.assertFalse([k for k in q.cache if k[0] != k[0].lower()])
    self.assertEqual(['198.51.100.10'], q.cache[('trusted.example', 'A')])

  def test_cname_chain_still_followed(self):
    # A legitimate CNAME chain for the queried name still resolves.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 a:alias.example -all',)))
    self.add('alias.example', 'A',
        (('ALIAS.Example.', 'CNAME'), 'real.example.'))
    self.add('real.example', 'A',
        (('REAL.Example.', 'A'), '192.0.2.66'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('pass', res)
    self.assertEqual(['real.example'], q.cache[('alias.example', 'CNAME')])

  def test_mx_exchange_additional_reused(self):
    # Legitimate: the MX answer and an A for its exchange share one
    # response and the address is in the queried zone.  No second query.
    self.add('victim.example', 'TXT',
        (('victim.example', 'TXT'), (b'v=spf1 mx -all',)))
    self.add('victim.example', 'MX',
        (('victim.example', 'MX'), (10, 'mail.victim.example')),
        (('mail.victim.example', 'A'), '192.0.2.66'))
    q, (res, code, exp) = self.check('192.0.2.66', 'u@victim.example')
    self.assertEqual('pass', res)
    self.assertEqual([('victim.example', 'TXT'), ('victim.example', 'MX')], self.calls)
    self.assertEqual(['192.0.2.66'], q.cache[('mail.victim.example', 'A')])



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

def docsuite():
  suite = unittest.defaultTestLoader.loadTestsFromTestCase(SPFTestCases)
  suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(
      DNSAdditionalCacheTests))
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
