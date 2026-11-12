#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import spf

CLIENT='192.0.2.66'
ZONE = {
  'mxhost.example.com': [('A', ('198.51.100.9',), 'mxhost.example.com')],
  'dom.example.com':    [('TXT', ('v=spf1 mx -all',), 'dom.example.com'),
                         ('MX', (0,'mxhost.example.com'), 'dom.example.com')],
  'void.example.com':   [('TXT', ('v=spf1 mx -all',), 'void.example.com')],
}
def DNSLookup(name,qtype,strict=True,timeout=None,level=0):
    name=name.lower().rstrip('.')
    for t,v,n in ZONE.get(name,[]):
        if t==qtype:
            if t in ('TXT','SPF'): v=tuple(x.encode() for x in v)
            yield ((n,t),v)
spf.DNSLookup=DNSLookup

# monkeypatch at module level BEFORE check() binds
calls=[]
_orig=spf._insert_libspf_local_policy_indexed
def counting(spftxt, local=None):
    calls.append(spftxt); return _orig(spftxt,local)
spf._insert_libspf_local_policy_indexed=counting

def runq(local=None, spftxt=None, dom='dom.example.com'):
    calls.clear()
    x=spf.query(CLIENT,'user@%s'%dom,'h.example.com',local=local)
    r=x.check(spf=spftxt)
    return r[0], x.mechanism, x.lookups, len(calls)

print('--- local policy qualifier semantics (record v=spf1 mx -all) ---')
for loc in ['ip4:%s'%CLIENT, '~ip4:%s'%CLIENT, '?ip4:%s'%CLIENT, '-ip4:%s'%CLIENT,
            '~all', '-all', '?all', '+all']:
    print('local=%-16s -> %s' % (loc, runq(loc)[:2]))

print('\n--- DNS lookup budget: local mx adds a lookup beyond domain record ---')
print('no local            :', runq(None))
print("local 'mx'          :", runq("mx"))
print("local 'ip4' (no DNS):", runq("ip4:%s"%CLIENT))

print('\n--- local with DNS-using mech on domain lacking MX (void accounting) ---')
x=spf.query(CLIENT,'user@void.example.com','h.example.com',local='mx')
try:
    print('local mx w/ no MX    :', x.check()[0], 'void_lookups=',x.void_lookups)
except Exception as e:
    print('raised', type(e).__name__, e)

print('\n--- insertion only when BOTH spf text and local present ---')
print('explicit spf + local:', runq("ip4:%s"%CLIENT, spftxt='v=spf1 mx -all'))
print('DNS record + local  :', runq("ip4:%s"%CLIENT))
x=spf.query(CLIENT,'user@none.example.com','h.example.com',local='ip4:%s'%CLIENT)
print('no SPF domain +local:', x.check()[0], '(insert calls=%d)'%len(calls))

print('\n--- exp= placement dead-code confirmation (insert output only) ---')
print(spf.insert_libspf_local_policy('v=spf1 -all exp=_exp.example.com','ip4:%s'%CLIENT))
print(spf.insert_libspf_local_policy('v=spf1 exp=_exp.example.com -all','ip4:%s'%CLIENT))

print('\n--- duplicate insert if caller re-checks a spliced record ---')
once=spf.insert_libspf_local_policy('v=spf1 mx -all','ip4:%s'%CLIENT)
print('1st:', once)
print('2nd:', spf.insert_libspf_local_policy(once,'ip4:%s'%CLIENT))
