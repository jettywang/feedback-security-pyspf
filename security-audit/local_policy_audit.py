#!/usr/bin/env python3
# Offline, reproducible audit of pyspf "local policy" (libspf_local) semantics.
# No network: spf.DNSLookup is replaced with an in-memory zone.
import sys, os, copy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import spf

CLIENT = '192.0.2.66'           # IP that ONLY the local policy authorizes
SENDER = 'user@example.com'
HELO   = 'mail.example.com'

# ---------------------------------------------------------------- zone data
ZONE = {
    # plain domain, strict -all
    'strict.example.com':        [('TXT', ('v=spf1 ip4:198.51.100.7 -all',), 'strict.example.com')],
    # explicit + qualifier on last mech, then -all
    'plus.example.com':          [('TXT', ('v=spf1 mx +ip4:198.51.100.7 -all',), 'plus.example.com'),
                                  ('MX', (0, 'mx.plus.example.com'), 'plus.example.com'),
                                  ('A', ('198.51.100.9',), 'mx.plus.example.com')],
    # softfail / neutral qualifier matrix ending in ~all
    'qual.example.com':          [('TXT', ('v=spf1 ~ip4:198.51.100.7 ?ip4:198.51.100.8 ~all',), 'qual.example.com')],
    # include chain: top has include then -all
    'incl.example.com':          [('TXT', ('v=spf1 include:sub.example.com -all',), 'incl.example.com')],
    'sub.example.com':           [('TXT', ('v=spf1 ip4:198.51.100.7 -all',), 'sub.example.com')],
    # include that returns none (no SPF)
    'inclnone.example.com':      [('TXT', ('v=spf1 include:nosub.example.com -all',), 'inclnone.example.com')],
    # redirect only
    'redir.example.com':         [('TXT', ('v=spf1 redirect=target.example.com',), 'redir.example.com')],
    'target.example.com':        [('TXT', ('v=spf1 ip4:198.51.100.7 -all',), 'target.example.com')],
    # redirect target that itself includes
    'redir2.example.com':        [('TXT', ('v=spf1 redirect=target2.example.com',), 'redir2.example.com')],
    'target2.example.com':       [('TXT', ('v=spf1 include:sub.example.com -all',), 'target2.example.com')],
    # no SPF at all
    'none.example.com':          [('A', ('198.51.100.7',), 'none.example.com')],
    # redirect to a domain with no SPF (permerror case)
    'redirbad.example.com':      [('TXT', ('v=spf1 redirect=nosub.example.com',), 'redirbad.example.com')],
    # exp= modifier before -all (placement edge case)
    'exp.example.com':           [('TXT', ('v=spf1 -all exp=_exp.example.com',), 'exp.example.com')],
    '_exp.example.com':          [('TXT', ('why blocked',), '_exp.example.com')],
    # default-qualified mech then explicit +all
    'plusall.example.com':       [('TXT', ('v=spf1 mx +all',), 'plusall.example.com'),
                                  ('MX', (0, 'mx.plusall.example.com'), 'plusall.example.com'),
                                  ('A', ('198.51.100.9',), 'mx.plusall.example.com')],
    # all-fail record with several mechanisms
    'allfail.example.com':       [('TXT', ('v=spf1 -ip4:198.51.100.7 -all',), 'allfail.example.com')],
}

def DNSLookup(name, qtype, strict=True, timeout=None, level=0):
    name = name.lower().rstrip('.')
    if name not in ZONE:
        return
    for t, v, n in ZONE[name]:
        if t == qtype:
            if t in ('TXT', 'SPF'):
                v = tuple(x.encode() for x in v)
            yield ((n, t), v)

spf.DNSLookup = DNSLookup

# count how many times the local-policy splicing function is actually invoked
_orig_insert = spf._insert_libspf_local_policy_indexed
insert_calls = []
def counting_insert(spftxt, local=None):
    insert_calls.append((spftxt, local))
    return _orig_insert(spftxt, local)
spf._insert_libspf_local_policy_indexed = counting_insert

LOCAL = 'ip4:%s' % CLIENT

def run(domain, local=None):
    insert_calls.clear()
    sender = 'user@%s' % domain
    q = spf.query(i=CLIENT, s=sender, h=HELO, local=local, receiver='rcpt.example')
    res = q.check()
    return {
        'result': res[0], 'code': res[1], 'expl': res[2],
        'mechanism': getattr(q, 'mechanism', None),
        'lookups': q.lookups,
        'inserts': len(insert_calls),
        'inserted_records': [c[0] for c in insert_calls],
        'result_source': getattr(q, 'result_source', None),
    }

print('=' * 78)
print('PART A  insert_libspf_local_policy() string transformation matrix')
print('=' * 78)
spf._insert_libspf_local_policy_indexed = _orig_insert
cases = [
    ('v=spf1 -all', 'mx'),
    ('v=spf1', 'a mx ptr'),
    ('v=spf1 mx -all', 'a ptr'),
    ('v=spf1 mx -include:foo.co +all', 'a ptr'),
    ('v=spf1 mx ?include:foo.co +all', 'a ptr'),
    ('v=spf1 ip4:1.2.3.4 -a:example.net -all', 'ip4:192.0.2.3 a:example.org'),
    ('v=spf1 redirect=target.example.com', 'ip4:192.0.2.66'),
    ('v=spf1 -all exp=_exp.example.com', 'ip4:192.0.2.66'),
    ('v=spf1 -ip4:1.2.3.4 -all', 'ip4:192.0.2.66'),
    ('v=spf1 +all', 'ip4:192.0.2.66'),
]
for rec, loc in cases:
    print('%-46s + local %-22s -> %s' % (rec, loc, spf.insert_libspf_local_policy(rec, loc)))

print()
print('=' * 78)
print('PART B  Full evaluation: client IP %s is authorized ONLY by local policy' % CLIENT)
print('=' * 78)
spf._insert_libspf_local_policy_indexed = counting_insert
domains = ['strict.example.com','plus.example.com','qual.example.com',
           'incl.example.com','inclnone.example.com','redir.example.com',
           'redir2.example.com','redirbad.example.com','none.example.com',
           'exp.example.com','plusall.example.com','allfail.example.com']
hdr = '%-24s | %-9s %-9s | %-26s %-26s | %s' % (
    'domain', 'no-local', 'w/local', 'mech(no-local)', 'mech(w/local)', 'inserts / lookups')
print(hdr); print('-' * len(hdr))
for d in domains:
    a = run(d); b = run(d, LOCAL)
    print('%-24s | %-9s %-9s | %-26s %-26s | %d / %d->%d  src=%s' % (
        d, a['result'], b['result'], str(a['mechanism']), str(b['mechanism']),
        b['inserts'], a['lookups'], b['lookups'], b['result_source']))

print()
print('=' * 78)
print('PART C  Recursion: is local policy re-inserted on included/redirected doms?')
print('=' * 78)
for d in ['incl.example.com','redir.example.com','redir2.example.com']:
    r = run(d, LOCAL)
    print('%-24s inserts=%d (1 = top-level only); records passed to insert: %s'
          % (d, r['inserts'], r['inserted_records']))
spf.insert_libspf_local_policy = _orig_insert

print()
print('=' * 78)
print('PART D  Header wording when local policy creates the pass')
print('=' * 78)
q = spf.query(i=CLIENT, s='user@strict.example.com', h=HELO, local=LOCAL,
              receiver='rcpt.example')
res = q.check()
print('check()        ->', res)
print('mechanism attr ->', q.mechanism)
print('Received-SPF   ->', q.get_header(res[0]))
