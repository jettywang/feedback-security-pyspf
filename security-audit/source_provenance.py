#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import spf

CLIENT = '192.0.2.66'
ZONE = {
  'strict.example.com': [('TXT', ('v=spf1 ip4:198.51.100.7 -all',), 'strict.example.com')],
  'same.example.com':   [('TXT', ('v=spf1 ip4:%s -all' % CLIENT,), 'same.example.com')],
}
def DNSLookup(name, qtype, strict=True, timeout=None, level=0):
    for t, v, n in ZONE.get(name.lower().rstrip('.'), []):
        if t == qtype:
            if t in ('TXT', 'SPF'):
                v = tuple(x.encode() for x in v)
            yield ((n, t), v)
spf.DNSLookup = DNSLookup

def case(label, local, spftxt=None, dom='strict.example.com'):
    q = spf.query(CLIENT, 'user@%s' % dom, 'h.example.com',
                  local=local, receiver='rcpt.example')
    r = q.check(spf=spftxt)
    print('%-28s result=%-9s source=%-6s mechanism=%s'
          % (label, r[0], q.authorization_source(), q.mechanism))
    print('    default hdr :', q.get_header(r[0]))
    print('    annotate    :', q.get_header(r[0], annotate_source=True))

case('local-only pass', 'ip4:%s' % CLIENT)
case('domain-own pass', None, spftxt='v=spf1 ip4:%s -all' % CLIENT)
case('domain -all fail', None, spftxt='v=spf1 -all')
# identical mechanism text present in BOTH domain and local -> must be domain
q = spf.query(CLIENT, 'user@same.example.com', 'h.example.com',
              local='ip4:%s' % CLIENT, receiver='rcpt.example')
r = q.check()
print('%-28s result=%-9s source=%-6s (position, not text, decides)'
      % ('identical text, domain wins', r[0], q.authorization_source()))
# local softfail qualifier
case('local ~ qualifier', '~ip4:%s' % CLIENT,
     spftxt='v=spf1 ip4:198.51.100.7 -all')
