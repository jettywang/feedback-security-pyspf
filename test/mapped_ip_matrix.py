# Local matrix: pyspf handling of IPv4-mapped IPv6 addresses.
# Traces set_ip state, DNS query types, cidr matching, object-reuse leakage,
# and client-ip identity in generated result headers. No network access:
# spf.DNSLookup is replaced with a fake resolver backed by ZONE.
import ipaddress
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import spf

S = 'strong-bad@email.example.com'
H = 'mx.example.org'

# ---- fake DNS ----------------------------------------------------------
QUERIES = []
ZONE = {}
def fake_dns(name, qtype, strict=True, timeout=30):
    QUERIES.append((name, qtype))
    for (n, t), vals in ZONE.items():
        if n == name.lower() and t == qtype:
            for v in vals:
                yield ((n, t), v)
spf.DNSLookup = fake_dns

def ptrname(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return '.'.join(reversed(str(a).split('.'))) + '.in-addr.arpa'
    return '.'.join(reversed(a.exploded.replace(':', ''))) + '.ip6.arpa'

ZONE[(ptrname('192.0.2.3'), 'PTR')]   = ['mx.example.org']
ZONE[(ptrname('2001:db8::1'), 'PTR')] = ['mx6.example.org']
ZONE[('mx.example.org', 'A')]         = ['192.0.2.3']
ZONE[('mx6.example.org', 'AAAA')]     = ['2001:db8::1']

def qtypes():
    return sorted(set(t for _, t in QUERIES))

def run(ip, spf_rec, **kw):
    """fresh object evaluation; returns (result, qtypes, ptrnames, client-ip)"""
    del QUERIES[:]
    q = spf.query(i=ip, s=S, h=H, strict=False, **kw)
    try:
        res = q.check(spf=spf_rec)[0]
    except Exception as x:
        res = 'EXC:%s' % type(x).__name__
    hdr = q.get_header(res if res in ('pass','fail','neutral','softfail',
                                      'none','permerror','temperror') else 'none')
    cip = [p for p in hdr.split() if p.startswith('client-ip=')]
    ptrs = sorted(set(n for n, t in QUERIES if t == 'PTR'))
    return res, qtypes(), ptrs, (cip[0] if cip else '-')

# ---- S1: set_ip state --------------------------------------------------
print('== S1: set_ip state (fresh objects) ==')
print('%-28s %-8s %-15s %-4s %-8s %-4s %s' % (
    'input', 'family', 'c', 'A', 'v', 'max', 'ipaddress x-check'))
for ip in ['192.0.2.3', '2001:db8::1',
           '::ffff:192.0.2.3', '::ffff:c000:0203', '0:0:0:0:0:ffff:192.0.2.3',
           '::FFFF:C000:0203', '::192.0.2.3', '::ffff:0:192.0.2.3',
           '::ffff:999.1.1.1', 'list', 'list6']:
    try:
        q = spf.query(i=ip, s=S, h=H, strict=False)
        fam = 'ip6' if q.v == 'ip6' else 'ip4'
        c = getattr(q, 'c', '<unset>'); i = getattr(q, 'i', '<unset>')
        a = ipaddress.ip_address(ip) if ip not in ('list', 'list6') else None
        if a is None:
            xc = 'list-mode'
        else:
            m = a.ipv4_mapped if a.version == 6 else None
            xc = 'v%d mapped=%s' % (a.version, m)
        print('%-28s %-8s %-15s %-4s %-8s %-4s %s  i=%s' % (
            ip, fam, c, q.A, q.v, q.cidrmax, xc, i))
    except Exception as x:
        print('%-28s EXC %s: %s' % (ip, type(x).__name__, x))

# ---- S2: evaluation matrix (fresh object per cell) ---------------------
print()
print('== S2: SPF result / DNS qtypes / client-ip (fresh objects) ==')
IPS = ['192.0.2.3', '::ffff:192.0.2.3', '::ffff:c000:0203',
       '2001:db8::1', '::192.0.2.3']
SPFS = [
    'v=spf1 ip4:192.0.2.0/31 -all',
    'v=spf1 ip4:192.0.2.3/32 -all',
    'v=spf1 ip6:::ffff:192.0.2.3 -all',
    'v=spf1 ip6:2001:db8::/127 -all',
    'v=spf1 ip6:2001:db8::1/128 -all',
    'v=spf1 a:mx.example.org -all',
    'v=spf1 a:mx6.example.org -all',
    'v=spf1 ptr:example.org -all',
    'v=spf1 a:mx.example.org/24//64 -all',
    'v=spf1 ip4:192.0.2.3/33 -all',
    'v=spf1 ip6:2001:db8::1/129 -all',
    'v=spf1 ip4:999.1.1.1 -all',
]
for spf_rec in SPFS:
    print('-- %s' % spf_rec)
    for ip in IPS:
        res, qt, ptrs, cip = run(ip, spf_rec)
        extra = ''
        if ptrs: extra = ' ptr=%s' % (','.join(p.split('.arpa')[0][-12:] + '.arpa' for p in ptrs))
        print('   %-20s -> %-9s q=%-12s %s %s' % (ip, res, '+'.join(qt), cip, extra))

# ---- S3: same-object reuse --------------------------------------------
print()
print('== S3: set_ip switching on one query object vs fresh objects ==')
SEQ = ['192.0.2.3', '2001:db8::1', '::ffff:192.0.2.3', '192.0.2.3']
SPF_PTR = 'v=spf1 ptr:example.org -all'
SPF_A4  = 'v=spf1 ip4:192.0.2.0/31 -all'
SPF_A6  = 'v=spf1 ip6:2001:db8::/127 -all'

q = spf.query(i=SEQ[0], s=S, h=H, strict=False)
print('%-16s %-26s %-26s %-22s %s' % ('set_ip', 'p(lazy PTR) switched', 'p fresh', 'result switched/fresh', 'c/i/A/v ok'))
for ip in SEQ:
    q.set_ip(ip)
    del QUERIES[:]
    p_sw = q.getp()                      # lazy PTR macro on reused object
    fq = spf.query(i=ip, s=S, h=H, strict=False)
    p_fr = fq.getp()
    r_sw = q.check(spf=SPF_PTR)[0]
    r_fr = fq.check(spf=SPF_PTR)[0]
    state_ok = (q.c == fq.c and q.i == fq.i and q.A == fq.A
                and q.v == fq.v and q.cidrmax == fq.cidrmax
                and q.ipaddr == fq.ipaddr)
    print('%-16s %-26s %-26s %-22s %s' % (ip, p_sw, p_fr,
                                          '%s/%s' % (r_sw, r_fr), state_ok))

print()
print('-- result equivalence after switching (ptr/ip4/ip6 records) --')
for ip in SEQ:
    q.set_ip(ip)
    fq = spf.query(i=ip, s=S, h=H, strict=False)
    row = []
    for rec in (SPF_PTR, SPF_A4, SPF_A6):
        row.append('%s/%s' % (q.check(spf=rec)[0], fq.check(spf=rec)[0]))
    hdr_sw = q.get_header('pass')
    hdr_fr = fq.get_header('pass')
    cip = lambda h: [p for p in h.split() if p.startswith('client-ip=')][0]
    print('%-16s ptr=%s ip4=%s ip6=%s client-ip %s/%s' % (
        ip, row[0], row[1], row[2], cip(hdr_sw), cip(hdr_fr)))

print()
print('-- list/list6 mode after a real IP (stale state check) --')
q2 = spf.query(i='192.0.2.3', s=S, h=H, strict=False)
q2.set_ip('list')
fq2 = spf.query(i='list', s=S, h=H, strict=False)
for attr in ('ipaddr', 'c', 'i', 'A', 'v', 'cidrmax', 'iplist'):
    sw = getattr(q2, attr, '<unset>'); fr = getattr(fq2, attr, '<unset>')
    flag = '' if sw == fr else '   <-- MISMATCH'
    print('list  %-8s switched=%-18r fresh=%-18r%s' % (attr, sw, fr, flag))
q2.set_ip('list6')
fq3 = spf.query(i='list6', s=S, h=H, strict=False)
for attr in ('ipaddr', 'c', 'i', 'A', 'v', 'cidrmax', 'iplist'):
    sw = getattr(q2, attr, '<unset>'); fr = getattr(fq3, attr, '<unset>')
    flag = '' if sw == fr else '   <-- MISMATCH'
    print('list6 %-8s switched=%-18r fresh=%-18r%s' % (attr, sw, fr, flag))

# ---- S4: post-fix regression checks ------------------------------------
print()
print('== S4: post-fix checks ==')
# p cache reset on set_ip
q = spf.query(i='192.0.2.3', s=S, h=H, strict=False)
_ = q.getp()
q.set_ip('2001:db8::1')
fq = spf.query(i='2001:db8::1', s=S, h=H, strict=False)
print('p after switch : %-16s fresh: %-16s %s' % (
    q.getp(), fq.getp(), 'OK' if q.getp() == fq.getp() else 'FAIL'))

# list mode: attributes consistent with fresh, get_header works
q = spf.query(i='192.0.2.3', s=S, h=H, strict=False)
q.set_ip('list')
fq = spf.query(i='list', s=S, h=H, strict=False)
ok = all(getattr(q, a, '<u>') == getattr(fq, a, '<u>')
         for a in ('ipaddr', 'c', 'i', 'A', 'v', 'cidrmax'))
print('list attrs match fresh:', 'OK' if ok else 'FAIL')
try:
    h1, h2 = q.get_header('fail'), fq.get_header('fail')
    print('list get_header : OK (%s)' % (h1 == h2))
except Exception as x:
    print('list get_header : FAIL %s' % x)

# explanation does not leak old identity across set_ip
def exp_dns(name, qtype, strict=True, timeout=30):
    if name == '_exp.b.example':
        yield (('_exp.b.example', 'TXT'), [b'ip %{i} not allowed'])
spf.DNSLookup = exp_dns
q = spf.query(i='192.0.2.3', s='a@b.example', h='mx.example.org', strict=False)
r1 = q.check(spf='v=spf1 ip4:1.2.3.4 -all exp=_exp.b.example')
q.set_ip('2001:db8::1')
r2 = q.check(spf='v=spf1 ip4:1.2.3.4 -all')
fq = spf.query(i='2001:db8::1', s='a@b.example', h='mx.example.org', strict=False)
r3 = fq.check(spf='v=spf1 ip4:1.2.3.4 -all')
print('exp switched    : %r' % (r2[2],))
print('exp fresh       : %r  %s' % (r3[2], 'OK' if r2 == r3 else 'FAIL'))
print('exp with exp=   : %r (uses current ip)' % (r1[2],))
q.set_ip('::ffff:192.0.2.3')
r4 = q.check(spf='v=spf1 ip4:1.2.3.4 -all exp=_exp.b.example')
print('exp mapped form : %r  %s' % (r4[2], 'OK' if r4 == r1 else 'FAIL'))
