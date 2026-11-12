"""Offline DNS view used to make SPF recomputation fully replayable.

pyspf resolves every record through the module level ``spf.DNSLookup``
function (see ``spf.py``).  Replacing that function with an adapter backed
by a frozen in-memory view guarantees that a forensic re-check performs no
network I/O at all and always observes the same answers.

A view is keyed by lower-case, root-dot-stripped ``(name, qtype)`` pairs and
stores answers in a form close to the dnspython driver contract:

* ``A`` / ``AAAA`` -> dotted IPv4 / IPv6 text strings
* ``MX``           -> ``(preference, exchange)`` tuples
* ``PTR``          -> target name strings
* ``TXT`` / ``SPF`` -> either a single string or a sequence of strings,
  each string becoming one character-string of one DNS TXT RDATA
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from threading import RLock
from typing import Dict, Iterable, List, Optional, Tuple

import spf

_QTYPES = ("A", "AAAA", "MX", "PTR", "TXT", "SPF")
Key = Tuple[str, str]


class OfflineDNSMissing(Exception):
    """Raised in strict mode when a lookup has no entry in the offline view."""

    def __init__(self, name: str, qtype: str):
        super().__init__("no offline DNS record for %s %s" % (qtype, name))
        self.name = name
        self.qtype = qtype


def _norm_name(name: str) -> str:
    name = str(name).rstrip(".").lower()
    if not name or any(len(label) < 1 or len(label) > 63 for label in name.split(".")):
        raise spf.PermError("Invalid DNS name: %r" % name)
    return name


def _norm_qtype(qtype: str) -> str:
    qtype = str(qtype).upper()
    if qtype not in _QTYPES:
        raise spf.PermError("Unsupported qtype: %r" % qtype)
    return qtype


def _txt_rdata(value) -> Tuple[bytes, ...]:
    if isinstance(value, (bytes, str)):
        value = [value]
    out: List[bytes] = []
    for chunk in value:
        if isinstance(chunk, str):
            chunk = chunk.encode("ascii")
        out.append(chunk)
    return tuple(out)


class OfflineDNSView:
    """Frozen, content-addressable DNS view with a full query audit log."""

    def __init__(
        self,
        records: Optional[Dict[Key, list]] = None,
        *,
        missing: str = "empty",
        view_id: Optional[str] = None,
    ):
        """
        :param records: mapping ``(name, qtype) -> list of rdata``
        :param missing: ``"empty"`` returns no answer (NXDOMAIN/NoAnswer
            semantics); ``"temperror"`` raises :class:`spf.TempError` so
            gaps surface instead of silently looking like absent records;
            ``"strict"`` raises :class:`OfflineDNSMissing`.
        :param view_id: optional provenance label (e.g. snapshot name).
        """
        if missing not in ("empty", "temperror", "strict"):
            raise ValueError("missing must be empty, temperror or strict")
        self.missing = missing
        self.view_id = view_id
        self._records: Dict[Key, list] = {}
        if records:
            for (name, qtype), rdata in records.items():
                self.put(name, qtype, rdata)
        self.query_log: List[dict] = []
        self._lock = RLock()

    def put(self, name: str, qtype: str, rdata: list) -> "OfflineDNSView":
        """Add or replace one RR set; normalised into the pyspf contract."""
        key = (_norm_name(name), _norm_qtype(qtype))
        qtype = key[1]
        normalised: list = []
        for item in rdata:
            if qtype in ("TXT", "SPF"):
                normalised.append(_txt_rdata(item))
            elif qtype == "MX":
                preference, exchange = item
                normalised.append((int(preference), str(exchange).rstrip(".").lower()))
            else:
                normalised.append(str(item).rstrip(".").lower())
        with self._lock:
            self._records[key] = normalised
        return self

    def get(self, name: str, qtype: str) -> Optional[list]:
        key = (_norm_name(name), _norm_qtype(qtype))
        with self._lock:
            value = self._records.get(key)
            return list(value) if value is not None else None

    def keys(self) -> List[Key]:
        with self._lock:
            return sorted(self._records)

    def lookup(self, name: str, qtype: str, strict=True, timeout=20) -> List[tuple]:
        """Adapter with the same call signature as ``spf.DNSLookup``.

        Returns ``[((name, qtype), rdata), ...]`` exactly like the
        dnspython driver, so pyspf caching and CNAME handling work unchanged.
        Every call, including misses, is appended to :attr:`query_log`.
        """
        nname = _norm_name(name)
        nqtype = _norm_qtype(qtype)
        with self._lock:
            answers = self._records.get((nname, nqtype))
            entry = {
                "name": nname,
                "qtype": nqtype,
                "hit": answers is not None,
                "answers": 0 if answers is None else len(answers),
            }
            self.query_log.append(entry)
            if answers is None:
                if self.missing == "temperror":
                    raise spf.TempError(
                        "offline view has no %s record for %s" % (nqtype, nname)
                    )
                if self.missing == "strict":
                    raise OfflineDNSMissing(nname, nqtype)
                return []
            return [((nname, nqtype), rdata) for rdata in answers]

    def mark_log(self) -> int:
        """Return the current query log position (per re-check slicing)."""
        with self._lock:
            return len(self.query_log)

    def log_since(self, mark: int) -> List[dict]:
        with self._lock:
            return [dict(item) for item in self.query_log[mark:]]

    def fingerprint(self) -> str:
        """Stable SHA-256 over the exact view contents for the report."""
        canonical = json.dumps(
            [
                [list(key), self._json_rdata(key[1], rdata)]
                for key in sorted(self._records)
                for rdata in (self._records[key],)
            ],
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _json_rdata(qtype: str, rdata: list):
        if qtype in ("TXT", "SPF"):
            return [[chunk.decode("ascii", "replace") for chunk in rr] for rr in rdata]
        return rdata

    def describe(self) -> dict:
        return {
            "view_id": self.view_id,
            "fingerprint_sha256": self.fingerprint(),
            "missing_policy": self.missing,
            "records": [
                {"name": name, "qtype": qtype, "rdata": self._json_rdata(qtype, rdata)}
                for (name, qtype), rdata in sorted(self._records.items())
            ],
        }


@contextmanager
def offline_dns(view: OfflineDNSView):
    """Temporarily install ``view`` as pyspf's sole DNS resolver.

    The original resolver is always restored, even if the re-check raises.
    Nesting is supported; no live resolver is reachable inside the block.
    """
    original = spf.DNSLookup
    spf.DNSLookup = view.lookup
    try:
        yield view
    finally:
        spf.DNSLookup = original
