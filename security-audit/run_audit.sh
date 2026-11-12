#!/bin/sh
# Reproducible, fully offline audit of pyspf local-policy semantics.
# Overrides spf.DNSLookup with an in-memory zone, so no network is used.
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
set -e
echo "### 1. String-splice / full-eval / recursion / header matrix"
"$PY" security-audit/local_policy_audit.py
echo
echo "### 2. Qualifier, lookup-budget, void and idempotency edge cases"
"$PY" security-audit/local_policy_edge.py
echo
echo "### 3. Authorization provenance (domain vs local) and header annotation"
"$PY" security-audit/source_provenance.py
echo
echo "### 4. Unit tests (official YAML suite + new provenance tests)"
( cd test && ../"$PY" testspf.py )
