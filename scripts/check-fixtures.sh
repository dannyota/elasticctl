#!/usr/bin/env bash
# Fail if a recorded fixture carries a credential or an identifying host.
#
# Fixtures are recorded from a real stack and committed to a public repository.
# The recorder scrubs by key name and sweeps the recording host out of every
# value, but both are code that can regress, and the failure is silent: a
# fixture looks fine until someone reads the one field nobody thought to name.
#
# This is the backstop, and it exists because the real leak was not a
# credential. `kibana.alert.url` carried the project's host, region, and slug —
# a key no allowlist names, holding identity in its value. A generic secret
# scanner finds none of that, so the patterns below are the shapes this project
# actually produces.
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=tests/fixtures
[ -d "$DIR" ] || { echo "no $DIR to scan"; exit 0; }

fail=0
report() {
  echo "LEAK: $1"
  shift
  printf '  %s\n' "$@"
  fail=1
}

# An Elastic API key, or an Authorization header carrying one.
if hits=$(grep -rnE 'essu_[A-Za-z0-9_-]{8,}|ApiKey [A-Za-z0-9+/=]{20,}|Bearer [A-Za-z0-9._-]{20,}' "$DIR" 2>/dev/null); then
  report "credential material in a fixture" "$hits"
fi

# A real deployment host. The recorder rewrites these to REDACTED.example.invalid;
# anything else that resolves to a cloud endpoint is a recording that escaped it.
if hits=$(grep -rnE '[a-z0-9-]+\.(kb|es)\.[a-z0-9-]+\.(aws|gcp|azure)\.elastic(-cloud)?\.(cloud|com)' "$DIR" 2>/dev/null); then
  report "a deployment hostname in a fixture" "$hits"
fi

# Credentials embedded in a URL's authority.
if hits=$(grep -rnE '://[^/"[:space:]]+:[^/@"[:space:]]+@' "$DIR" 2>/dev/null); then
  report "userinfo in a URL" "$hits"
fi

# An operator's identity. The scrub replaces these with REDACTED; a bare
# address or a populated identity field means it did not run.
if hits=$(grep -rnE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$DIR" 2>/dev/null | grep -v 'example\.\(com\|invalid\)'); then
  report "an email address in a fixture" "$hits"
fi

if [ "$fail" -eq 0 ]; then
  echo "fixtures clean: no credential, host, userinfo, or email"
fi
exit "$fail"
