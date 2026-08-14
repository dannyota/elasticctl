#!/usr/bin/env bash
# Fail if a recorded fixture contains credentials or an identifying host.
#
# Fixtures come from a real stack and are committed to a public repository.
# The recorder redacts values selected by key name and removes the recording
# host from every value. This check catches regressions when an identifying
# field is missed.
#
# This backstop covers the original leak: `kibana.alert.url` carried the
# project's host, region, and slug in a value. A generic secret scanner misses
# that shape, so the patterns below match data this project actually produces.
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

# An Elastic API key or an Authorization header carrying one.
if hits=$(grep -rnE 'essu_[A-Za-z0-9_-]{8,}|ApiKey [A-Za-z0-9+/=]{20,}|Bearer [A-Za-z0-9._-]{20,}' "$DIR" 2>/dev/null); then
  report "credential material in a fixture" "$hits"
fi

# A real deployment host. The recorder rewrites these to
# REDACTED.example.invalid; any other cloud endpoint escaped scrubbing.
if hits=$(grep -rnE '[a-z0-9-]+\.(kb|es)\.[a-z0-9-]+\.(aws|gcp|azure)\.elastic(-cloud)?\.(cloud|com)' "$DIR" 2>/dev/null); then
  report "a deployment hostname in a fixture" "$hits"
fi

# Credentials embedded in a URL authority.
if hits=$(grep -rnE '://[^/"[:space:]]+:[^/@"[:space:]]+@' "$DIR" 2>/dev/null); then
  report "userinfo in a URL" "$hits"
fi

# The scrubber redacts values under identity keys. This check catches email
# addresses elsewhere, including escaped values.
if hits=$(grep -rnE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$DIR" 2>/dev/null | grep -v 'example\.\(com\|invalid\)'); then
  report "an email address in a fixture" "$hits"
fi

if [ "$fail" -eq 0 ]; then
  echo "fixtures clean: no credential, host, userinfo, or email"
fi
exit "$fail"
