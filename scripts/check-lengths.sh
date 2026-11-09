#!/usr/bin/env bash
# Check authored file lengths against limits and a shrinking baseline.
set -euo pipefail

RUST_MAX=700
MD_MAX=400

cd "${BASH_SOURCE[0]%/*}/.."
BASELINE=scripts/lengths-baseline.txt
violations=0
shrunk=''

# Read the whole file so a generated header can follow an early test module.
count_lines() {
  awk -v rust="$2" '
    NR <= 5 && (/@generated/ || (/Code generated/ && /DO NOT EDIT/)) { generated = 1 }
    rust && pending && /^[[:space:]]*(pub([[:space:]]*\(crate\))?[[:space:]]+)?mod[[:space:]]+[[:alnum:]_]+[[:space:]]*\{/ && !boundary {
      boundary = NR - 1
    }
    { pending = ($0 ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/) }
    END { print generated ? -1 : (boundary ? boundary - 1 : NR) }
  ' "$1"
}

while IFS= read -r -d '' file; do
  rust=0
  case "$file" in
    *.rs)
      case "$file" in tests/*|*/tests/*|tests.rs|*/tests.rs) continue ;; esac
      limit=$RUST_MAX
      rust=1 ;;
    *.md)
      case "$file" in docs/plans/*|docs/conformance/*|docs/reviews/*) continue ;; esac
      limit=$MD_MAX ;;
    *) continue ;;
  esac
  [[ -f "$file" ]] || continue
  lines=$(count_lines "$file" "$rust")
  ((lines >= 0)) || continue
  cap=$(awk -v path="$file" '
    /^[[:space:]]*#/ { next }
    { n = $1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, ""); if ($0 == path) print n }
  ' "$BASELINE")
  if [[ -n "$cap" ]]; then
    if ((lines <= limit)); then
      printf '%s: %s lines (limit %s | cap %s), remove baseline entry\n' "$file" "$lines" "$limit" "$cap"
      violations=$((violations + 1))
    elif ((lines > cap)); then
      printf '%s: %s lines (cap %s)\n' "$file" "$lines" "$cap"
      violations=$((violations + 1))
    elif ((lines < cap)); then
      shrunk+="; $file: $lines lines (cap $cap), shrank, lower its cap"
    fi
  elif ((lines > limit)); then
    printf '%s: %s lines (limit %s)\n' "$file" "$lines" "$limit"
    violations=$((violations + 1))
  fi
done < <(git ls-files -z -- '*.rs' '*.md')

while read -r cap file; do
  [[ -n "$cap" ]] || continue
  if [[ ! -f "$file" ]] || ! git ls-files --error-unmatch -- "$file" >/dev/null 2>&1; then
    printf '%s: 0 lines (cap %s), stale baseline path (missing or untracked)\n' "$file" "$cap"
    violations=$((violations + 1))
  fi
done < <(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$BASELINE")

((violations == 0)) || exit 1
printf 'check-lengths: ok (Rust <= %s, Markdown <= %s lines)%s\n' "$RUST_MAX" "$MD_MAX" "$shrunk"
