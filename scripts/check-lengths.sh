#!/usr/bin/env bash
# Check authored file lengths against limits and a shrinking baseline.
set -euo pipefail

RUST_MAX=700
MD_MAX=400

cd "${BASH_SOURCE[0]%/*}/.."
BASELINE=scripts/lengths-baseline.txt
violations=0
base_ref=''
if (($#)); then
  if [[ $# != 2 || $1 != --base-ref || -z $2 ]]; then
    printf 'usage: check-lengths.sh [--base-ref <ref>]\n' >&2
    exit 1
  fi
  base_ref=$2
fi

cap_for() {
  awk -v path="$1" '
    /^[[:space:]]*#/ { next }
    { n = $1; sub(/^[[:space:]]*[0-9]+[[:space:]]+/, ""); if ($0 == path) print n }
  '
}

if [[ -n "$base_ref" ]]; then
  base_commit=$(git rev-parse --verify --end-of-options "$base_ref^{commit}" 2>/dev/null) || {
    printf 'check-lengths: invalid base ref: %s\n' "$base_ref" >&2
    exit 1
  }
  base_baseline=''
  if [[ -n $(git ls-tree "$base_commit" -- "$BASELINE") ]]; then
    base_baseline=$(git show "$base_commit:$BASELINE")
  else
    # The change that introduces the gate has no base baseline to compare.
    printf 'check-lengths: %s has no baseline; skipping base comparison\n' "$base_ref"
  fi
  [[ -n "$base_baseline" ]] && while read -r cap file; do
    [[ -n "$cap" ]] || continue
    base_cap=$(cap_for "$file" <<<"$base_baseline")
    if [[ -z "$base_cap" ]]; then
      printf '%s: baseline entry absent from base ref\n' "$file"
      violations=$((violations + 1))
    elif ((cap > base_cap)); then
      printf '%s: cap %s exceeds base cap %s\n' "$file" "$cap" "$base_cap"
      violations=$((violations + 1))
    fi
  done < <(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$BASELINE")
fi

# Delay a test attribute until the following line confirms an inline module.
count_lines() {
  awk -v rust="$2" '
    { sub(/\r$/, "") }
    skipping { if (/^}/) skipping = 0; next }
    rust && pending {
      pending = 0
      if (/^(pub([[:space:]]*\(crate\))?[[:space:]]+)?mod[[:space:]]+[[:alnum:]_]+[[:space:]]*\{/) {
        if (/\{[[:space:]]*}[[:space:]]*(\/\/.*)?$/) next
        if (/\{[[:space:]]*(\/\/.*)?$/) {
          skipping = 1
          next
        }
      }
      count++
    }
    rust && /^#\[cfg\(test\)\][[:space:]]*$/ { pending = 1; next }
    { count++ }
    END { print count + pending }
  ' "$1"
}

while IFS= read -r -d '' file; do
  rust=0
  case "$file" in
    *.rs)
      case "$file" in tests/*|*/tests/*) continue ;; esac
      limit=$RUST_MAX
      rust=1 ;;
    *.md)
      case "$file" in docs/plans/*|docs/conformance/*|docs/reviews/*) continue ;; esac
      limit=$MD_MAX ;;
    *) continue ;;
  esac
  [[ -f "$file" ]] || continue
  lines=$(count_lines "$file" "$rust")
  cap=$(cap_for "$file" <"$BASELINE")
  if [[ -n "$cap" ]]; then
    if ((lines <= limit)); then
      printf '%s: %s lines (limit %s | cap %s), remove baseline entry\n' "$file" "$lines" "$limit" "$cap"
      violations=$((violations + 1))
    elif ((lines > cap)); then
      printf '%s: %s lines (cap %s)\n' "$file" "$lines" "$cap"
      violations=$((violations + 1))
    elif ((lines < cap)); then
      printf '%s: %s lines (cap %s), lower its cap to %s\n' "$file" "$lines" "$cap" "$lines"
      violations=$((violations + 1))
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
printf 'check-lengths: ok (Rust <= %s, Markdown <= %s lines)\n' "$RUST_MAX" "$MD_MAX"
