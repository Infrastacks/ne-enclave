#!/usr/bin/env sh
set -eu

file="${1:-deny.toml}"
current_version="$(
  sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1
)"

if [ -z "$current_version" ]; then
  echo "unable to determine workspace version from Cargo.toml" >&2
  exit 1
fi

awk '
  /{ id = "RUSTSEC-/ {
    if ($0 !~ /owner=[^;"]+/ ||
        $0 !~ /expires=v[0-9]+\.[0-9]+\.[0-9]+/ ||
        $0 !~ /rationale=[^"]+/) {
      print "advisory ignore lacks owner/expires metadata: " $0 > "/dev/stderr"
      bad = 1
    }
  }
  END { exit bad }
' "$file"

version_at_or_after() {
  awk -v current="$1" -v expiry="$2" '
    BEGIN {
      sub(/^v/, "", current)
      sub(/^v/, "", expiry)
      split(current, c, ".")
      split(expiry, e, ".")
      for (i = 1; i <= 3; i++) {
        if ((c[i] + 0) > (e[i] + 0)) exit 0
        if ((c[i] + 0) < (e[i] + 0)) exit 1
      }
      exit 0
    }
  '
}

bad=0
# shellcheck disable=SC2013 # Expiry tokens are version strings with no whitespace.
for expiry in $(
  sed -n 's/.*expires=\(v[0-9][0-9.]*\);.*/\1/p' "$file"
); do
  if version_at_or_after "$current_version" "$expiry"; then
    echo "advisory exception expired at $expiry" >&2
    bad=1
  fi
done
exit "$bad"
