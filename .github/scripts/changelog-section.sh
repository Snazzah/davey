#!/usr/bin/env bash
# Usage: changelog-section.sh <changelog> <version>...
# Prints the section of the first version heading found (e.g. "## 0.1.12 - 2026-06-20"),
# falling back to the "## Unreleased" section.
set -euo pipefail

changelog="$1"
shift

extract() {
  awk -v heading="$1" '
    /^## / {
      if (found) exit
      if ($0 == "## " heading || index($0, "## " heading " ") == 1) { found = 1; next }
    }
    found { print }
  ' "$changelog" | sed '/./,$!d'
}

for version in "$@" Unreleased; do
  section="$(extract "$version")"
  if [ -n "$section" ]; then
    if [ "$version" = Unreleased ]; then
      echo "::warning::No changelog section found for $*, using the Unreleased section" >&2
    fi
    printf '%s\n' "$section"
    exit 0
  fi
done

echo "::error::No changelog section found for $* or Unreleased in $changelog" >&2
exit 1
