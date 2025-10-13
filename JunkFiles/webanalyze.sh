#!/usr/bin/env bash
# tech_variants_flat.sh
# Usage:
#   webanalyze -app technologies.json -host example.com | ./tech_variants_flat.sh
#   ./tech_variants_flat.sh webanalyze_out.txt

set -euo pipefail

input="-"
if [ "$#" -gt 0 ]; then
  input="$1"
fi

# read lines (trim blanks)
read_lines() {
  if [ "$input" = "-" ]; then
    sed '/^[[:space:]]*$/d'
  else
    sed '/^[[:space:]]*$/d' "$input"
  fi
}

trim() { echo "$1" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'; }

# extract version:
# - prefer tokens with at least one dot (v1.2 or 1.2.3)
# - allow leading v/V, underscores are treated as dots
# - strip trailing non-digit/dot chars
extract_version() {
  local line="$1"
  local norm
  norm=$(echo "$line" | tr '_' '.')   # 1_2_3 -> 1.2.3

  # prefer tokens with at least one dot
  local v
  v=$(echo "$norm" | grep -oE 'v?[0-9]+(\.[0-9]+){1,}' | head -n1 || true)
  if [ -n "$v" ]; then
    v=$(echo "$v" | sed -E 's/^[vV]//')                      # remove leading v
    v=$(echo "$v" | grep -oE '^[0-9]+(\.[0-9]+)*' || true)  # keep only digits+dots
    echo "$v"
    return 0
  fi

  # fallback: single integer token (e.g., "7")
  v=$(echo "$line" | grep -oE 'v?[0-9]+' | head -n1 || true)
  if [ -n "$v" ]; then
    v=$(echo "$v" | sed -E 's/^[vV]//')
    echo "$v"
    return 0
  fi

  return 1
}

# extract original name: before comma if exists, else strip version+trailing parts
extract_name() {
  local line="$1"
  if echo "$line" | grep -q ','; then
    echo "$line" | sed -E 's/,.*$//'
  else
    # remove the first version-like token and everything after it (case-insensitive)
    echo "$line" | sed -E 's/[[:space:]]+v?[0-9]+(\.[0-9]+){0,}.*$//I' | sed -E 's/\([^)]+\)//g'
  fi
}

declare -A seen
while IFS= read -r raw; do
  line=$(trim "$raw")
  [ -z "$line" ] && continue

  ver=$(extract_version "$line" || true)
  [ -z "$ver" ] && continue   # skip entries without any version

  name=$(trim "$(extract_name "$line")")
  [ -z "$name" ] && name="$line"

  # split version into parts
  IFS='.' read -ra parts <<< "$ver"
  major="${parts[0]:-}"
  minor="${parts[1]:-}"
  patch="${parts[2]:-}"

  # output full (original name + full version)
  out1="$name $ver"
  if [ -z "${seen[$out1]+x}" ]; then
    echo "$out1"
    seen[$out1]=1
  fi

  # output major.minor if available (and not duplicate)
  if [ -n "$minor" ]; then
    out2="$name $major.$minor"
    if [ -z "${seen[$out2]+x}" ]; then
      echo "$out2"
      seen[$out2]=1
    fi
  fi

  # output major (if not duplicate)
  if [ -n "$major" ]; then
    out3="$name $major"
    if [ -z "${seen[$out3]+x}" ]; then
      echo "$out3"
      seen[$out3]=1
    fi
  fi

done < <(read_lines <&0)
