#!/usr/bin/env bash
# searchsploit-pretty-relaxed.sh
# Usage: ./searchsploit-pretty-relaxed.sh "search terms..."
#
# What it does:
# - Builds relaxed queries from your input (product + version steps: X.Y.Z, X.Y, X)
# - Runs searchsploit -j for each query, merges & de-dups results
# - Accepts loose brand/product matches (tolerates minor typos) OR version matches
# - Sorts results by specificity (X.Y.Z > X.Y > X > none), prints top comment + CVEs
#
# Requirements: searchsploit, jq, awk, sed, grep, realpath (optional)
set -euo pipefail

# ----- Checks -----
if ! command -v searchsploit >/dev/null 2>&1; then
  echo "ERROR: searchsploit not found. Install exploitdb/searchsploit first." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq not found. Install jq (sudo apt install jq)." >&2
  exit 1
fi
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <search terms...>" >&2
  exit 1
fi

# ----- Input normalization (locale-safe) -----
QUERY_RAW="$*"

# Lowercase safely with awk (avoids locale issues)
QUERY_LC="$(printf '%s' "$QUERY_RAW" | awk '{print tolower($0)}')"

# Keep a simple safe character set; replace others with space (avoid tr-class pitfalls)
# Allowed: letters, digits, space, dot, underscore, comma, dash, parentheses
QUERY_SAFE="$(printf '%s' "$QUERY_LC" | sed 's/[^a-z0-9 ._,()\-]/ /g')"

# Extract a likely product name: first token with 3+ letters
PRODUCT="$(printf '%s\n' "$QUERY_SAFE" \
  | awk '
    {
      for(i=1;i<=NF;i++){
        # pick tokens with at least 3 letters (ignore versions-only)
        if ($i ~ /[a-z]/ && length($i) >= 3) { print $i; exit }
      }
    }
  ')"
[ -z "$PRODUCT" ] && PRODUCT="$(echo "$QUERY_SAFE" | awk '{print $1}')"

# Extract the first version-like thing: n(.n){0,2}
FULL_VER="$(printf '%s' "$QUERY_SAFE" | grep -Eo '[0-9]+(\.[0-9]+){0,2}' | head -n1 || true)"
MAJOR=""; MINOR=""
if [[ "${FULL_VER:-}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
elif [[ "${FULL_VER:-}" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="$FULL_VER"
elif [[ "${FULL_VER:-}" =~ ^([0-9]+)$ ]]; then
  MAJOR="$FULL_VER"
fi

# Build relaxed query set (most specific first)
QUERIES=()
if [ -n "${PRODUCT:-}" ] && [ -n "${FULL_VER:-}" ]; then QUERIES+=("$PRODUCT $FULL_VER"); fi
if [ -n "${PRODUCT:-}" ] && [ -n "${MINOR:-}" ] && [ "$MINOR" != "$FULL_VER" ]; then QUERIES+=("$PRODUCT $MINOR"); fi
if [ -n "${PRODUCT:-}" ] && [ -n "${MAJOR:-}" ] && [ "$MAJOR" != "$FULL_VER" ] && [ "$MAJOR" != "$MINOR" ]; then QUERIES+=("$PRODUCT $MAJOR"); fi
if [ -n "${PRODUCT:-}" ]; then QUERIES+=("$PRODUCT"); fi
# Last resort: the original
QUERIES+=("$QUERY_RAW")

# ----- Helpers -----
# Create a loose product regex that tolerates skipped letters (e.g., lferay still matches liferay)
# "liferay" -> "l.*i.*f.*e.*r.*a.*y"
loose_pat_from_word() {
  local w="$1"
  w="$(printf '%s' "$w" | sed 's/[^a-z0-9]//g')"  # alnum only
  local out="" i ch
  for (( i=0; i<${#w}; i++ )); do
    ch="${w:$i:1}"
    out="${out}${ch}.*"
  done
  printf '%s' "$out"
}
LOOSE_PAT="$(loose_pat_from_word "$PRODUCT")"

# Resolve a relative exploitdb path to a local absolute path, if possible
resolve_path() {
  local p="$1"
  [ -z "$p" ] && { printf '%s' ""; return; }
  if [ ! -f "$p" ]; then
    for base in /usr/share/exploitdb /usr/share/exploitdb/platforms /usr/local/share/exploitdb; do
      local cand="$base/$p"
      if [ -f "$cand" ]; then
        printf '%s' "$cand"; return
      fi
    done
    if [ -f "/usr/share/exploitdb/$p" ]; then
      printf '%s' "/usr/share/exploitdb/$p"; return
    fi
  fi
  printf '%s' "$p"
}

# Extract a brief top comment and CVEs from a local file
extract_meta_from_file() {
  local file="$1"
  local desc=""; local cves=""
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    printf "%s|%s" "__NOFILE__" "__NOCVES__"
    return
  fi

  if command -v realpath >/dev/null 2>&1; then
    file="$(realpath "$file")"
  fi

  cves="$(grep -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' "$file" 2>/dev/null | tr '\n' ' ' | xargs -r echo | sed 's/  */ /g')"
  [ -z "$cves" ] && cves=""

  desc="$(awk '
    BEGIN { state=0; desc="" }
    NR==1 && substr($0,1,2)=="#!" { next }   # skip shebang
    {
      line=$0
      gsub(/^[ \t]+|[ \t]+$/,"",line)
      if (state==0) {
        if (line ~ /^#/)      { state=1; sub(/^# ?/,"",line); desc=line; next }
        else if (line ~ /^\/\//){ state=1; sub(/^\/\/ ?/,"",line); desc=line; next }
        else if (line ~ /^\/\*/){ state=2; sub(/^\/\*/,"",line); gsub(/\*\/$/,"",line); if (length(line)) desc=line; next }
        else if (length(line)==0) { next }
        else { exit }
      } else if (state==1) {
        if (line ~ /^#/)      { sub(/^# ?/,"",line); desc=desc" "line; next }
        else if (line ~ /^\/\//){ sub(/^\/\/ ?/,"",line); desc=desc" "line; next }
        else { exit }
      } else if (state==2) {
        if (line ~ /\*\//)    { sub(/\*\//,"",line); gsub(/^[ \t]*\* ?/,"",line); if (length(line)) desc=desc" "line; exit }
        gsub(/^[ \t]*\* ?/,"",line); desc=desc" "line
      }
    }
    END {
      gsub(/^[ \t]+|[ \t]+$/,"",desc)
      if (length(desc) > 800) desc=substr(desc,1,797)"..."
      print desc
    }' "$file" 2>/dev/null)"

  desc="$(printf '%s' "$desc" | tr -s '[:space:]' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')"
  printf "%s|%s" "$desc" "$cves"
}

# ----- Fetch & merge results -----
TMP_ITEMS="$(mktemp)"; trap 'rm -f "$TMP_ITEMS"' EXIT
> "$TMP_ITEMS"

for q in "${QUERIES[@]}"; do
  OUT="$(searchsploit -j "$q" 2>/dev/null || true)"
  [ -z "$OUT" ] && continue

  # Accept valid JSON; normalize to an array of result objects
  if echo "$OUT" | jq -e . >/dev/null 2>&1; then
    KEY="$(echo "$OUT" | jq -r 'if has("RESULTS_EXPLOIT") then "RESULTS_EXPLOIT" elif has("RESULTS") then "RESULTS" else empty end' || true)"
    if [ -n "$KEY" ]; then
      echo "$OUT" | jq -c ".\"$KEY\"[]" >> "$TMP_ITEMS" 2>/dev/null || true
    else
      # maybe already an array
      if echo "$OUT" | jq -e 'type=="array"' >/dev/null 2>&1; then
        echo "$OUT" | jq -c '.[]' >> "$TMP_ITEMS" 2>/dev/null || true
      fi
    fi
  fi
done

if [ ! -s "$TMP_ITEMS" ]; then
  echo "No results found." >&2
  exit 0
fi

# Deduplicate by (EDB-ID, Path, Title)
SLURPED="$(jq -sc '
  map({
    title: (.Exploit // .Title // .Name // .exploit // .title // "N/A"),
    edb: (."EDB-ID" // ."EDB_ID" // ."EDB ID" // .EDB // null),
    path: (.Path // .path // null)
  })
  | unique_by([.edb, .path, .title])
' "$TMP_ITEMS")"

if [ -z "$SLURPED" ] || [ "$SLURPED" = "[]" ]; then
  echo "No results after deduplication." >&2
  exit 0
fi

# ----- Score & filter -----
# Scoring:
#   Full version match (X.Y.Z): +3
#   Minor version match (X.Y) : +2
#   Major version match (X)   : +1
#   Loose product match       : +2
# Keep items with score > 0
TMP_SORT="$(mktemp)"; trap 'rm -f "$TMP_SORT"' RETURN
echo "$SLURPED" | jq -cr '.[]' | while IFS= read -r item; do
  title="$(printf '%s' "$item" | jq -r '.title')"
  edb="$(printf '%s' "$item" | jq -r '.edb // empty')"
  path="$(printf '%s' "$item" | jq -r '.path // empty')"

  t_lc="$(printf '%s' "$title" | awk '{print tolower($0)}')"

  score=0
  # version specificity (word-ish boundaries for numbers)
  if [ -n "${FULL_VER:-}" ] && echo "$t_lc" | grep -Eq "(^|[^0-9])${FULL_VER}([^0-9]|$)"; then
    score=$((score+3))
  elif [ -n "${MINOR:-}" ] && echo "$t_lc" | grep -Eq "(^|[^0-9])${MINOR}([^0-9]|$)"; then
    score=$((score+2))
  elif [ -n "${MAJOR:-}" ] && echo "$t_lc" | grep -Eq "(^|[^0-9])${MAJOR}([^0-9]|$)"; then
    score=$((score+1))
  fi

  # loose product (tolerate minor typos / gaps)
  if [ -n "${PRODUCT:-}" ] && echo "$t_lc" | grep -Eqi "$LOOSE_PAT"; then
    score=$((score+2))
  fi

  if [ "$score" -gt 0 ]; then
    # TSV: score | title | edb | path
    printf '%s\t%s\t%s\t%s\n' "$score" "$title" "$edb" "$path" >> "$TMP_SORT"
  fi
done

if [ ! -s "$TMP_SORT" ]; then
  echo "No approximate matches that look relevant." >&2
  exit 0
fi

# ----- Output -----
sort -r -n -k1,1 "$TMP_SORT" | while IFS=$'\t' read -r score title edb path; do
  # try to resolve local file path for meta
  [ -n "$path" ] && path="$(resolve_path "$path")"
  meta="$(extract_meta_from_file "$path")"
  desc="${meta%%|*}"
  cves="${meta#*|}"

  # also scan title for CVEs if file didn't contain any
  if [ -z "$cves" ] || [ "$cves" = "__NOCVES__" ]; then
    title_cves="$(printf '%s' "$title" | grep -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' || true)"
    [ -n "$title_cves" ] && cves="$(echo "$title_cves" | tr '\n' ' ' | xargs -r echo | sed 's/  */ /g')"
  fi

  echo "----------------------------------------"
  echo "Score : $score"
  echo "Title : $title"
  if [ -n "$edb" ] && [ "$edb" != "null" ]; then
    echo "EDB-ID: $edb    URL: https://www.exploit-db.com/exploits/${edb}"
  fi
  if [ -n "$path" ] && [ -f "$path" ]; then
    echo "Local : $path"
  fi
  if [ -n "$desc" ] && [ "$desc" != "__NOFILE__" ]; then
    echo "Desc  : $desc"
  else
    echo "Desc  : (no top comment description found in exploit file)"
  fi
  if [ -n "$cves" ] && [ "$cves" != "__NOCVES__" ]; then
    echo "CVE(s): $cves"
  else
    echo "CVE(s): (none found in exploit file or title)"
  fi
  echo
done

exit 0
