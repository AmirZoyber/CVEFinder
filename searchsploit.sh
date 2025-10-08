#!/usr/bin/env bash
# searchsploit-pretty.sh
# Usage: ./searchsploit-pretty.sh "search terms..."
# Requirements: searchsploit, jq, awk, sed, grep, realpath (optional)

set -euo pipefail

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

QUERY="$*"

# Run searchsploit -j and try to parse with jq.
# If JSON parse fails, attempt a conservative fix (replace paired duplicated quotes inside string values).
RAW_JSON="$(searchsploit -j "$QUERY" 2>/dev/null || true)"
if [ -z "$RAW_JSON" ]; then
  echo "No output from searchsploit. Perhaps no results or searchsploit failed." >&2
  exit 0
fi

# Try jq first
if echo "$RAW_JSON" | jq . >/dev/null 2>&1; then
  JSON="$RAW_JSON"
else
  # Attempt some conservative fixes:
  # 1) replace occurrences of '""' that often appear inside values with single '"'
  # 2) collapse stray control characters
  FIXED="$(echo "$RAW_JSON" \
    | sed -E 's/""/"/g' \
    | tr -d '\000')"
  # final sanity check
  if echo "$FIXED" | jq . >/dev/null 2>&1; then
    JSON="$FIXED"
  else
    # as last resort try to extract JSON object's inner RESULTS* using grep
    # This is brittle but better than nothing.
    TRY="$(echo "$FIXED" | sed -n '1,20000p')"
    if echo "$TRY" | jq . >/dev/null 2>&1; then
      JSON="$TRY"
    else
      echo "ERROR: couldn't parse searchsploit JSON output. Raw output starts with:" >&2
      echo "${RAW_JSON:0:800}" >&2
      exit 2
    fi
  fi
fi

# Determine which results key is present
RESULTS_KEY="$(echo "$JSON" | jq -r 'if has("RESULTS_EXPLOIT") then "RESULTS_EXPLOIT" elif has("RESULTS") then "RESULTS" else empty end')"

if [ -z "$RESULTS_KEY" ]; then
  # maybe it's a single array already
  if echo "$JSON" | jq 'type == "array"' >/dev/null 2>&1 && [ "$(echo "$JSON" | jq 'length')" -gt 0 ]; then
    RESULTS_ARRAY="$JSON"
  else
    echo "No results found." >&2
    exit 0
  fi
else
  RESULTS_ARRAY="$(echo "$JSON" | jq --arg k "$RESULTS_KEY" '.[$k]')"
fi

CVE_REGEX='CVE-[0-9]\{4\}-[0-9]\{4,7\}'

# helper: extract top comment block and CVEs from a file
extract_meta_from_file() {
  local file="$1"
  local desc=""
  local cves=""
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    echo "__NOFILE__|__NOCVES__"
    return
  fi

  # try to get absolute path
  if command -v realpath >/dev/null 2>&1; then
    file="$(realpath "$file")"
  fi

  # Extract CVEs from file
  cves="$(grep -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' "$file" 2>/dev/null | tr '\n' ' ' | xargs -r echo | sed 's/  */ /g')"
  [ -z "$cves" ] && cves=""

  # Extract top comment block (heuristic)
  # - skip shebang (#!)
  # - gather leading lines starting with # or // contiguous
  # - or a /* ... */ block at the top
  desc="$(awk '
    BEGIN { state=0; first=1; desc="" }
    NR==1 && substr($0,1,2)=="#!" { next }   # skip shebang
    {
      line=$0
      gsub(/^[ \t]+|[ \t]+$/,"",line)
      if (state==0) {
        if (line ~ /^#/) { state=1; sub(/^# ?/,"",line); desc=(line); next }
        else if (line ~ /^\/\//) { state=1; sub(/^\/\/ ?/,"",line); desc=(line); next }
        else if (line ~ /^\/\*/) { state=2; sub(/^\/\*/, "", line); gsub(/\*\/$/,"",line); if (length(line)) desc=line; next }
        else if (length(line)==0) { next }
        else { exit }
      } else if (state==1) {
        if (line ~ /^#/) { sub(/^# ?/,"",line); desc = desc " " line; next }
        else if (line ~ /^\/\//) { sub(/^\/\/ ?/,"",line); desc = desc " " line; next }
        else { exit }
      } else if (state==2) {
        # inside /* ... */
        if (line ~ /\*\//) { sub(/\*\//,"",line); gsub(/^[ \t]*\* ?/,"",line); if (length(line)) desc = desc " " line; exit }
        gsub(/^[ \t]*\* ?/,"",line)
        desc = desc " " line
      }
    }
    END {
      gsub(/^[ \t]+|[ \t]+$/,"",desc)
      if (length(desc) > 800) desc = substr(desc,1,797) "..."
      if (length(desc)==0) desc = ""
      print desc
    }' "$file" 2>/dev/null)"

  # Normalize whitespace
  desc="$(echo "$desc" | tr -s '[:space:] ' ' ' | sed 's/^[ \t]*//;s/[ \t]*$//')"
  printf "%s|%s" "$desc" "$cves"
}

# iterate results
COUNT="$(echo "$RESULTS_ARRAY" | jq 'length')"
if [ "$COUNT" -eq 0 ]; then
  echo "No results." >&2
  exit 0
fi

for i in $(seq 0 $((COUNT-1))); do
  item="$(echo "$RESULTS_ARRAY" | jq -r ".[$i]")"

  # extract common fields robustly
  title="$(echo "$item" | jq -r '(.Exploit // .Title // .Name // .exploit // .title) // "N/A"')"
  edb="$(echo "$item" | jq -r '(.["EDB-ID"] // .["EDB_ID"] // .["EDB ID"] // .EDB // empty)')"
  path="$(echo "$item" | jq -r '(.Path // .path // empty)')"

  # If path is relative, try common exploitdb base paths
  if [ -n "$path" ] && [ ! -f "$path" ]; then
    # common locations
    for base in /usr/share/exploitdb /usr/share/exploitdb/platforms /usr/local/share/exploitdb; do
      candidate="$base/$path"
      if [ -f "$candidate" ]; then
        path="$candidate"
        break
      fi
    done
  fi

  # if still not absolute and looks like "platforms/..." try prefix
  if [ -n "$path" ] && [ ! -f "$path" ] && [ -f "/usr/share/exploitdb/$path" ]; then
    path="/usr/share/exploitdb/$path"
  fi

  # get cves and description from file if available
  meta="$(extract_meta_from_file "$path")"
  desc="${meta%%|*}"
  cves="${meta#*|}"
  # also check CVEs in title
  if [ -z "$cves" ] || [ "$cves" = "__NOCVES__" ]; then
    title_cves="$(echo "$title" | grep -E -o 'CVE-[0-9]{4}-[0-9]{4,7}' || true)"
    if [ -n "$title_cves" ]; then
      cves="$(echo "$title_cves" | tr '\n' ' ' | xargs -r echo | sed 's/  */ /g')"
    else
      cves=""
    fi
  fi

  echo "----------------------------------------"
  echo "Result #$((i+1))"
  echo "Title : $title"
  if [ -n "$edb" ] && [ "$edb" != "null" ]; then
    echo "EDB-ID: $edb    URL: https://www.exploit-db.com/exploits/${edb}"
  fi
  if [ -n "$path" ] && [ -f "$path" ]; then
    echo "Local : $path"
  fi
  if [ -n "$desc" ]; then
    echo "Desc  : $desc"
  else
    echo "Desc  : (no top comment description found in exploit file)"
  fi
  if [ -n "$cves" ]; then
    echo "CVE(s): $cves"
  else
    echo "CVE(s): (none found in exploit file or title)"
  fi
  echo
done

