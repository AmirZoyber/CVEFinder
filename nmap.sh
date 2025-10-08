#!/usr/bin/env bash
# nscan.sh - simple wrapper around nmap to parse ports into "port/tcp" "port/udp" lines
# Usage examples:
#   ./nscan.sh -t 1.2.3.4 -T            # tcp scan
#   ./nscan.sh -t example.com -U --delay 200   # udp scan with 200ms scan-delay
#   ./nscan.sh -t 1.2.3.4 -TU -o out.txt       # both, write raw nmap output to out.txt and print ports
#   ./nscan.sh -t 1.2.3.4 -TU -o out.txt --scilent  # write but don't print

set -euo pipefail

print_help() {
  cat <<EOF
nscan.sh - minimal wrapper for nmap that prints only ports as "port/tcp" or "port/udp"

Options:
  -t, --target <target>      Target host or network (required)
  -T, --tcp                  Do a TCP scan (-sT)
  -U, --udp                  Do a UDP scan (-sU)
  -TU                        Do both TCP and UDP
  --delay <ms>               Pass a scan delay to nmap as --scan-delay <ms> (milliseconds)
  -o <file>                  Save raw nmap output to <file> (also prints parsed ports unless --scilent)
  --scilent                  If present, suppress printing parsed ports to stdout (file still written if -o used)
  -h, --help                 Show this help
EOF
}

# defaults
TARGET=""
DO_TCP=false
DO_UDP=false
DELAY=""
OUTFILE=""
SCILENT=false

# parse args (supports long and short)
if [ $# -eq 0 ]; then
  print_help
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)
      TARGET="$2"; shift 2 ;;
    -T|--tcp)
      DO_TCP=true; shift ;;
    -U|--udp)
      DO_UDP=true; shift ;;
    -TU)
      DO_TCP=true; DO_UDP=true; shift ;;
    --delay)
      # expect milliseconds like 100 or 200ms (we'll append ms if user gave a number)
      raw="$2"
      if [[ "$raw" =~ ^[0-9]+$ ]]; then
        DELAY="${raw}ms"
      else
        DELAY="$raw"
      fi
      shift 2 ;;
    -o)
      OUTFILE="$2"; shift 2 ;;
    --scilent)
      SCILENT=true; shift ;;
    -h|--help)
      print_help; exit 0 ;;
    *)
      echo "unknown option: $1"; print_help; exit 2 ;;
  esac
done

# validation
if [ -z "$TARGET" ]; then
  echo "error: target is required (-t | --target)." >&2
  exit 2
fi
if [ "$DO_TCP" = false ] && [ "$DO_UDP" = false ]; then
  echo "error: at least one of TCP or UDP must be requested (-T/--tcp, -U/--udp, or -TU)." >&2
  exit 2
fi

# check nmap exists
if ! command -v nmap >/dev/null 2>&1; then
  echo "error: nmap not found in PATH." >&2
  exit 3
fi

# build nmap command
NMAP_OPTS=()
if [ "$DO_TCP" = true ]; then
  NMAP_OPTS+=("-sT")
fi
if [ "$DO_UDP" = true ]; then
  NMAP_OPTS+=("-sU")
fi
# quiet-ish nmap output (but keep useful info)
NMAP_OPTS+=("-Pn")   # skip host discovery to speed things and avoid blocking (adjust if you don't want this)
# user-provided delay
if [ -n "$DELAY" ]; then
  NMAP_OPTS+=("--scan-delay" "$DELAY")
fi

# temp file for raw output
TMP=$(mktemp /tmp/nscan.XXXXXX)
trap 'rm -f "$TMP"' EXIT

# run nmap
echo "running nmap on ${TARGET}..." >&2
nmap "${NMAP_OPTS[@]}" "$TARGET" -oN "$TMP" >/dev/null 2>&1 || true
# note: we capture output in $TMP even if nmap exits non-zero (e.g., no UDP privileges); continue to parsing

# if outfile requested, write raw nmap output there
if [ -n "$OUTFILE" ]; then
  cp "$TMP" "$OUTFILE"
  echo "raw nmap output written to: $OUTFILE" >&2
fi

# parse ports lines from nmap normal output
# nmap normal output shows a table section like:
# PORT     STATE  SERVICE
# 22/tcp   open   ssh
# 53/udp   open   domain
# We'll capture lines that look like 'number/(tcp|udp)' at line start
PORT_LINES=$(grep -E '^[0-9]+/(tcp|udp)' "$TMP" || true)

# produce final port list: "port/tcp" ...
# If user asked not to print (scilent), we skip printing to stdout.
if [ -z "$PORT_LINES" ]; then
  # no ports found
  if [ "$SCILENT" = false ]; then
    # still print nothing but exit success
    :
  fi
else
  # extract first column (port/proto)
  if [ "$SCILENT" = false ]; then
    echo "$PORT_LINES" | awk '{print $1}'
  fi
fi

# exit
exit 0
