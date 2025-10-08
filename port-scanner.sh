#!/usr/bin/env bash
# port-scanner.sh - unified wrapper around masscan/nmap
# Usage examples:
#  sudo ./port-scanner.sh -t 198.51.100.0/24 -T
#  ./port-scanner.sh -t example.com -U -o ports.txt
#  sudo ./port-scanner.sh -t 1.2.3.4 -TU --scilence
#
# Notes:
#  - Requires masscan and/or nmap to be installed. masscan is used for TCP if available for speed.
#  - Scanning UDP often requires root privileges (both masscan and nmap).
#  - Only scan hosts/networks you are authorized to scan.

set -euo pipefail

# defaults
TARGET=""
DO_TCP=false
DO_UDP=false
OUTFILE=""
SCILENT=false

# masscan defaults (you can edit below if you want different defaults)
MASSCAN_PORTS="1-65535"
MASSCAN_RATE="10000"

print_help() {
  cat <<EOF
port-scanner.sh - prints open ports as "port/tcp" or "port/udp", sorted and unique

Options:
  -t, --target <target>    Target IP/CIDR/hostname (required)
  -T                       Scan TCP
  -U                       Scan UDP
  -TU                      Scan both TCP and UDP
  -o, --output <file>      Save final ports to <file>
  -s, --scilence           Suppress printing parsed ports to stdout (still writes file if -o given)
  -h, --help               Show this help
EOF
}

# parse args
if [ $# -eq 0 ]; then
  print_help
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)
      TARGET="$2"; shift 2 ;;
    -T)
      DO_TCP=true; shift ;;
    -U)
      DO_UDP=true; shift ;;
    -TU)
      DO_TCP=true; DO_UDP=true; shift ;;
    -o|--output)
      OUTFILE="$2"; shift 2 ;;
    -s|--scilence)
      SCILENT=true; shift ;;
    -h|--help)
      print_help; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      print_help
      exit 2 ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "error: target is required (-t | --target)." >&2
  exit 2
fi

# default behavior: if neither specified, default to TCP (common expectation)
if ! $DO_TCP && ! $DO_UDP; then
  DO_TCP=true
fi

# temp files
TMPDIR="$(mktemp -d /tmp/portscan.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT
MASSCAN_RAW="$TMPDIR/masscan_raw.txt"
NMAP_RAW="$TMPDIR/nmap_raw.txt"
AGG_RAW="$TMPDIR/agg_ports.txt"

# helpers
log_err() { printf "%s\n" "$*" >&2; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# parse masscan raw output lines like:
#   Discovered open port 1194/tcp on 198.51.100.10
# produce port/proto lines in $1 (file)
parse_masscan() {
  local infile="$1"; local outfile="$2"
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) {
        print $i
      }
    }
  }' "$infile" 2>/dev/null | tr -d '\r' | sort -V -u > "$outfile" || true
}

# parse nmap normal output lines like:
# 22/tcp   open   ssh
# 53/udp   open   domain
parse_nmap() {
  local infile="$1"; local outfile="$2"
  grep -E '^[0-9]+/(tcp|udp)' "$infile" 2>/dev/null | awk '{print $1}' | tr -d '\r' | sort -V -u > "$outfile" || true
}

# run masscan for given proto(s)
# args: <proto> where proto is "tcp", "udp", or "both"
run_masscan() {
  local proto="$1"
  local p_arg
  if [ "$proto" = "both" ]; then
    p_arg="-p${MASSCAN_PORTS},U:${MASSCAN_PORTS}"
  elif [ "$proto" = "udp" ]; then
    p_arg="-pU:${MASSCAN_PORTS}"
  else
    p_arg="-p${MASSCAN_PORTS}"
  fi
  log_err "running masscan on ${TARGET} (proto=${proto}) ..."
  # prefer sudo for masscan because it often needs raw sockets
  if has_cmd masscan; then
    if [ "$EUID" -ne 0 ]; then
      # run with sudo; if sudo not available or fails, masscan will probably fail but we attempt
      sudo masscan ${p_arg} --rate="${MASSCAN_RATE}" "${TARGET}" 2>&1 | tee "$MASSCAN_RAW" || true
    else
      masscan ${p_arg} --rate="${MASSCAN_RATE}" "${TARGET}" 2>&1 | tee "$MASSCAN_RAW" || true
    fi
  else
    log_err "masscan not found; skipping masscan"
    : > "$MASSCAN_RAW"
  fi
}

# run nmap (we run -oN to capture nice normal output)
run_nmap() {
  local nmap_opts=()
  if $DO_TCP; then nmap_opts+=("-sT"); fi
  if $DO_UDP; then nmap_opts+=("-sU"); fi
  # skip host discovery to speed things up by default (user can change code if desired)
  nmap_opts+=("-Pn")
  log_err "running nmap on ${TARGET} (opts: ${nmap_opts[*]}) ..."
  if has_cmd nmap; then
    # capture normal output to file (nmap returns non-zero for some UDP cases; ignore exit code)
    nmap "${nmap_opts[@]}" "${TARGET}" -oN "$NMAP_RAW" >/dev/null 2>&1 || true
  else
    log_err "nmap not found; skipping nmap"
    : > "$NMAP_RAW"
  fi
}

# MAIN: choose scanning strategy
# Use masscan for TCP if available (fast). Use nmap for UDP by default.
# If user asked for both and masscan exists, we run masscan both; also run nmap to improve UDP detection if desired.
MASSCAN_AVAILABLE=false
if has_cmd masscan; then MASSCAN_AVAILABLE=true; fi

# Run scans conditionally
# For TCP:
if $DO_TCP; then
  if $MASSCAN_AVAILABLE; then
    # run masscan tcp
    run_masscan "tcp"
    parse_masscan "$MASSCAN_RAW" "$TMPDIR/masscan_tcp.txt"
  else
    # fallback to nmap for tcp
    run_nmap
    parse_nmap "$NMAP_RAW" "$TMPDIR/nmap_tcp.txt"
  fi
fi

# For UDP:
if $DO_UDP; then
  # prefer nmap for UDP unless masscan present and we want to use it
  if $MASSCAN_AVAILABLE; then
    # masscan udp requires root; attempt it but also run nmap for better accuracy
    run_masscan "udp"
    parse_masscan "$MASSCAN_RAW" "$TMPDIR/masscan_udp.txt"
    # also run nmap for UDP overlap (nmap may give more accurate service detection)
    run_nmap
    parse_nmap "$NMAP_RAW" "$TMPDIR/nmap_udp.txt"
  else
    # use nmap only
    run_nmap
    parse_nmap "$NMAP_RAW" "$TMPDIR/nmap_udp.txt"
  fi
fi

# Collect parsed results into AGG_RAW, normalize so all lines are like "port/tcp" or "port/udp"
: > "$AGG_RAW"
# from masscan tcp
if [ -f "$TMPDIR/masscan_tcp.txt" ] && [ -s "$TMPDIR/masscan_tcp.txt" ]; then
  awk -F'/' '{print $1 "/tcp"}' "$TMPDIR/masscan_tcp.txt" >> "$AGG_RAW"
fi
# from masscan udp
if [ -f "$TMPDIR/masscan_udp.txt" ] && [ -s "$TMPDIR/masscan_udp.txt" ]; then
  awk -F'/' '{print $1 "/udp"}' "$TMPDIR/masscan_udp.txt" >> "$AGG_RAW"
fi
# from nmap tcp
if [ -f "$TMPDIR/nmap_tcp.txt" ] && [ -s "$TMPDIR/nmap_tcp.txt" ]; then
  awk -F'/' '{print $1 "/tcp"}' "$TMPDIR/nmap_tcp.txt" >> "$AGG_RAW"
fi
# from nmap udp
if [ -f "$TMPDIR/nmap_udp.txt" ] && [ -s "$TMPDIR/nmap_udp.txt" ]; then
  awk -F'/' '{print $1 "/udp"}' "$TMPDIR/nmap_udp.txt" >> "$AGG_RAW"
fi
# from parsed nmap (if earlier used only nmap without separate tcp/udp files)
if [ -f "$NMAP_RAW" ] && [ -s "$NMAP_RAW" ]; then
  # ensure we don't double-add: extract lines starting with digits/(tcp|udp) and append
  grep -E '^[0-9]+/(tcp|udp)' "$NMAP_RAW" 2>/dev/null | awk '{print $1}' >> "$AGG_RAW" || true
fi
# from parsed masscan raw (catch any leftover)
if [ -f "$MASSCAN_RAW" ] && [ -s "$MASSCAN_RAW" ]; then
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) print $i
    }
  }' "$MASSCAN_RAW" 2>/dev/null | tr -d '\r' >> "$AGG_RAW" || true
fi

# finalize: sort version-aware and unique, ensure format is port/proto
if [ -s "$AGG_RAW" ]; then
  # normalize any stray whitespace and blanks, then sort unique
  awk '{$1=$1; print}' "$AGG_RAW" | grep -E '^[0-9]+/(tcp|udp)$' | sort -V -u > "$TMPDIR/final_ports.txt" || true
else
  # empty result
  : > "$TMPDIR/final_ports.txt"
fi

# write to outfile if requested
if [ -n "$OUTFILE" ]; then
  cp "$TMPDIR/final_ports.txt" "$OUTFILE"
  log_err "final ports written to: $OUTFILE"
fi

# print to stdout unless scilent
if [ "$SCILENT" = false ]; then
  if [ -s "$TMPDIR/final_ports.txt" ]; then
    cat "$TMPDIR/final_ports.txt"
  else
    log_err "No open ports found (or none parsed)."
  fi
fi

exit 0
