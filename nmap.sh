#!/usr/bin/env bash
set -euo pipefail

# nmap_ports.sh
# Usage:
#   sudo ./nmap_ports.sh -t <target> [-p <ports>] [-o <out-file>] [-T] [-U] [-r <pps>] [-d <delay>]
#
# Options:
#   -t <target>     Target IP / CIDR / hostname (required)
#   -p <ports>      Port range (default: 1-65535)
#   -o <out-file>   File to write discovered ports (default: nmap_open_ports.txt)
#   -T              Scan TCP using -sT
#   -U              Scan UDP using -sU
#                   If neither -T nor -U provided, defaults to TCP (-T).
#   -r <pps>        Rate in packets-per-second: sets --min-rate <pps> --max-rate <pps>
#   -d <delay>      Delay between probes: sets --scan-delay <time> (e.g. 200ms, 1s)
# Examples:
#   sudo ./nmap_ports.sh -t 198.51.100.5 -T
#   sudo ./nmap_ports.sh -t 198.51.100.0/24 -U -p 53 -r 50
#   sudo ./nmap_ports.sh -t example.com -T -U -r 20 -d 200ms -o out.txt

TARGET=""
PORTS="1-65535"
OUTFILE="nmap_open_ports.txt"
SCAN_TCP=false
SCAN_UDP=false
RATE=""
DELAY=""

print_usage() {
  cat <<EOF
Usage: $0 -t <target> [-p <ports>] [-o <out-file>] [-T] [-U] [-r <pps>] [-d <delay>]

  -t target       (required) IP/CIDR/hostname
  -p ports        ports to scan (default: ${PORTS})
  -o out-file     output file (default: ${OUTFILE})
  -T              TCP scan (uses -sT)
  -U              UDP scan (uses -sU)
  -r pps          packets-per-second rate (sets --min-rate and --max-rate)
  -d delay        scan-delay between probes (e.g. 100ms, 1s) -> sets --scan-delay

Notes:
 - UDP scans are slow and unreliable at large scale. Prefer limiting ports when using -sU.
 - Use sudo for best results.
 - Example delay formats: 200ms, 1s, 500ms
EOF
}

while getopts "t:p:o:TUr:d:h" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    T) SCAN_TCP=true ;;
    U) SCAN_UDP=true ;;
    r) RATE="$OPTARG" ;;
    d) DELAY="$OPTARG" ;;
    h) print_usage; exit 0 ;;
    *) print_usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: target (-t) is required."
  print_usage
  exit 2
fi

# default to TCP if neither given
if ! $SCAN_TCP && ! $SCAN_UDP; then
  SCAN_TCP=true
fi

# build rate/delay options for nmap
RATE_OPTS=""
if [[ -n "$RATE" ]]; then
  # basic validation: RATE should be a positive integer
  if ! [[ "$RATE" =~ ^[0-9]+$ ]]; then
    echo "ERROR: rate (-r) must be a positive integer (packets per second)."
    exit 3
  fi
  RATE_OPTS="--min-rate ${RATE} --max-rate ${RATE}"
fi

DELAY_OPTS=""
if [[ -n "$DELAY" ]]; then
  # don't attempt to validate time format here too strictly; nmap accepts values like "200ms" or "1s"
  DELAY_OPTS="--scan-delay ${DELAY}"
fi

# temp file for nmap raw output
TMPOUT="$(mktemp /tmp/nmap_raw.XXXXXX)"
trap 'rm -f "$TMPOUT"' EXIT

echo "Target: $TARGET"
echo "Ports: $PORTS"
echo -n "Mode: "
if $SCAN_TCP && $SCAN_UDP; then MODE="both"; echo "both (TCP & UDP)"
elif $SCAN_UDP; then MODE="udp"; echo "UDP only"
else MODE="tcp"; echo "TCP only"; fi

if [[ -n "$RATE" ]]; then echo "Rate: ${RATE} pps (min/max rate)"; fi
if [[ -n "$DELAY" ]]; then echo "Delay: ${DELAY} (scan-delay)"; fi
echo "Raw nmap output -> $TMPOUT"
echo

# helper to run nmap and append to TMPOUT
# Using -sT for TCP, -sU for UDP. We include -Pn to avoid host discovery failure on firewalled hosts.
run_nmap() {
  local proto="$1"   # "tcp" or "udp"
  local scan_opts="$2"
  local label="$3"
  echo "=== Starting nmap $label scan ($proto) at $(date -u +"%Y-%m-%d %H:%M:%S UTC") ===" | tee -a "$TMPOUT"
  # Note: sudo is used to allow raw sockets where needed. Remove if you prefer non-privileged runs.
  sudo nmap -p "${PORTS}" ${scan_opts} "${TARGET}" -oN - 2>&1 | tee -a "$TMPOUT"
  echo "=== Finished nmap $label scan ($proto) at $(date -u +"%Y-%m-%d %H:%M:%S UTC") ===" | tee -a "$TMPOUT"
  echo >> "$TMPOUT"
}

# Build options for each proto
TCP_OPTS="-sT -Pn ${RATE_OPTS} ${DELAY_OPTS}"
UDP_OPTS="-sU -Pn ${RATE_OPTS} ${DELAY_OPTS}"

# Run scans
if $SCAN_TCP && $SCAN_UDP; then
  run_nmap "tcp" "${TCP_OPTS}" "TCP"
  run_nmap "udp" "${UDP_OPTS}" "UDP"
elif $SCAN_UDP; then
  run_nmap "udp" "${UDP_OPTS}" "UDP"
else
  run_nmap "tcp" "${TCP_OPTS}" "TCP"
fi

# Parse TMPOUT for open ports.
# nmap prints lines like:
#   80/tcp   open  http
#   53/udp   open  domain
# We'll extract fields that match "<port>/<proto>  open" (case-insensitive).
if [[ "$MODE" == "both" ]]; then
  # output port/proto (e.g. 53/udp)
  awk 'BEGIN{IGNORECASE=1}
    /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
      gsub(/\r/,"",$1);
      print $1
    }' "$TMPOUT" | sort -V -u > "$OUTFILE"
else
  # single protocol: output numeric ports only
  awk 'BEGIN{IGNORECASE=1}
    /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
      split($1,a,"/");
      print a[1]
    }' "$TMPOUT" | sort -n -u > "$OUTFILE"
fi

# Final report
if [[ -s "$OUTFILE" ]]; then
  echo
  echo "Saved discovered open ports to: $OUTFILE"
  echo "----"
  cat "$OUTFILE"
  echo "----"
  if [[ "$MODE" == "both" ]]; then
    echo "(format: port/protocol)"
  else
    echo "(format: port)"
  fi
else
  echo
  echo "No open ports found (no matching 'open' lines parsed in nmap output)."
  # ensure outfile exists (empty)
  : > "$OUTFILE"
fi
