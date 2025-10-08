#!/usr/bin/env bash
set -euo pipefail

# masscan_ports.sh
# Usage:
#   sudo ./masscan_ports.sh -t <target> [-p <port-range>] [-r <rate>] [-o <out-file>] [-T] [-U]
#
# Examples:
#   sudo ./masscan_ports.sh -t 198.51.100.0/24 -r 10000 -T        # TCP only
#   sudo ./masscan_ports.sh -t 198.51.100.0/24 -r 1000  -U      # UDP only
#   sudo ./masscan_ports.sh -t 198.51.100.0/24 -r 500  -T -U    # both (you can also pass -TU)
#
# Notes:
# - -t (lowercase) is target. -T (uppercase) selects TCP, -U selects UDP.
# - If neither -T nor -U is given, the script defaults to TCP only.
# - When scanning both protocols, the output file will contain protocol-qualified ports (e.g. 53/udp).
# - Only scan hosts/networks you are authorized to scan.

TARGET=""
PORTS="1-65535"
RATE="10000"
OUTFILE="open_ports.txt"
SCAN_TCP=false
SCAN_UDP=false

print_usage() {
  cat <<EOF
Usage: $0 -t <target> [-p <port-range>] [-r <rate>] [-o <out-file>] [-T] [-U]

  -t target       Target IP / CIDR / hostname (required)
  -p port-range   Port range (default: ${PORTS})
  -r rate         Masscan rate (default: ${RATE})
  -o out-file     File to write the extracted ports (default: ${OUTFILE})
  -T              Scan TCP (masscan default)
  -U              Scan UDP
                  Use -T -U (or -TU) to scan both protocols.

Examples:
  sudo $0 -t 198.51.100.0/24 -r 10000 -T
  sudo $0 -t 198.51.100.0/24 -r 1000  -U
  sudo $0 -t 198.51.100.0/24 -r 500  -T -U
EOF
}

# parse options; getopts is case-sensitive so -t and -T are different
while getopts "t:p:r:o:TUh" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    r) RATE="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    T) SCAN_TCP=true ;;
    U) SCAN_UDP=true ;;
    h) print_usage; exit 0 ;;
    *) print_usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: target (-t) is required."
  print_usage
  exit 2
fi

# default: if neither specified, default to TCP only (common expectation)
if ! $SCAN_TCP && ! $SCAN_UDP; then
  SCAN_TCP=true
fi

# build masscan -p argument
if $SCAN_TCP && $SCAN_UDP; then
  MASSCAN_P="-p${PORTS},U:${PORTS}"
  MODE="both"
elif $SCAN_UDP; then
  MASSCAN_P="-pU:${PORTS}"
  MODE="udp"
else
  MASSCAN_P="-p${PORTS}"
  MODE="tcp"
fi

# temp file to store raw output from masscan
TMPOUT="$(mktemp /tmp/masscan_raw.XXXXXX)"
trap 'rm -f "$TMPOUT"' EXIT

echo "Running masscan on target: $TARGET"
echo "Mode: $MODE"
echo "Ports: ${PORTS}  Rate: ${RATE}"
echo "Raw masscan output -> $TMPOUT"
echo

# Run masscan and tee raw output
# masscan usually needs root privileges
sudo masscan ${MASSCAN_P} --rate="${RATE}" "${TARGET}" 2>&1 | tee "$TMPOUT"

# Parse discovered lines.
# masscan prints lines like:
#   Discovered open port 1194/tcp on 198.51.100.10
# We'll extract port and proto. Behavior:
#  - If scanning only tcp or only udp -> output plain port numbers (one per line)
#  - If scanning both -> output port/proto (e.g. 1194/udp) so caller can distinguish
if [[ "$MODE" == "both" ]]; then
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) {
        print $i      # e.g. "1194/tcp"
      }
    }
  }' "$TMPOUT" | tr -d '\r' | sort -V -u > "$OUTFILE"
else
  # single-protocol: just output numeric ports
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) {
        split($i, a, "/");
        print a[1];
      }
    }
  }' "$TMPOUT" | tr -d '\r' | sort -n -u > "$OUTFILE"
fi

# Report results
if [[ -s "$OUTFILE" ]]; then
  echo
  echo "Saved unique open ports to: $OUTFILE"
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
  echo "No open ports found (no 'Discovered open port' lines parsed)."
  # ensure outfile exists (empty)
  : > "$OUTFILE"
fi
