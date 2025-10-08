#!/usr/bin/env bash
set -euo pipefail

# masscan_ports.sh
# Usage: ./masscan_ports.sh -t <target> [-p <port-range>] [-r <rate>] [-o <out-file>]
# Example:
#   sudo ./masscan_ports.sh -t 198.51.100.0/24 -r 10000 -o open_ports.txt

TARGET=""
PORTS="1-65535"
RATE="10000"
OUTFILE="open_ports.txt"

print_usage() {
  cat <<EOF
Usage: $0 -t <target> [-p <port-range>] [-r <rate>] [-o <out-file>]

  -t target       Target IP / CIDR / hostname (required)
  -p port-range   Port range for masscan (default: ${PORTS})
  -r rate         Rate for masscan (default: ${RATE})
  -o out-file     File to write the extracted ports (default: ${OUTFILE})

Example:
  sudo $0 -t 198.51.100.0/24 -r 10000 -o open_ports.txt
EOF
}

while getopts "t:p:r:o:h" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    p) PORTS="$OPTARG" ;;
    r) RATE="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    h) print_usage; exit 0 ;;
    *) print_usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "ERROR: target is required."
  print_usage
  exit 2
fi

# temp file to store raw output from masscan
TMPOUT="$(mktemp /tmp/masscan_raw.XXXXXX)"
trap 'rm -f "$TMPOUT"' EXIT

echo "Running masscan on target: $TARGET (ports: $PORTS, rate: $RATE)"
echo "Raw masscan output -> $TMPOUT"
echo

# Run masscan, capture both stdout and stderr
# NOTE: masscan typically needs root (sudo)
sudo masscan -p${PORTS} --rate=${RATE} "${TARGET}" 2>&1 | tee "$TMPOUT"

# Extract port numbers from "Discovered open port X/tcp on IP" lines
# Support lines containing /tcp or /udp. Print one port per line.
awk '
/[Dd]iscovered open port/ {
  for (i=1;i<=NF;i++) {
    if ($i ~ /\/(tcp|udp)$/) {
      split($i, a, "/");
      print a[1];
    }
  }
}
' "$TMPOUT" | sort -n -u > "$OUTFILE"

# Report results
if [[ -s "$OUTFILE" ]]; then
  echo
  echo "Saved unique open ports to: $OUTFILE"
  echo "Ports:"
  cat "$OUTFILE"
else
  echo
  echo "No open ports found (no 'Discovered open port' lines parsed)."
  # Ensure empty outfile exists (overwrite)
  : > "$OUTFILE"
fi
