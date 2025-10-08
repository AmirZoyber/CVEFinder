#!/usr/bin/env bash
# port-scanner.sh - unified wrapper around masscan/nmap with -p, --port-scan, --service-scan
# Usage examples:
#  sudo ./port-scanner.sh -t 198.51.100.0/24 -T
#  ./port-scanner.sh -t example.com -U -o ports.txt
#  sudo ./port-scanner.sh -t 1.2.3.4 -TU --scilence
#  ./port-scanner.sh -t 1.2.3.4 -p 22,80,443 --service-scan
#  sudo ./port-scanner.sh -t 1.2.3.4 --port-scan    # acts like -TU if no -T/-U/-TU
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
MASSCAN_PORTS="1-65535"
MASSCAN_RATE="10000"

# new flags
PORTS_SPEC=""          # user-specified -p
PORT_SCAN_FLAG=false   # --port-scan
SERVICE_SCAN_FLAG=false # --service-scan

print_help() {
  cat <<EOF
port-scanner.sh - prints open ports as "port/tcp" or "port/udp", sorted and unique

Options:
  -t, --target <target>    Target IP/CIDR/hostname (required)
  -T                       Scan TCP
  -U                       Scan UDP
  -TU                      Scan both TCP and UDP
  -p, --ports <ports>      Ports spec: single, comma list, or range e.g. 80  80,443  1-1024  80,443,8000-8100
  --port-scan              If present and no -T/-U/-TU provided, behave like -TU (scan both)
  --service-scan           Requires -p/--ports and must NOT be used with --port-scan or -T/-U/-TU.
                           Performs port scan for provided ports, then runs nmap -sV to enumerate services.
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
    -p|--ports)
      PORTS_SPEC="$2"; shift 2 ;;
    --port-scan)
      PORT_SCAN_FLAG=true; shift ;;
    --service-scan)
      SERVICE_SCAN_FLAG=true; shift ;;
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

# If --port-scan present and user didn't pass -T/-U/-TU explicitly, behave as -TU
if $PORT_SCAN_FLAG && ! $DO_TCP && ! $DO_UDP; then
  DO_TCP=true
  DO_UDP=true
fi

# service-scan rules:
# - requires -p
# - must NOT be used with --port-scan or explicit -T/-U/-TU (we require a clean run: service-scan controls flow)
if $SERVICE_SCAN_FLAG; then
  if [ -z "$PORTS_SPEC" ]; then
    echo "error: --service-scan requires -p|--ports to be specified." >&2
    exit 2
  fi
  # If user provided any explicit scan flags or port-scan, reject to avoid ambiguity
  if $PORT_SCAN_FLAG || $DO_TCP || $DO_UDP; then
    echo "error: --service-scan must not be combined with --port-scan or -T/-U/-TU. Use only -p and --service-scan." >&2
    exit 2
  fi
  # For service-scan, we'll scan both TCP & UDP ports in the provided spec
  DO_TCP=true
  DO_UDP=true
fi

# if neither specified, default to TCP (common expectation)
if ! $DO_TCP && ! $DO_UDP; then
  DO_TCP=true
fi

# if -p provided, override masscan default port range for the scan
if [ -n "$PORTS_SPEC" ]; then
  MASSCAN_PORTS="$PORTS_SPEC"
fi

# temp files
TMPDIR="$(mktemp -d /tmp/portscan.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT
MASSCAN_RAW="$TMPDIR/masscan_raw.txt"
NMAP_RAW="$TMPDIR/nmap_raw.txt"
AGG_RAW="$TMPDIR/agg_ports.txt"
SERVICES_RAW="$TMPDIR/services.txt"

# helpers
log_err() { printf "%s\n" "$*" >&2; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# parse masscan raw output lines like:
#   Discovered open port 1194/tcp on 198.51.100.10
# produce port/proto lines in $2 (outfile)
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
# gather port/proto
parse_nmap() {
  local infile="$1"; local outfile="$2"
  grep -E '^[0-9]+/(tcp|udp)' "$infile" 2>/dev/null | awk '{print $1}' | tr -d '\r' | sort -V -u > "$outfile" || true
}

# parse nmap -sV output to get services lines:
# e.g. "22/tcp open  ssh   OpenSSH 7.6p1" -> prints "22/tcp -> ssh OpenSSH 7.6p1"
parse_nmap_services() {
  local infile="$1"; local outfile="$2"
  # lines that start with port/proto
  awk '/^[0-9]+\/(tcp|udp)/ {
    proto=$1;
    # service is typically $3, banner is fields 4+
    service=$3;
    banner="";
    for(i=4;i<=NF;i++){ banner=banner" "$i }
    gsub(/^ +| +$/,"",banner)
    printf "%s -> %s%s\n", proto, service, (banner ? " " banner : "")
  }' "$infile" 2>/dev/null | tr -d '\r' | sort -V -u > "$outfile" || true
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
  log_err "running masscan on ${TARGET} (proto=${proto}) ports=${MASSCAN_PORTS} ..."
  if has_cmd masscan; then
    if [ "$EUID" -ne 0 ]; then
      sudo masscan ${p_arg} --rate="${MASSCAN_RATE}" "${TARGET}" 2>&1 | tee "$MASSCAN_RAW" || true
    else
      masscan ${p_arg} --rate="${MASSCAN_RATE}" "${TARGET}" 2>&1 | tee "$MASSCAN_RAW" || true
    fi
  else
    log_err "masscan not found; skipping masscan"
    : > "$MASSCAN_RAW"
  fi
}

# run nmap (we run -oN to capture normal output)
# nmap_opts constructed by caller
run_nmap() {
  local -n nmap_opts_ref=$1
  log_err "running nmap on ${TARGET} (opts: ${nmap_opts_ref[*]}) ..."
  if has_cmd nmap; then
    # capture normal output to file (nmap returns non-zero for some UDP cases; ignore exit code)
    nmap "${nmap_opts_ref[@]}" "${TARGET}" -oN "$NMAP_RAW" >/dev/null 2>&1 || true
  else
    log_err "nmap not found; skipping nmap"
    : > "$NMAP_RAW"
  fi
}

# run nmap -sV against a list of ports (tcp and/or udp)
# args: tcp_ports_string, udp_ports_string  (comma separated lists or empty)
run_service_nmap() {
  local tcp_ports="$1"
  local udp_ports="$2"
  local tmpsvc="$SERVICES_RAW"
  : > "$tmpsvc"
  if [ -n "$tcp_ports" ] && [ "$tcp_ports" != "-" ]; then
    log_err "running nmap -sV (TCP) on ${TARGET} ports=${tcp_ports} ..."
    # -Pn skip host discovery, -sV service/version, -p ports
    if has_cmd nmap; then
      nmap -Pn -sV -p "${tcp_ports}" "${TARGET}" -oN "$TMPDIR/nmap_sV_tcp.txt" >/dev/null 2>&1 || true
      parse_nmap_services "$TMPDIR/nmap_sV_tcp.txt" "$TMPDIR/nmap_sV_tcp_parsed.txt"
      cat "$TMPDIR/nmap_sV_tcp_parsed.txt" >> "$tmpsvc" || true
    fi
  fi
  if [ -n "$udp_ports" ] && [ "$udp_ports" != "-" ]; then
    log_err "running nmap -sU -sV (UDP) on ${TARGET} ports=${udp_ports} ... (UDP scans may be slow and require root)"
    if has_cmd nmap; then
      # UDP may require root; if not root, nmap may fall back but could be less effective
      if [ "$EUID" -ne 0 ]; then
        # try sudo for UDP service scan
        sudo nmap -Pn -sU -sV -p "${udp_ports}" "${TARGET}" -oN "$TMPDIR/nmap_sV_udp.txt" >/dev/null 2>&1 || true
      else
        nmap -Pn -sU -sV -p "${udp_ports}" "${TARGET}" -oN "$TMPDIR/nmap_sV_udp.txt" >/dev/null 2>&1 || true
      fi
      parse_nmap_services "$TMPDIR/nmap_sV_udp.txt" "$TMPDIR/nmap_sV_udp_parsed.txt"
      cat "$TMPDIR/nmap_sV_udp_parsed.txt" >> "$tmpsvc" || true
    fi
  fi
  # normalize and unique services
  if [ -s "$tmpsvc" ]; then
    sort -V -u "$tmpsvc" > "$SERVICES_RAW"
  else
    : > "$SERVICES_RAW"
  fi
}

# MAIN: choose scanning strategy
MASSCAN_AVAILABLE=false
if has_cmd masscan; then MASSCAN_AVAILABLE=true; fi

# Run scans conditionally
# We'll create per-source parsed files in TMPDIR and then aggregate

# Reset intermediate parsed files
: > "$AGG_RAW"
: > "$SERVICES_RAW"

# For TCP:
if $DO_TCP; then
  if $MASSCAN_AVAILABLE; then
    run_masscan "tcp"
    parse_masscan "$MASSCAN_RAW" "$TMPDIR/masscan_tcp.txt"
  else
    # fallback to nmap for tcp
    # run nmap just to get ports (no -sV here unless service-scan later)
    nmap_opts_tcp=()
    nmap_opts_tcp+=("-sT")
    nmap_opts_tcp+=("-Pn")
    if [ -n "$PORTS_SPEC" ]; then
      nmap_opts_tcp+=("-p" "${PORTS_SPEC}")
    fi
    run_nmap nmap_opts_tcp
    parse_nmap "$NMAP_RAW" "$TMPDIR/nmap_tcp.txt"
  fi
fi

# For UDP:
if $DO_UDP; then
  if $MASSCAN_AVAILABLE; then
    # try masscan udp then also run nmap for UDP accuracy
    run_masscan "udp"
    parse_masscan "$MASSCAN_RAW" "$TMPDIR/masscan_udp.txt"
    # nmap UDP probe (no -sV, except when service-scan will later run -sU -sV)
    nmap_opts_udp=()
    nmap_opts_udp+=("-sU")
    nmap_opts_udp+=("-Pn")
    if [ -n "$PORTS_SPEC" ]; then
      nmap_opts_udp+=("-p" "${PORTS_SPEC}")
    fi
    run_nmap nmap_opts_udp
    parse_nmap "$NMAP_RAW" "$TMPDIR/nmap_udp.txt"
  else
    # use nmap only for udp
    nmap_opts_udp=()
    nmap_opts_udp+=("-sU")
    nmap_opts_udp+=("-Pn")
    if [ -n "$PORTS_SPEC" ]; then
      nmap_opts_udp+=("-p" "${PORTS_SPEC}")
    fi
    run_nmap nmap_opts_udp
    parse_nmap "$NMAP_RAW" "$TMPDIR/nmap_udp.txt"
  fi
fi

# Collect parsed results into AGG_RAW, normalize so all lines are like "port/tcp" or "port/udp"
# masscan tcp
if [ -f "$TMPDIR/masscan_tcp.txt" ] && [ -s "$TMPDIR/masscan_tcp.txt" ]; then
  awk -F'/' '{print $1 "/tcp"}' "$TMPDIR/masscan_tcp.txt" >> "$AGG_RAW"
fi
# masscan udp
if [ -f "$TMPDIR/masscan_udp.txt" ] && [ -s "$TMPDIR/masscan_udp.txt" ]; then
  awk -F'/' '{print $1 "/udp"}' "$TMPDIR/masscan_udp.txt" >> "$AGG_RAW"
fi
# nmap tcp
if [ -f "$TMPDIR/nmap_tcp.txt" ] && [ -s "$TMPDIR/nmap_tcp.txt" ]; then
  awk -F'/' '{print $1 "/tcp"}' "$TMPDIR/nmap_tcp.txt" >> "$AGG_RAW"
fi
# nmap udp
if [ -f "$TMPDIR/nmap_udp.txt" ] && [ -s "$TMPDIR/nmap_udp.txt" ]; then
  awk -F'/' '{print $1 "/udp"}' "$TMPDIR/nmap_udp.txt" >> "$AGG_RAW"
fi
# from final raw nmap if any leftover
if [ -f "$NMAP_RAW" ] && [ -s "$NMAP_RAW" ]; then
  grep -E '^[0-9]+/(tcp|udp)' "$NMAP_RAW" 2>/dev/null | awk '{print $1}' >> "$AGG_RAW" || true
fi
# masscan raw leftover
if [ -f "$MASSCAN_RAW" ] && [ -s "$MASSCAN_RAW" ]; then
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) print $i
    }
  }' "$MASSCAN_RAW" 2>/dev/null | tr -d '\r' >> "$AGG_RAW" || true
fi

# finalize: sort version-aware and unique, ensure format is port/proto
if [ -s "$AGG_RAW" ]; then
  awk '{$1=$1; print}' "$AGG_RAW" | grep -E '^[0-9]+/(tcp|udp)$' | sort -V -u > "$TMPDIR/final_ports.txt" || true
else
  : > "$TMPDIR/final_ports.txt"
fi

# If --service-scan was requested, run nmap -sV against discovered ports (but only on the ports user specified -p)
if $SERVICE_SCAN_FLAG; then
  # Build comma-separated lists for tcp and udp from final_ports.txt but constrained to the ports user asked (-p)
  # We will accept the discovered ports (so user can have asked 1-100 but only some discovered)
  tcp_list=$(grep '/tcp$' "$TMPDIR/final_ports.txt" | awk -F'/' '{print $1}' | paste -sd, - || true)
  udp_list=$(grep '/udp$' "$TMPDIR/final_ports.txt" | awk -F'/' '{print $1}' | paste -sd, - || true)

  # If no ports discovered, still try to probe the user-supplied ports (they may be filtered but we try)
  if [ -z "$tcp_list" ]; then
    # try to use user-specified ports for probe (only tcp portion)
    # extract tcp members from PORTS_SPEC if possible (we'll just pass the whole PORTS_SPEC to nmap tcp probe)
    # But first convert U: or other masscan syntax - assume user used normal syntax: we'll use PORTS_SPEC for tcp probe
    tcp_list="$PORTS_SPEC"
  fi
  if [ -z "$udp_list" ]; then
    udp_list="$PORTS_SPEC"
  fi

  # normalize placeholders
  if [ -z "$tcp_list" ]; then tcp_list="-" ; fi
  if [ -z "$udp_list" ]; then udp_list="-" ; fi

  run_service_nmap "$tcp_list" "$udp_list"
fi

# write to outfile if requested
if [ -n "$OUTFILE" ]; then
  cp "$TMPDIR/final_ports.txt" "$OUTFILE"
  log_err "final ports written to: $OUTFILE"
fi

# print ports to stdout unless scilent
if [ "$SCILENT" = false ]; then
  if [ -s "$TMPDIR/final_ports.txt" ]; then
    echo "==== Open ports (port/proto) ===="
    cat "$TMPDIR/final_ports.txt"
  else
    log_err "No open ports found (or none parsed)."
  fi
fi

# If service-scan ran, print service results
if $SERVICE_SCAN_FLAG; then
  if [ -s "$SERVICES_RAW" ]; then
    echo
    echo "==== Services discovered (port/proto -> service + banner) ===="
    cat "$SERVICES_RAW"
  else
    echo
    log_err "No services discovered (nmap -sV returned nothing or not installed)."
  fi
fi

exit 0
