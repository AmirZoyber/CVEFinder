#!/usr/bin/env bash
# port-scanner.sh - unified wrapper around masscan/nmap with -p, --port-scan, --service-scan
# Usage examples:
#  sudo ./port-scanner.sh -t 198.51.100.0/24 -T
#  ./port-scanner.sh -t example.com -U -o ports.txt
#  sudo ./port-scanner.sh -t 1.2.3.4 -TU --scilence
#  ./port-scanner.sh -t 1.2.3.4 -p 22,80,443 --service-scan
#  sudo ./port-scanner.sh -t 1.2.3.4 --port-scan    # acts like -TU if no -T/-U/-TU

set -euo pipefail

# defaults
TARGET=""
DO_TCP=false
DO_UDP=false
OUTFILE=""
SCILENT=false
MASSCAN_PORTS="1-65535"   # default if no -p provided
MASSCAN_RATE="10000"

# new flags
PORTS_SPEC=""            # user-specified -p (if empty -> scan all ports)
PORT_SCAN_FLAG=false    # --port-scan
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
  --service-scan           Performs port scan then nmap -sV service enumeration.
                           If -p/--ports is omitted, defaults to scanning all ports (1-65535).
                           Must NOT be combined with --port-scan or -T/-U/-TU.
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

# If user provided -p, use it; otherwise keep default MASSCAN_PORTS ("1-65535")
if [ -n "$PORTS_SPEC" ]; then
  MASSCAN_PORTS="$PORTS_SPEC"
fi

# service-scan rules:
# - must NOT be used with --port-scan or explicit -T/-U/-TU (we require a clean run: service-scan controls flow)
if $SERVICE_SCAN_FLAG; then
  if $PORT_SCAN_FLAG || $DO_TCP || $DO_UDP; then
    echo "error: --service-scan must not be combined with --port-scan or -T/-U/-TU. Use only -t (target) and optionally -p." >&2
    exit 2
  fi
  # For service-scan we always probe both protocols
  DO_TCP=true
  DO_UDP=true
  # If PORTS_SPEC empty, MASSCAN_PORTS remains "1-65535" so we'll scan all ports
  if [ -z "$PORTS_SPEC" ]; then
    log_err() { printf "%s\n" "$*" >&2; } # ensure log_err available
    log_err "note: --service-scan used without -p; defaulting to all ports (${MASSCAN_PORTS})."
  fi
fi

# if neither specified, default to TCP (common expectation)
if ! $DO_TCP && ! $DO_UDP; then
  DO_TCP=true
fi

# temp files
TMPDIR="$(mktemp -d /tmp/portscan.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT
# we'll use per-proto raw files to avoid overwrites
MASSCAN_RAW_TCP="$TMPDIR/masscan_tcp.raw"
MASSCAN_RAW_UDP="$TMPDIR/masscan_udp.raw"
NMAP_RAW_TCP="$TMPDIR/nmap_tcp.raw"
NMAP_RAW_UDP="$TMPDIR/nmap_udp.raw"
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
  }' "$infile" 2>/dev/null | tr -d '\r' | sed 's/^ *//;s/ *$//' | sort -V -u > "$outfile" || true
}

# parse nmap normal output lines like:
# 22/tcp   open   ssh
# gather port/proto (allow leading whitespace)
parse_nmap() {
  local infile="$1"; local outfile="$2"
  grep -E '^[[:space:]]*[0-9]+/(tcp|udp)' "$infile" 2>/dev/null | awk '{gsub(/^[ \t]+/,"",$0); print $1}' | tr -d '\r' | sort -V -u > "$outfile" || true
}

# parse nmap -sV output to get services lines (allow leading whitespace)
parse_nmap_services() {
  local infile="$1"; local outfile="$2"
  awk '/^[[:space:]]*[0-9]+\/(tcp|udp)/ {
    # remove leading whitespace
    sub(/^[ \t]+/,"");
    proto=$1;
    service=$3;
    banner="";
    for(i=4;i<=NF;i++){ banner=banner" "$i }
    gsub(/^ +| +$/,"",banner)
    printf "%s -> %s%s\n", proto, service, (banner ? " " banner : "")
  }' "$infile" 2>/dev/null | tr -d '\r' | sort -V -u > "$outfile" || true
}

# run masscan for given proto(s) and write to proto-specific file
run_masscan() {
  local proto="$1"
  local out="$2"
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
      sudo masscan ${p_arg} --rate="${MASSCAN_RATE}" "${TARGET}" 2>&1 | tee "${out}" || true
    else
      masscan ${p_arg} --rate="${MASSCAN_RATE}" "${TARGET}" 2>&1 | tee "${out}" || true
    fi
  else
    log_err "masscan not found; skipping masscan"
    : > "${out}"
  fi
}

# run nmap (writes to the provided outfile)
run_nmap() {
  local -n nmap_opts_ref=$1
  local outfile="$2"
  log_err "running nmap on ${TARGET} (opts: ${nmap_opts_ref[*]}) ..."
  if has_cmd nmap; then
    nmap "${nmap_opts_ref[@]}" "${TARGET}" -oN "${outfile}" >/dev/null 2>&1 || true
  else
    log_err "nmap not found; skipping nmap"
    : > "${outfile}"
  fi
}

# run nmap -sV against lists of ports
run_service_nmap() {
  local tcp_ports="$1"
  local udp_ports="$2"
  local tmpsvc="$SERVICES_RAW"
  : > "$tmpsvc"
  if [ -n "$tcp_ports" ] && [ "$tcp_ports" != "-" ]; then
    log_err "running nmap -sV (TCP) on ${TARGET} ports=${tcp_ports} ..."
    if has_cmd nmap; then
      nmap -Pn -sV -p "${tcp_ports}" "${TARGET}" -oN "$TMPDIR/nmap_sV_tcp.txt" >/dev/null 2>&1 || true
      parse_nmap_services "$TMPDIR/nmap_sV_tcp.txt" "$TMPDIR/nmap_sV_tcp_parsed.txt"
      if [ -s "$TMPDIR/nmap_sV_tcp_parsed.txt" ]; then
        cat "$TMPDIR/nmap_sV_tcp_parsed.txt" >> "$tmpsvc" || true
      fi
    fi
  fi
  if [ -n "$udp_ports" ] && [ "$udp_ports" != "-" ]; then
    log_err "running nmap -sU -sV (UDP) on ${TARGET} ports=${udp_ports} ... (may require root)"
    if has_cmd nmap; then
      if [ "$EUID" -ne 0 ]; then
        sudo nmap -Pn -sU -sV -p "${udp_ports}" "${TARGET}" -oN "$TMPDIR/nmap_sV_udp.txt" >/dev/null 2>&1 || true
      else
        nmap -Pn -sU -sV -p "${udp_ports}" "${TARGET}" -oN "$TMPDIR/nmap_sV_udp.txt" >/dev/null 2>&1 || true
      fi
      parse_nmap_services "$TMPDIR/nmap_sV_udp.txt" "$TMPDIR/nmap_sV_udp_parsed.txt"
      if [ -s "$TMPDIR/nmap_sV_udp_parsed.txt" ]; then
        cat "$TMPDIR/nmap_sV_udp_parsed.txt" >> "$tmpsvc" || true
      fi
    fi
  fi
  if [ -s "$tmpsvc" ]; then
    sort -V -u "$tmpsvc" > "$SERVICES_RAW"
  else
    : > "$SERVICES_RAW"
  fi
}

# MAIN
MASSCAN_AVAILABLE=false
if has_cmd masscan; then MASSCAN_AVAILABLE=true; fi

: > "$AGG_RAW"
: > "$SERVICES_RAW"

# For TCP:
if $DO_TCP; then
  if $MASSCAN_AVAILABLE; then
    run_masscan "tcp" "$MASSCAN_RAW_TCP"
    parse_masscan "$MASSCAN_RAW_TCP" "$TMPDIR/masscan_tcp.txt"
  else
    nmap_opts_tcp=()
    nmap_opts_tcp+=("-sT")
    nmap_opts_tcp+=("-Pn")
    if [ -n "$PORTS_SPEC" ]; then
      nmap_opts_tcp+=("-p" "${PORTS_SPEC}")
    fi
    run_nmap nmap_opts_tcp "$NMAP_RAW_TCP"
    parse_nmap "$NMAP_RAW_TCP" "$TMPDIR/nmap_tcp.txt"
  fi
fi

# For UDP:
if $DO_UDP; then
  if $MASSCAN_AVAILABLE; then
    run_masscan "udp" "$MASSCAN_RAW_UDP"
    parse_masscan "$MASSCAN_RAW_UDP" "$TMPDIR/masscan_udp.txt"
    # run nmap UDP scan to supplement masscan (may be slow)
    nmap_opts_udp=()
    nmap_opts_udp+=("-sU")
    nmap_opts_udp+=("-Pn")
    if [ -n "$PORTS_SPEC" ]; then
      nmap_opts_udp+=("-p" "${PORTS_SPEC}")
    fi
    run_nmap nmap_opts_udp "$NMAP_RAW_UDP"
    parse_nmap "$NMAP_RAW_UDP" "$TMPDIR/nmap_udp.txt"
  else
    nmap_opts_udp=()
    nmap_opts_udp+=("-sU")
    nmap_opts_udp+=("-Pn")
    if [ -n "$PORTS_SPEC" ]; then
      nmap_opts_udp+=("-p" "${PORTS_SPEC}")
    fi
    run_nmap nmap_opts_udp "$NMAP_RAW_UDP"
    parse_nmap "$NMAP_RAW_UDP" "$TMPDIR/nmap_udp.txt"
  fi
fi

# Aggregate parsed results
if [ -f "$TMPDIR/masscan_tcp.txt" ] && [ -s "$TMPDIR/masscan_tcp.txt" ]; then
  awk -F'/' '{print $1 "/tcp"}' "$TMPDIR/masscan_tcp.txt" >> "$AGG_RAW"
fi
if [ -f "$TMPDIR/masscan_udp.txt" ] && [ -s "$TMPDIR/masscan_udp.txt" ]; then
  awk -F'/' '{print $1 "/udp"}' "$TMPDIR/masscan_udp.txt" >> "$AGG_RAW"
fi
if [ -f "$TMPDIR/nmap_tcp.txt" ] && [ -s "$TMPDIR/nmap_tcp.txt" ]; then
  awk -F'/' '{print $1 "/tcp"}' "$TMPDIR/nmap_tcp.txt" >> "$AGG_RAW"
fi
if [ -f "$TMPDIR/nmap_udp.txt" ] && [ -s "$TMPDIR/nmap_udp.txt" ]; then
  awk -F'/' '{print $1 "/udp"}' "$TMPDIR/nmap_udp.txt" >> "$AGG_RAW"
fi
# also include any direct nmap raw lines from per-run files
if [ -f "$NMAP_RAW_TCP" ] && [ -s "$NMAP_RAW_TCP" ]; then
  grep -E '^[[:space:]]*[0-9]+/(tcp|udp)' "$NMAP_RAW_TCP" 2>/dev/null | awk '{gsub(/^[ \t]+/,"",$0); print $1}' >> "$AGG_RAW" || true
fi
if [ -f "$NMAP_RAW_UDP" ] && [ -s "$NMAP_RAW_UDP" ]; then
  grep -E '^[[:space:]]*[0-9]+/(tcp|udp)' "$NMAP_RAW_UDP" 2>/dev/null | awk '{gsub(/^[ \t]+/,"",$0); print $1}' >> "$AGG_RAW" || true
fi
# include masscan raw lines too
if [ -f "$MASSCAN_RAW_TCP" ] && [ -s "$MASSCAN_RAW_TCP" ]; then
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) print $i
    }
  }' "$MASSCAN_RAW_TCP" 2>/dev/null | tr -d '\r' >> "$AGG_RAW" || true
fi
if [ -f "$MASSCAN_RAW_UDP" ] && [ -s "$MASSCAN_RAW_UDP" ]; then
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /\/(tcp|udp)$/) print $i
    }
  }' "$MASSCAN_RAW_UDP" 2>/dev/null | tr -d '\r' >> "$AGG_RAW" || true
fi

# finalize ports list
if [ -s "$AGG_RAW" ]; then
  awk '{$1=$1; print}' "$AGG_RAW" | grep -E '^[0-9]+/(tcp|udp)$' | sort -V -u > "$TMPDIR/final_ports.txt" || true
else
  : > "$TMPDIR/final_ports.txt"
fi

# If service-scan, run nmap -sV against discovered ports or against the full requested range (default all ports)
if $SERVICE_SCAN_FLAG; then
  tcp_list=$(grep '/tcp$' "$TMPDIR/final_ports.txt" | awk -F'/' '{print $1}' | paste -sd, - || true)
  udp_list=$(grep '/udp$' "$TMPDIR/final_ports.txt" | awk -F'/' '{print $1}' | paste -sd, - || true)

  # If nothing discovered, probe the user-specified ports or default full range (MASSCAN_PORTS)
  if [ -z "$tcp_list" ]; then
    tcp_list="${PORTS_SPEC:-$MASSCAN_PORTS}"
  fi
  if [ -z "$udp_list" ]; then
    udp_list="${PORTS_SPEC:-$MASSCAN_PORTS}"
  fi

  # normalize placeholder
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

# print service results if any
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
