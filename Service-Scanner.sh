#!/usr/bin/env bash
# service-scanner.sh - masscan/nmap wrapper with per-port nmap -sV enumeration
# The script sources ./config.conf for all static variables.
set -euo pipefail

# -----------------------
# Load config
# -----------------------
CONFIGFILE="./config.conf"
if [ ! -f "$CONFIGFILE" ]; then
  echo "[!] Missing config file: $CONFIGFILE"
  echo "    Copy the provided config.conf into the script directory and edit as needed."
  exit 1
fi
# shellcheck source=/dev/null
. "$CONFIGFILE"

# -----------------------
# Validate expected config variables exist (fail early if missing)
# -----------------------
_required_vars=(TARGET DO_TCP DO_UDP OUTFILE SCILENT KEEP_TMP DEBUG RATE PORTS_SPEC PORT_SCAN_FLAG SERVICE_SCAN_FLAG MASSCAN_FIRST WEBANALYZE_APP_JSON RUN_WEBANALYZE_ALWAYS PORTS_TCP PORTS_UDP)
_missing=()
for v in "${_required_vars[@]}"; do
  if ! eval "[ \"\${${v}+defined}\" ]"; then
    _missing+=("$v")
  fi
done
if [ "${#_missing[@]}" -ne 0 ]; then
  echo "[!] The following config variables are missing in $CONFIGFILE:"
  for m in "${_missing[@]}"; do echo "    - $m"; done
  exit 2
fi
unset _required_vars _missing m v

# -----------------------
# Helpers
# -----------------------
log()     { printf "%s\n" "$*" >&2; }
die()     { log "[ERROR] $*"; exit 1; }
#check_installed() { command -v "$1" >/dev/null 2>&1; }

# check if app is installed
check_installed() {
    local app="$1"
    if which "$app" >/dev/null 2>&1; then
        return 0    # true
    else
        return 1    # false
    fi
}


print_help() {
  cat <<'EOF'
  service-scanner.sh - Port discovery + per-port service enumeration with nmap

  Usage: ./service-scanner.sh -t <target> [options]

  Options (CLI overrides config.conf):
    -t, --target <target>    Target IP/CIDR/hostname (overrides TARGET in config)
    -T                       Scan TCP
    -U                       Scan UDP
    -TU                      Scan both TCP and UDP
    -p, --ports <spec>       Port spec (overrides PORTS_SPEC), e.g. "80,443,8000-8100"
    --rate <n>               masscan --rate (overrides RATE from config)
    --port-scan              Discovery only (sets PORT_SCAN_FLAG=true)
    --service-scan           Discovery + per-port nmap -sV (sets SERVICE_SCAN_FLAG=true)
    --keep-tmp               Keep tmp directory after run
    --debug                  Enable debug output (implies --keep-tmp)
    -o, --output <file>      Save final ports list (overrides OUTFILE)
    -s, --scilence           Do not print final ports to stdout
    -h, --help               Show this help
EOF
}

# -----------------------
# Arg parsing (CLI overrides config)
# -----------------------
# copy config values into mutable vars
TARGET="${TARGET:-}"
DO_TCP="${DO_TCP:-false}"
DO_UDP="${DO_UDP:-false}"
OUTFILE="${OUTFILE:-}"
SCILENT="${SCILENT:-false}"
KEEP_TMP="${KEEP_TMP:-false}"
DEBUG="${DEBUG:-false}"
RATE="${RATE:-10000}"
PORTS_SPEC="${PORTS_SPEC:-}"
PORT_SCAN_FLAG="${PORT_SCAN_FLAG:-false}"
SERVICE_SCAN_FLAG="${SERVICE_SCAN_FLAG:-false}"
MASSCAN_FIRST="${MASSCAN_FIRST:-true}"
WEBANALYZE_APP_JSON="${WEBANALYZE_APP_JSON:-./technologies.json}"
RUN_WEBANALYZE_ALWAYS="${RUN_WEBANALYZE_ALWAYS:-false}"
PORTS_TCP="${PORTS_TCP:-1-65535}"
PORTS_UDP="${PORTS_UDP:-1-65535}"

# parse args
if [ $# -eq 0 ]; then print_help; exit 1; fi
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    -T) DO_TCP=true; shift;;
    -U) DO_UDP=true; shift;;
    -TU) DO_TCP=true; DO_UDP=true; shift;;
    -p|--ports) PORTS_SPEC="$2"; shift 2;;
    --rate) RATE="$2"; shift 2;;
    --port-scan) PORT_SCAN_FLAG=true; SERVICE_SCAN_FLAG=false; shift;;
    --service-scan) SERVICE_SCAN_FLAG=true; PORT_SCAN_FLAG=false; shift;;
    --keep-tmp) KEEP_TMP=true; shift;;
    --debug) DEBUG=true; KEEP_TMP=true; shift;;
    -o|--output) OUTFILE="$2"; shift 2;;
    -s|--scilence) SCILENT=true; shift;;
    -h|--help) print_help; exit 0;;
    *) log "Unknown option: $1"; print_help; exit 2;;
  esac
done

# -----------------------
# Validate target
# -----------------------
if [ -z "$TARGET" ]; then
  die "Target is required (-t/--target or set TARGET in $CONFIGFILE)."
fi

# apply PORTS_SPEC to per-protocol defaults if set
if [ -n "$PORTS_SPEC" ]; then
  PORTS_TCP="$PORTS_SPEC"
  PORTS_UDP="$PORTS_SPEC"
fi

# default behavior: if neither DO_TCP nor DO_UDP set, choose sensible default
if [ "$DO_TCP" != "true" ] && [ "$DO_UDP" != "true" ]; then
  if [ "$PORT_SCAN_FLAG" = "true" ]; then
    DO_TCP=true; DO_UDP=true
  else
    DO_TCP=true
  fi
fi

# disallow combining port-scan and service-scan
if [ "$SERVICE_SCAN_FLAG" = "true" ] && [ "$PORT_SCAN_FLAG" = "true" ]; then
  die "Use --service-scan alone (do not combine with --port-scan)."
fi

# tmpdir and cleanup
TMPDIR="$(mktemp -d /tmp/svcscan.XXXXXX)"
if [ "$DEBUG" = "true" ]; then log "[debug] TMPDIR=$TMPDIR"; fi
cleanup() {
  if [ "$KEEP_TMP" = "true" ]; then
    log "[*] Keeping tmp: $TMPDIR"
  else
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# file paths
RAW_MASS_TCP="$TMPDIR/masscan_tcp.raw"
RAW_MASS_UDP="$TMPDIR/masscan_udp.raw"
RAW_NMAP_TCP="$TMPDIR/nmap_tcp.raw"
RAW_NMAP_UDP="$TMPDIR/nmap_udp.raw"
PARSED_TCP="$TMPDIR/open_tcp.txt"
PARSED_UDP="$TMPDIR/open_udp.txt"
FINAL_PORTS="$TMPDIR/final_ports.txt"
SERVICES_RAW="$TMPDIR/services.txt"
WEBANALYZE_OUTDIR="$TMPDIR/webanalyze"
: > "$SERVICES_RAW"
mkdir -p "$WEBANALYZE_OUTDIR"

# -----------------------
# Utilities: port expansion and parsers
# -----------------------
expand_ports() {
  echo "$1" | tr ',' '\n' | while read -r tok; do
    tok=$(echo "$tok" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$tok" ] && continue
    if echo "$tok" | grep -Eq '^[0-9]+-[0-9]+$'; then
      start=${tok%-*}; end=${tok#*-}
      if echo "$start" | grep -Eq '^[0-9]+$' && echo "$end" | grep -Eq '^[0-9]+$' && [ "$start" -le "$end" ]; then
        seq "$start" "$end"
      fi
    else
      if echo "$tok" | grep -Eq '^[0-9]+$'; then
        echo "$tok"
      fi
    fi
  done | awk 'NF' | sort -n | uniq
}

parse_masscan_to_ports() {
  local infile="$1" out="$2"
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) if ($i ~ /\/(tcp|udp)$/) print $i
  }' "$infile" 2>/dev/null \
    | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | awk -F/ '$1 ~ /^[0-9]+$/ && ($2=="tcp"||$2=="udp") {print $1"/"$2}' \
    | sort -V -u > "$out" || true
}

parse_nmap_ports() {
  local infile="$1" out="$2"
  grep -E '^[[:space:]]*[0-9]+/(tcp|udp)' "$infile" 2>/dev/null \
    | awk '{gsub(/^[ \t]+/,""); print $1}' \
    | tr -d '\r' \
    | awk -F/ '$1 ~ /^[0-9]+$/ && ($2=="tcp"||$2=="udp") {print $1"/"$2}' \
    | sort -V -u > "$out" || true
}

parse_nmap_services() {
  local infile="$1" out="$2"
  awk '/^[[:space:]]*[0-9]+\/(tcp|udp)/ {
    sub(/^[ \t]+/,"");
    portproto=$1; state=$2; svc=$3; banner="";
    if (portproto ~ /^PORT/) next;
    for (i=4;i<=NF;i++) banner=banner" "$i;
    gsub(/^ +| +$/,"",banner);
    printf "%s -> %s%s\n", portproto, svc, (banner ? " " banner : "")
  }' "$infile" 2>/dev/null \
    | tr -d '\r' \
    | sort -V -u > "$out" || true
}

# flatten webanalyze lines to "Name version" pairs (full versions only)
flatten_webanalyze_full_versions() {
  local infile="$1" outfile="$2"
  sed '/^[[:space:]]*$/d' "$infile" \
    | while IFS= read -r raw; do
        line=$(echo "$raw" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
        [ -z "$line" ] && continue
        norm=$(echo "$line" | tr '_' '.')
        ver=$(echo "$norm" | grep -oE 'v?[0-9]+(\.[0-9]+){1,}' | head -n1 || true)
        if [ -n "$ver" ]; then
          ver=$(echo "$ver" | sed -E 's/^[vV]//')
          ver=$(echo "$ver" | grep -oE '^[0-9]+(\.[0-9]+)*' || true)
        else
          ver=$(echo "$norm" | grep -oE 'v?[0-9]+' | head -n1 || true)
          ver=$(echo "$ver" | sed -E 's/^[vV]//')
        fi
        [ -z "$ver" ] && continue
        if echo "$line" | grep -q ','; then
          name=$(echo "$line" | sed -E 's/,.*$//' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
        else
          name=$(echo "$line" | sed -E 's/[[:space:]]+v?[0-9]+(\.[0-9]+){0,}.*$//I' | sed -E 's/\([^)]+\)//g' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
        fi
        [ -z "$name" ] && name="$line"
        echo "$name $ver"
      done | sort -u > "$outfile" || true
}

# -----------------------
# Runner functions
# -----------------------
run_masscan() {
  local target="$1" proto="$2" ports="$3" outfile="$4"
  local parg
  if [ "$proto" = "udp" ]; then parg="-pU:${ports}"; else parg="-p${ports}"; fi
  log "[*] masscan ${target} proto=${proto} ports=${ports} rate=${RATE}"
  if [ "$EUID" -ne 0 ]; then
    sudo masscan ${parg} --rate "${RATE}" "${target}" 2>&1 | tee "$outfile" || true
  else
    masscan ${parg} --rate "${RATE}" "${target}" 2>&1 | tee "$outfile" || true
  fi
}

run_nmap_simple() {
  local target="$1" proto="$2" ports="$3" outfile="$4"
  log "[*] nmap discovery ${target} proto=${proto} ports=${ports}"
  if [ "$proto" = "udp" ]; then
    if [ -n "$ports" ]; then
      nmap -Pn -sU -p "$ports" -oN "$outfile" "$target" >/dev/null 2>&1 || true
    else
      nmap -Pn -sU -oN "$outfile" "$target" >/dev/null 2>&1 || true
    fi
  else
    if [ -n "$ports" ]; then
      nmap -Pn -sT -p "$ports" -oN "$outfile" "$target" >/dev/null 2>&1 || true
    else
      nmap -Pn -sT -oN "$outfile" "$target" >/dev/null 2>&1 || true
    fi
  fi
}

run_nmap_sv_one_tcp() {
  local target="$1" port="$2" outfile="$3"
  log "[*] nmap -sV TCP ${target} -p ${port}"
  nmap -Pn -sV -p "$port" -oN "$outfile" "$target" >/dev/null 2>&1 || true
}

run_nmap_sv_one_udp() {
  local target="$1" port="$2" outfile="$3"
  log "[*] nmap -sU -sV UDP ${target} -p ${port}"
  if [ "$EUID" -ne 0 ]; then
    sudo nmap -Pn -sU -sV -p "$port" -oN "$outfile" "$target" >/dev/null 2>&1 || true
  else
    nmap -Pn -sU -sV -p "$port" -oN "$outfile" "$target" >/dev/null 2>&1 || true
  fi
}

run_webanalyze_one() {
  local scheme="$1" host="$2" port="$3" outdir="$4"
  local wa_out="$outdir/webanalyze_${port}.txt"
  if ! check_installed webanalyze; then
    log "[!] webanalyze not installed; skipping."
    return 1
  fi
  if [ ! -f "$WEBANALYZE_APP_JSON" ]; then
    log "[!] technologies.json not found at $WEBANALYZE_APP_JSON; skipping."
    return 1
  fi
  log "[*] webanalyze ${scheme}://${host}:${port}"

  if [ "$port" = "443" ]; then
    target_url="https://${host}"
  elif [ "$port" = "80" ]; then
    target_url="http://${host}"
  else
    target_url="${scheme}://${host}:${port}"
  fi

  if [ "$EUID" -ne 0 ]; then
    sudo webanalyze -apps "$WEBANALYZE_APP_JSON" -host "$target_url" 2>/dev/null | tee "$wa_out" >/dev/null || true
  else
    webanalyze -apps "$WEBANALYZE_APP_JSON" -host "$target_url" 2>/dev/null | tee "$wa_out" >/dev/null || true
  fi

  local flat="$outdir/webanalyze_${port}.flat"
  flatten_webanalyze_full_versions "$wa_out" "$flat"
  [ -s "$flat" ] && return 0 || return 2
}

# -----------------------
# Discovery phase
# -----------------------
if [ "$DO_TCP" = "true" ]; then
  if [ "$MASSCAN_FIRST" = "true" ] && check_installed masscan; then
    run_masscan "$TARGET" "tcp" "$PORTS_TCP" "$RAW_MASS_TCP"
    parse_masscan_to_ports "$RAW_MASS_TCP" "$PARSED_TCP"
  else
    run_nmap_simple "$TARGET" "tcp" "$PORTS_TCP" "$RAW_NMAP_TCP"
    parse_nmap_ports "$RAW_NMAP_TCP" "$PARSED_TCP"
  fi
fi

if [ "$DO_UDP" = "true" ]; then
  if [ "$MASSCAN_FIRST" = "true" ] && check_installed masscan; then
    run_masscan "$TARGET" "udp" "$PORTS_UDP" "$RAW_MASS_UDP"
    parse_masscan_to_ports "$RAW_MASS_UDP" "$PARSED_UDP"
    # augment with nmap UDP discovery (nmap may provide additional info)
    run_nmap_simple "$TARGET" "udp" "$PORTS_UDP" "$RAW_NMAP_UDP"
    parse_nmap_ports "$RAW_NMAP_UDP" "$TMPDIR/nmap_udp_ports.txt"
    cat "$TMPDIR/nmap_udp_ports.txt" >> "$PARSED_UDP" 2>/dev/null || true
    sort -V -u "$PARSED_UDP" -o "$PARSED_UDP" || true
  else
    run_nmap_simple "$TARGET" "udp" "$PORTS_UDP" "$RAW_NMAP_UDP"
    parse_nmap_ports "$RAW_NMAP_UDP" "$PARSED_UDP"
  fi
fi

# -----------------------
# Combine and print final ports
# -----------------------
: > "$FINAL_PORTS"
[ -s "$PARSED_TCP" ] && cat "$PARSED_TCP" >> "$FINAL_PORTS"
[ -s "$PARSED_UDP" ] && cat "$PARSED_UDP" >> "$FINAL_PORTS"
if [ -s "$FINAL_PORTS" ]; then
  sort -V -u "$FINAL_PORTS" -o "$FINAL_PORTS" || true
fi

if [ -n "$OUTFILE" ]; then
  cp "$FINAL_PORTS" "$OUTFILE" 2>/dev/null || true
  [ -n "$OUTFILE" ] && log "[*] final ports written to: $OUTFILE"
fi

if [ "$SCILENT" != "true" ]; then
  if [ -s "$FINAL_PORTS" ]; then
    echo "==== Open ports (port/proto) ===="
    cat "$FINAL_PORTS"
  else
    log "[!] No open ports discovered."
  fi
fi

# -----------------------
# if --service-scan requested but no open ports -> exit early
# -----------------------
if [ "$SERVICE_SCAN_FLAG" = "true" ]; then
  if [ ! -s "$FINAL_PORTS" ]; then
    log "[*] --service-scan requested but no open ports were discovered. Exiting (no service enumeration will be run)."
    exit 0
  fi
fi

# -----------------------
# Service enumeration per-port
# -----------------------
if [ "$SERVICE_SCAN_FLAG" = "true" ]; then
  tcp_list="$(grep '/tcp$' "$FINAL_PORTS" 2>/dev/null | awk -F/ '{print $1}' | paste -sd, - || true)"
  udp_list="$(grep '/udp$' "$FINAL_PORTS" 2>/dev/null | awk -F/ '{print $1}' | paste -sd, - || true)"
  [ -z "$tcp_list" ] && [ "$DO_TCP" = "true" ] && tcp_list="$PORTS_TCP"
  [ -z "$udp_list" ] && [ "$DO_UDP" = "true" ] && udp_list="$PORTS_UDP"

  : > "$TMPDIR/tcp_elist.txt"; : > "$TMPDIR/udp_elist.txt"
  [ -n "${tcp_list:-}" ] && expand_ports "$tcp_list" > "$TMPDIR/tcp_elist.txt"
  [ -n "${udp_list:-}" ] && expand_ports "$udp_list" > "$TMPDIR/udp_elist.txt"

  if [ -s "$TMPDIR/tcp_elist.txt" ]; then
    while read -r p; do
      [ -z "$p" ] && continue
      out="$TMPDIR/nmap_sV_tcp_${p}.txt"
      run_nmap_sv_one_tcp "$TARGET" "$p" "$out"
      parse_nmap_services "$out" "${out}.parsed"
      [ -s "${out}.parsed" ] && cat "${out}.parsed" >> "$SERVICES_RAW"
    done < "$TMPDIR/tcp_elist.txt"
  fi

  if [ -s "$TMPDIR/udp_elist.txt" ]; then
    while read -r p; do
      [ -z "$p" ] && continue
      out="$TMPDIR/nmap_sV_udp_${p}.txt"
      run_nmap_sv_one_udp "$TARGET" "$p" "$out"
      parse_nmap_services "$out" "${out}.parsed"
      [ -s "${out}.parsed" ] && cat "${out}.parsed" >> "$SERVICES_RAW"
    done < "$TMPDIR/udp_elist.txt"
  fi

  if [ -s "$SERVICES_RAW" ]; then
    sort -V -u "$SERVICES_RAW" -o "$SERVICES_RAW" || true
    echo
    echo "==== Services discovered (port/proto -> service + banner) ===="
    cat "$SERVICES_RAW"
  else
    echo
    log "[!] No services discovered (nmap -sV returned nothing or nmap not installed)."
  fi

  # ---- auto webanalyze only for 80/tcp and 443/tcp ----
  if [ "$RUN_WEBANALYZE_ALWAYS" = "true" ]; then
    have80=false; have443=false
    grep -q '^80/tcp$'  "$FINAL_PORTS" 2>/dev/null && have80=true
    grep -q '^443/tcp$' "$FINAL_PORTS" 2>/dev/null && have443=true

    if [ "$have80" = "true" ] || [ "$have443" = "true" ]; then
      echo
      log "[*] Running webanalyze using $WEBANALYZE_APP_JSON on open web ports..."
      : > "$TMPDIR/web_techs_full.txt"

      if [ "$have80" = "true" ];  then run_webanalyze_one "http"  "$TARGET" 80  "$WEBANALYZE_OUTDIR" || true; fi
      if [ "$have443" = "true" ]; then run_webanalyze_one "https" "$TARGET" 443 "$WEBANALYZE_OUTDIR" || true; fi

      # collect flats
      for flat in "$WEBANALYZE_OUTDIR"/webanalyze_*.flat; do
        [ -s "$flat" ] || continue
        port="${flat##*_}"; port="${port%.flat}"
        scheme="http"; [ "$port" = "443" ] && scheme="https"
        echo "---- ${scheme}://${TARGET}:${port} ----" >> "$TMPDIR/web_techs_full.txt"
        cat "$flat" >> "$TMPDIR/web_techs_full.txt"
        echo >> "$TMPDIR/web_techs_full.txt"
      done

      if [ -s "$TMPDIR/web_techs_full.txt" ]; then
        echo
        echo "==== Web technologies (full versions only) ===="
        cat "$TMPDIR/web_techs_full.txt"
      else
        log "[!] webanalyze produced no parsed results."
      fi
    else
      log "[*] Skipping webanalyze: neither 80/tcp nor 443/tcp were found open."
    fi
  fi
fi

exit 0
