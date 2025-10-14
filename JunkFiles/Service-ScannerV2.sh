#!/usr/bin/env bash
# service-scanner.sh - masscan/nmap wrapper with per-port nmap -sV enumeration
# - Timestamped, categorized logs with symbols and optional colors
# - Per-finding logs: "80/tcp found by masscan" / "443/tcp found by nmap"
# - End-of-run deduped, sorted summaries of ports and services (no source names)
# - Tool raw outputs go to tmp files; screen shows only our logs/summaries
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
# Logging (timestamps + categories + symbols + optional colors)
# -----------------------
_ts() { date +"%Y-%m-%d %H:%M:%S"; }

_supports_color=false
if [ -t 2 ] && command -v tput >/dev/null 2>&1; then
  if [ "${NO_COLOR:-}" = "" ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    _supports_color=true
  fi
fi

# Colors
if [ "$_supports_color" = true ]; then
  C_RST="$(tput sgr0)"; C_BLD="$(tput bold)"
  C_OK="$(tput setaf 2)"; C_INF="$(tput setaf 6)"; C_WRN="$(tput setaf 3)"
  C_ERR="$(tput setaf 1)"; C_DBG="$(tput setaf 8)"
else
  C_RST=""; C_BLD=""; C_OK=""; C_INF=""; C_WRN=""; C_ERR=""; C_DBG=""
fi

_log_core() {
  # $1 level, $2 symbol, $3 color, $4 message
  printf "%s %s%s%s %s\n" "$(_ts)" "$3" "$2" "$C_RST" "$4" >&2
}

log_ok()   { _log_core OK  "[+]" "$C_OK"  "$*"; }
log_info() { _log_core INF "[*]" "$C_INF" "$*"; }
log_warn() { _log_core WRN "[!]" "$C_WRN" "$*"; }
log_err()  { _log_core ERR "[x]" "$C_ERR" "$*"; }
log_dbg()  { [ "${DEBUG:-false}" = "true" ] && _log_core DBG "[·]" "$C_DBG" "$*"; }

die() { log_err "$*"; exit 1; }

# check if app is installed (exit code semantics)
check_installed() { which "$1" >/dev/null 2>&1; }

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
    *) log_err "Unknown option: $1"; print_help; exit 2;;
  esac
done

# -----------------------
# Validate target, defaults
# -----------------------
if [ -z "$TARGET" ]; then
  die "Target is required (-t/--target or set TARGET in $CONFIGFILE)."
fi

if [ -n "$PORTS_SPEC" ]; then
  PORTS_TCP="$PORTS_SPEC"
  PORTS_UDP="$PORTS_SPEC"
fi

if [ "$DO_TCP" != "true" ] && [ "$DO_UDP" != "true" ]; then
  if [ "$PORT_SCAN_FLAG" = "true" ]; then
    DO_TCP=true; DO_UDP=true
  else
    DO_TCP=true
  fi
fi

if [ "$SERVICE_SCAN_FLAG" = "true" ] && [ "$PORT_SCAN_FLAG" = "true" ]; then
  die "Use --service-scan alone (do not combine with --port-scan)."
fi

# -----------------------
# tmpdir and cleanup
# -----------------------
TMPDIR="$(mktemp -d /tmp/svcscan.XXXXXX)"
log_dbg "TMPDIR=$TMPDIR"
cleanup() {
  if [ "$KEEP_TMP" = "true" ]; then
    log_info "Keeping tmp: $TMPDIR"
  else
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# -----------------------
# File paths
# -----------------------
RAW_MASS_TCP="$TMPDIR/masscan_tcp.raw"
RAW_MASS_UDP="$TMPDIR/masscan_udp.raw"
RAW_NMAP_TCP="$TMPDIR/nmap_tcp.raw"
RAW_NMAP_UDP="$TMPDIR/nmap_udp.raw"

MASS_TCP_PORTS="$TMPDIR/masscan_tcp.ports"
MASS_UDP_PORTS="$TMPDIR/masscan_udp.ports"
NMAP_TCP_PORTS="$TMPDIR/nmap_tcp.ports"
NMAP_UDP_PORTS="$TMPDIR/nmap_udp.ports"

PARSED_TCP="$TMPDIR/open_tcp.txt"
PARSED_UDP="$TMPDIR/open_udp.txt"
FINAL_PORTS="$TMPDIR/final_ports.txt"

SERVICES_RAW="$TMPDIR/services.txt"
: > "$SERVICES_RAW"

WEBANALYZE_OUTDIR="$TMPDIR/webanalyze"
mkdir -p "$WEBANALYZE_OUTDIR"

# Tracking (internal; not shown in final summaries)
PORT_FINDINGS="$TMPDIR/port_findings.tsv"       # columns: port/proto <TAB> tool
SERVICE_FINDINGS="$TMPDIR/service_findings.tsv" # columns: "port/proto -> svc banner" <TAB> tool
: > "$PORT_FINDINGS"
: > "$SERVICE_FINDINGS"

# -----------------------
# Utilities
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
  # $1 infile $2 outports $3 toolname
  local infile="$1" out="$2" tool="${3:-masscan}"
  awk '/[Dd]iscovered open port/ {
    for (i=1;i<=NF;i++) if ($i ~ /\/(tcp|udp)$/) print $i
  }' "$infile" 2>/dev/null \
    | tr -d '\r' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | awk -F/ '$1 ~ /^[0-9]+$/ && ($2=="tcp"||$2=="udp") {print $1"/"$2}' \
    | sort -V -u > "$out" || true

  if [ -s "$out" ]; then
    while read -r pp; do
      [ -z "$pp" ] && continue
      printf "%s\t%s\n" "$pp" "$tool" >> "$PORT_FINDINGS"
      log_ok "$pp found by ${tool}"
    done < "$out"
  fi
}

parse_nmap_ports() {
  # $1 infile $2 outports $3 toolname
  local infile="$1" out="$2" tool="${3:-nmap}"
  grep -E '^[[:space:]]*[0-9]+/(tcp|udp)' "$infile" 2>/dev/null \
    | awk '{gsub(/^[ \t]+/,""); print $1}' \
    | tr -d '\r' \
    | awk -F/ '$1 ~ /^[0-9]+$/ && ($2=="tcp"||$2=="udp") {print $1"/"$2}' \
    | sort -V -u > "$out" || true

  if [ -s "$out" ]; then
    while read -r pp; do
      [ -z "$pp" ] && continue
      printf "%s\t%s\n" "$pp" "$tool" >> "$PORT_FINDINGS"
      log_ok "$pp found by ${tool}"
    done < "$out"
  fi
}

parse_nmap_services() {
  # $1 infile $2 out $3 toolname
  local infile="$1" out="$2" tool="${3:-nmap -sV}"
  awk '/^[[:space:]]*[0-9]+\/(tcp|udp)/ {
    sub(/^[ \t]+/,"");
    portproto=$1; state=$2; svc=$3; banner="";
    if (portproto ~ /^PORT/) next;
    for (i=4;i<=NF;i++) banner=banner" "$i;
    gsub(/^ +| +$/,"",banner);
    if (svc == "" || svc == "unknown") next;
    printf "%s -> %s%s\n", portproto, svc, (banner ? " " banner : "")
  }' "$infile" 2>/dev/null \
    | tr -d '\r' \
    | sort -V -u > "$out" || true

  if [ -s "$out" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      printf "%s\t%s\n" "$line" "$tool" >> "$SERVICE_FINDINGS"
      log_info "Service: $line  (${tool})"
    done < "$out"
  fi
}

# Flatten webanalyze output to "Name version" (only real versions like 1.2, 2.4.7)
flatten_webanalyze_full_versions() {
  local infile="$1" outfile="$2"
  : > "$outfile"
  sed '/^[[:space:]]*$/d' "$infile" \
    | grep -viE '^(https?://|url:|host:)' \
    | while IFS= read -r raw; do
        line=$(printf "%s" "$raw" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
        [ -z "$line" ] && continue

        # must contain at least x.y to count as version; drop IP-ish or host title junk
        ver=$(printf "%s" "$line" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n1 || true)
        [ -z "$ver" ] && continue
        printf "%s" "$line" | grep -qE 'https?://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && continue

        # name = line up to version (trim parentheses), normalize underscores to dots
        name=$(printf "%s" "$line" \
                | tr '_' '.' \
                | sed -E "s/[[:space:]]+$ver.*$//" \
                | sed -E 's/\([^)]+\)//g' \
                | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
        [ -z "$name" ] && continue

        echo "$name $ver"
      done | sort -u > "$outfile" || true
}

# -----------------------
# Runners
# -----------------------
run_masscan() {
  local target="$1" proto="$2" ports="$3" outfile="$4"
  local parg
  if [ "$proto" = "udp" ]; then parg="-pU:${ports}"; else parg="-p${ports}"; fi
  log_info "masscan ${target} proto=${proto} ports=${ports} rate=${RATE}"
  if [ "$EUID" -ne 0 ]; then
    sudo masscan ${parg} --rate "${RATE}" "${target}" 2>&1 | tee "$outfile" >/dev/null || true
  else
    masscan ${parg} --rate "${RATE}" "${target}" 2>&1 | tee "$outfile" >/dev/null || true
  fi
}

run_nmap_simple() {
  local target="$1" proto="$2" ports="$3" outfile="$4"
  log_info "nmap discovery ${target} proto=${proto} ports=${ports:-auto}"
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
  log_info "nmap -sV TCP ${target} -p ${port}"
  nmap -Pn -sV -p "$port" -oN "$outfile" "$target" >/dev/null 2>&1 || true
}

run_nmap_sv_one_udp() {
  local target="$1" port="$2" outfile="$3"
  log_info "nmap -sU -sV UDP ${target} -p ${port}"
  if [ "$EUID" -ne 0 ]; then
    sudo nmap -Pn -sU -sV -p "$port" -oN "$outfile" "$target" >/dev/null 2>&1 || true
  else
    nmap -Pn -sU -sV -p "$port" -oN "$outfile" "$target" >/dev/null 2>&1 || true
  fi
}

# webanalyze runner for one port (80/443 only), writes normalized service lines
run_webanalyze_one() {
  local scheme="$1" host="$2" port="$3" outdir="$4"
  local wa_out="$outdir/webanalyze_${port}.txt"
  if ! check_installed webanalyze; then
    log_warn "webanalyze not installed; skipping."
    return 1
  fi
  if [ ! -f "$WEBANALYZE_APP_JSON" ]; then
    log_warn "technologies.json not found at $WEBANALYZE_APP_JSON; skipping."
    return 1
  fi

  local target_url
  if [ "$port" = "443" ]; then
    target_url="https://${host}"
  elif [ "$port" = "80" ]; then
    target_url="http://${host}"
  else
    log_warn "Webanalyze: Only 80 and 443 are supported here; skipping port $port."
    return 1
  fi

  log_info "webanalyze ${target_url}"
  if [ "$EUID" -ne 0 ]; then
    sudo webanalyze -apps "$WEBANALYZE_APP_JSON" -host "$target_url" 2>/dev/null | tee "$wa_out" >/dev/null || true
  else
    webanalyze -apps "$WEBANALYZE_APP_JSON" -host "$target_url" 2>/dev/null | tee "$wa_out" >/dev/null || true
  fi

  local flat="$outdir/webanalyze_${port}.flat"
  flatten_webanalyze_full_versions "$wa_out" "$flat"
  if [ -s "$flat" ]; then
    local pp="${port}/tcp"
    while IFS= read -r tech; do
      [ -z "$tech" ] && continue
      printf "%s -> %s\twebanalyze\n" "$pp" "$tech" >> "$SERVICE_FINDINGS"
      log_ok "Web tech ($pp): $tech (webanalyze)"
    done < "$flat"
    return 0
  fi
  return 2
}

# -----------------------
# Discovery phase (TCP)
# -----------------------
if [ "$DO_TCP" = "true" ]; then
  if [ "$MASSCAN_FIRST" = "true" ] && check_installed masscan; then
    run_masscan "$TARGET" "tcp" "$PORTS_TCP" "$RAW_MASS_TCP"
    parse_masscan_to_ports "$RAW_MASS_TCP" "$MASS_TCP_PORTS" "masscan"
  else
    run_nmap_simple "$TARGET" "tcp" "$PORTS_TCP" "$RAW_NMAP_TCP"
    parse_nmap_ports "$RAW_NMAP_TCP" "$NMAP_TCP_PORTS" "nmap"
  fi
fi

# -----------------------
# Discovery phase (UDP)
# -----------------------
if [ "$DO_UDP" = "true" ]; then
  if [ "$MASSCAN_FIRST" = "true" ] && check_installed masscan; then
    run_masscan "$TARGET" "udp" "$PORTS_UDP" "$RAW_MASS_UDP"
    parse_masscan_to_ports "$RAW_MASS_UDP" "$MASS_UDP_PORTS" "masscan"
    # augment with nmap UDP discovery
    run_nmap_simple "$TARGET" "udp" "$PORTS_UDP" "$RAW_NMAP_UDP"
    parse_nmap_ports "$RAW_NMAP_UDP" "$NMAP_UDP_PORTS" "nmap"
  else
    run_nmap_simple "$TARGET" "udp" "$PORTS_UDP" "$RAW_NMAP_UDP"
    parse_nmap_ports "$RAW_NMAP_UDP" "$NMAP_UDP_PORTS" "nmap"
  fi
fi

# -----------------------
# Combine and print final ports
# -----------------------
: > "$PARSED_TCP"; : > "$PARSED_UDP"; : > "$FINAL_PORTS"

[ -s "$MASS_TCP_PORTS" ] && cat "$MASS_TCP_PORTS" >> "$PARSED_TCP"
[ -s "$NMAP_TCP_PORTS" ] && cat "$NMAP_TCP_PORTS" >> "$PARSED_TCP"
[ -s "$PARSED_TCP" ] && sort -V -u "$PARSED_TCP" -o "$PARSED_TCP"

[ -s "$MASS_UDP_PORTS" ] && cat "$MASS_UDP_PORTS" >> "$PARSED_UDP"
[ -s "$NMAP_UDP_PORTS" ] && cat "$NMAP_UDP_PORTS" >> "$PARSED_UDP"
[ -s "$PARSED_UDP" ] && sort -V -u "$PARSED_UDP" -o "$PARSED_UDP"

[ -s "$PARSED_TCP" ] && cat "$PARSED_TCP" >> "$FINAL_PORTS"
[ -s "$PARSED_UDP" ] && cat "$PARSED_UDP" >> "$FINAL_PORTS"
[ -s "$FINAL_PORTS" ] && sort -V -u "$FINAL_PORTS" -o "$FINAL_PORTS"

if [ -n "$OUTFILE" ]; then
  cp "$FINAL_PORTS" "$OUTFILE" 2>/dev/null || true
  [ -n "$OUTFILE" ] && log_info "final ports written to: $OUTFILE"
fi

if [ "$SCILENT" != "true" ]; then
  if [ -s "$FINAL_PORTS" ]; then
    echo
    echo "==== Open ports (port/proto) ===="
    cat "$FINAL_PORTS"
  else
    log_warn "No open ports discovered."
  fi
fi

# -----------------------
# If --service-scan requested but no open ports -> exit early
# -----------------------
if [ "$SERVICE_SCAN_FLAG" = "true" ]; then
  if [ ! -s "$FINAL_PORTS" ]; then
    log_info "--service-scan requested but no open ports were discovered. Exiting."
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
      parse_nmap_services "$out" "${out}.parsed" "nmap -sV"
      [ -s "${out}.parsed" ] && cat "${out}.parsed" >> "$SERVICES_RAW"
    done < "$TMPDIR/tcp_elist.txt"
  fi

  if [ -s "$TMPDIR/udp_elist.txt" ]; then
    while read -r p; do
      [ -z "$p" ] && continue
      out="$TMPDIR/nmap_sV_udp_${p}.txt"
      run_nmap_sv_one_udp "$TARGET" "$p" "$out"
      parse_nmap_services "$out" "${out}.parsed" "nmap -sU -sV"
      [ -s "${out}.parsed" ] && cat "${out}.parsed" >> "$SERVICES_RAW"
    done < "$TMPDIR/udp_elist.txt"
  fi

  # ---- auto webanalyze only for 80/tcp and 443/tcp ----
  if [ "$RUN_WEBANALYZE_ALWAYS" = "true" ]; then
    have80=false; have443=false
    grep -q '^80/tcp$'  "$FINAL_PORTS" 2>/dev/null && have80=true
    grep -q '^443/tcp$' "$FINAL_PORTS" 2>/dev/null && have443=true

    if [ "$have80" = "true" ] || [ "$have443" = "true" ]; then
      log_info "Running webanalyze using $WEBANALYZE_APP_JSON on open web ports..."
      [ "$have80" = "true" ]  && run_webanalyze_one "http"  "$TARGET" 80  "$WEBANALYZE_OUTDIR" || true
      [ "$have443" = "true" ] && run_webanalyze_one "https" "$TARGET" 443 "$WEBANALYZE_OUTDIR" || true
    else
      log_info "Skipping webanalyze: neither 80/tcp nor 443/tcp were found open."
    fi
  fi

  # -----------------------
  # Summaries (clean — no tool/source tags)
  # -----------------------
  echo
  echo "==== Port summary (deduped + sorted) ===="
  if [ -s "$FINAL_PORTS" ]; then
    cat "$FINAL_PORTS"
  else
    echo "(none)"
  fi

  echo
  echo "==== Services discovered (deduped) ===="
  if [ -s "$SERVICE_FINDINGS" ]; then
    # print just the unique left side: "port/proto -> service [banner]"
    awk -F'\t' '{print $1}' "$SERVICE_FINDINGS" | sort -V -u
  elif [ -s "$SERVICES_RAW" ]; then
    # fallback if anything landed only in SERVICES_RAW
    sort -V -u "$SERVICES_RAW"
  else
    echo "(none)"
  fi
fi

exit 0
