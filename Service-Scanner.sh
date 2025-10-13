#!/usr/bin/env bash
# service-scanner.sh - masscan/nmap wrapper with per-port nmap -sV enumeration
# Behavior:
#  --port-scan      : discovery only (masscan/nmap), print open ports
#  --service-scan   : discovery + per-port nmap -sV, print services, then auto webanalyze
#                     webanalyze runs ONLY if 80/tcp or 443/tcp are open, using ./technologies.json
# Notes:
#  - No --vuln/searchsploit integration in this version (intentionally left for later)
set -euo pipefail

TARGET=""
DO_TCP=false
DO_UDP=false
OUTFILE=""
SCILENT=false
KEEP_TMP=false
DEBUG=false

RATE="10000"
PORTS_SPEC=""
PORT_SCAN_FLAG=false
SERVICE_SCAN_FLAG=false
MASSCAN_FIRST=true

WEBANALYZE_APP_JSON="./technologies.json"   # required file in current directory
RUN_WEBANALYZE_ALWAYS=true                  # true: always try in --service-scan if 80/443 open

# print help message with switche -h or --help
print_help() {
  cat <<'EOF'
  service-scanner.sh - Port discovery + per-port service enumeration with nmap
  Options:
  -t, --target <target>   Target IP/CIDR/hostname (required)
  -T                      Scan TCP
  -U                      Scan UDP
  -TU                     Scan both TCP and UDP
  -p, --ports <spec>      "80", "80,443", "1-1024", "80,443,8000-8100"
  --rate <n>              masscan --rate (default: 10000)
  --port-scan             Discovery only (if no -T/-U/-TU set, defaults to both)
  --service-scan          Discovery + per-port nmap -sV; also auto webanalyze if 80/443 open
  --keep-tmp              Keep temporary files
  --debug                 Verbose; implies --keep-tmp
  -o, --output <file>     Save final ports list (port/proto per line)
  -s, --scilence          Do not print final ports to stdout
  -h, --help              Show this help
EOF
}

log()     { printf "%s\n" "$*" >&2; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

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

# ---- webanalyze: only 80/443 and only full versions ----
flatten_webanalyze_full_versions() {
  # input: raw webanalyze lines like "Liferay,7.3.1 (CMS)"
  # output: only "Name 7.3.1" (no major/minor variants)
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
          # fallback to single integer (rare)
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

run_webanalyze_one() {
  local scheme="$1" host="$2" port="$3" outdir="$4"
  local wa_out="$outdir/webanalyze_${port}.txt"
  if ! has_cmd webanalyze; then
    log "[!] webanalyze not installed; skipping."
    return 1
  fi
  if [ ! -f "$WEBANALYZE_APP_JSON" ]; then
    log "[!] technologies.json not found at $WEBANALYZE_APP_JSON; skipping."
    return 1
  fi
  log "[*] webanalyze ${scheme}://${host}:${port}"
  #webanalyze -apps "$WEBANALYZE_APP_JSON" -host "${host}:${port}" 2>/dev/null | tee "$wa_out" >/dev/null || true

  # decide URL style
  if [ "$port" = "443" ]; then
    target_url="https://${host}"
  elif [ "$port" = "80" ]; then
    target_url="http://${host}"
  else
    target_url="${host}:${port}"
  fi

  #webanalyze -apps "$WEBANALYZE_APP_JSON" -host "$target_url" 2>/dev/null | tee "$wa_out" >/dev/null || true
  webanalyze -apps "$WEBANALYZE_APP_JSON" -host "$target_url"

  local flat="$outdir/webanalyze_${port}.flat"
  flatten_webanalyze_full_versions "$wa_out" "$flat"
  [ -s "$flat" ] && return 0 || return 2
}

# ---- arg parsing ----
if [ $# -eq 0 ]; then print_help; exit 1; fi
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    -T) DO_TCP=true; shift;;
    -U) DO_UDP=true; shift;;
    -TU) DO_TCP=true; DO_UDP=true; shift;;
    -p|--ports) PORTS_SPEC="$2"; shift 2;;
    --rate) RATE="$2"; shift 2;;
    --port-scan) PORT_SCAN_FLAG=true; shift;;
    --service-scan) SERVICE_SCAN_FLAG=true; shift;;
    --keep-tmp) KEEP_TMP=true; shift;;
    --debug) DEBUG=true; KEEP_TMP=true; shift;;
    -o|--output) OUTFILE="$2"; shift 2;;
    -s|--scilence) SCILENT=true; shift;;
    -h|--help) print_help; exit 0;;
    *) log "Unknown option: $1"; print_help; exit 2;;
  esac
done

[ -z "$TARGET" ] && { log "error: -t/--target is required"; exit 2; }

if ! $DO_TCP && ! $DO_UDP; then
  if $PORT_SCAN_FLAG; then DO_TCP=true; DO_UDP=true; else DO_TCP=true; fi
fi
if $SERVICE_SCAN_FLAG && $PORT_SCAN_FLAG; then
  log "error: Use --service-scan alone (do not combine with --port-scan)."; exit 2
fi

TMPDIR="$(mktemp -d /tmp/svcscan.XXXXXX)"
[ "$DEBUG" = true ] && log "[debug] TMPDIR=$TMPDIR"
cleanup() { if ! $KEEP_TMP; then rm -rf "$TMPDIR"; else log "[*] Keeping tmp: $TMPDIR"; fi; }
trap cleanup EXIT

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

PORTS_TCP="${PORTS_SPEC:-1-65535}"
PORTS_UDP="${PORTS_SPEC:-1-65535}"

# ---- discovery ----
if $DO_TCP; then
  if $MASSCAN_FIRST && has_cmd masscan; then
    run_masscan "$TARGET" "tcp" "$PORTS_TCP" "$RAW_MASS_TCP"
    parse_masscan_to_ports "$RAW_MASS_TCP" "$PARSED_TCP"
  else
    run_nmap_simple "$TARGET" "tcp" "$PORTS_TCP" "$RAW_NMAP_TCP"
    parse_nmap_ports "$RAW_NMAP_TCP" "$PARSED_TCP"
  fi
fi
if $DO_UDP; then
  if $MASSCAN_FIRST && has_cmd masscan; then
    run_masscan "$TARGET" "udp" "$PORTS_UDP" "$RAW_MASS_UDP"
    parse_masscan_to_ports "$RAW_MASS_UDP" "$PARSED_UDP"
    run_nmap_simple "$TARGET" "udp" "$PORTS_UDP" "$RAW_NMAP_UDP"
    parse_nmap_ports "$RAW_NMAP_UDP" "$TMPDIR/nmap_udp_ports.txt"
    cat "$TMPDIR/nmap_udp_ports.txt" >> "$PARSED_UDP" 2>/dev/null || true
    sort -V -u "$PARSED_UDP" -o "$PARSED_UDP"
  else
    run_nmap_simple "$TARGET" "udp" "$PORTS_UDP" "$RAW_NMAP_UDP"
    parse_nmap_ports "$RAW_NMAP_UDP" "$PARSED_UDP"
  fi
fi

: > "$FINAL_PORTS"
[ -s "$PARSED_TCP" ] && cat "$PARSED_TCP" >> "$FINAL_PORTS"
[ -s "$PARSED_UDP" ] && cat "$PARSED_UDP" >> "$FINAL_PORTS"
[ -s "$FINAL_PORTS" ] && sort -V -u "$FINAL_PORTS" -o "$FINAL_PORTS"

if [ -n "$OUTFILE" ]; then cp "$FINAL_PORTS" "$OUTFILE" 2>/dev/null || true; log "[*] final ports written to: $OUTFILE"; fi

if [ "$SCILENT" = false ]; then
  if [ -s "$FINAL_PORTS" ]; then
    echo "==== Open ports (port/proto) ===="
    cat "$FINAL_PORTS"
  else
    log "[!] No open ports discovered."
  fi
fi

# ---- service enumeration per-port ----
if $SERVICE_SCAN_FLAG; then
  tcp_list="$(grep '/tcp$' "$FINAL_PORTS" 2>/dev/null | awk -F/ '{print $1}' | paste -sd, - || true)"
  udp_list="$(grep '/udp$' "$FINAL_PORTS" 2>/dev/null | awk -F/ '{print $1}' | paste -sd, - || true)"
  [ -z "$tcp_list" ] && $DO_TCP && tcp_list="$PORTS_TCP"
  [ -z "$udp_list" ] && $DO_UDP && udp_list="$PORTS_UDP"

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
    sort -V -u "$SERVICES_RAW" -o "$SERVICES_RAW"
    echo
    echo "==== Services discovered (port/proto -> service + banner) ===="
    cat "$SERVICES_RAW"
  else
    echo
    log "[!] No services discovered (nmap -sV returned nothing or nmap not installed)."
  fi

  # ---- auto webanalyze only for 80/tcp and 443/tcp ----
  if $RUN_WEBANALYZE_ALWAYS; then
    have80=false; have443=false
    grep -q '^80/tcp$'  "$FINAL_PORTS" 2>/dev/null && have80=true
    grep -q '^443/tcp$' "$FINAL_PORTS" 2>/dev/null && have443=true

    if $have80 || $have443; then
      echo
      log "[*] Running webanalyze using $WEBANALYZE_APP_JSON on open web ports..."
      : > "$TMPDIR/web_techs_full.txt"

      if $have80;  then run_webanalyze_one "http"  "$TARGET" 80  "$WEBANALYZE_OUTDIR" || true; fi
      if $have443; then run_webanalyze_one "https" "$TARGET" 443 "$WEBANALYZE_OUTDIR" || true; fi

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
