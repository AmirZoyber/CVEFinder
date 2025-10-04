#!/usr/bin/env bash
# scanner_funcs.sh
# Function-based recon pipeline:
#  - subdomain discovery (subfinder)
#  - resolve (dnsx)
#  - http probe (httpx tolerant)
#  - nuclei (robust flags detection)
#  - nikto (per-host)
#  - nmap (array args)
#  - exploit lookup (searchsploit + msf search)
#  - markdown report assembly
#
# Usage: ./scanner_funcs.sh --targets <file> [--nmap] [--nuclei] [--nikto] [--exploit] [--full]
# Comments are in English.
set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Globals / defaults
# -------------------------
TARGETS_FILE=""
DO_NMAP=false
DO_NUCLEI=false
DO_NIKTO=false
DO_EXPLOITS=false
DO_FULL=false

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTROOT="scanner_funcs_${TIMESTAMP}"
mkdir -p "${OUTROOT}"

# file paths (will be created under OUTROOT)
RAW="${OUTROOT}/raw_targets.txt"
DOMAINS="${OUTROOT}/domains.txt"
IPS="${OUTROOT}/ips.txt"
SUBS="${OUTROOT}/subdomains.txt"
COMBINED="${OUTROOT}/combined_domains.txt"
RESOLVED="${OUTROOT}/resolved_hosts.txt"   # host|ip
HTTP_URLS="${OUTROOT}/httpx_urls.txt"
NMAP_DIR="${OUTROOT}/nmap"
NUCLEI_DIR="${OUTROOT}/nuclei"
NIKTO_DIR="${OUTROOT}/nikto"
EXPLOITS_DIR="${OUTROOT}/exploits"
SERVICES_FILE="${OUTROOT}/discovered_services.txt"
CVES_FILE="${OUTROOT}/discovered_cves.txt"
REPORT="${OUTROOT}/final_report.md"

mkdir -p "${NMAP_DIR}" "${NUCLEI_DIR}" "${NIKTO_DIR}" "${EXPLOITS_DIR}"

# -------------------------
# Usage
# -------------------------
usage() {
  cat <<EOF
Usage: $0 --targets <file> [--nmap] [--nuclei] [--nikto] [--exploit] [--full]

Options:
  --targets <file>   targets file (one domain or IP per line) (required)
  --nmap             run nmap port/service scan
  --nuclei           run nuclei on HTTP endpoints
  --nikto            run nikto on HTTP endpoints
  --exploit          run exploit-finding (forces nmap+nikto)
  --full             run all modules
  --help             show this help
EOF
}

# -------------------------
# Arg parsing (manual long options)
# -------------------------
parse_args() {
  if [[ $# -eq 0 ]]; then usage; exit 1; fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --targets)
        TARGETS_FILE="$2"; shift 2;;
      --nmap) DO_NMAP=true; shift;;
      --nuclei) DO_NUCLEI=true; shift;;
      --nikto) DO_NIKTO=true; shift;;
      --exploit) DO_EXPLOITS=true; shift;;
      --full) DO_FULL=true; shift;;
      --help) usage; exit 0;;
      *)
        echo "Unknown option: $1" >&2; usage; exit 1;;
    esac
  done

  if [[ "${DO_FULL}" == true ]]; then
    DO_NMAP=true; DO_NUCLEI=true; DO_NIKTO=true; DO_EXPLOITS=true
  fi
  if [[ "${DO_EXPLOITS}" == true ]]; then
    DO_NMAP=true; DO_NIKTO=true
  fi

  if [[ -z "${TARGETS_FILE}" ]]; then
    echo "[!] --targets is required" >&2; usage; exit 2
  fi
  if [[ ! -f "${TARGETS_FILE}" ]]; then
    echo "[!] targets file not found: ${TARGETS_FILE}" >&2; exit 3
  fi
}

# -------------------------
# Tool checks (only what we need)
# -------------------------
check_tools() {
  local req=(subfinder dnsx)
  if command -v httpx >/dev/null 2>&1; then req+=(httpx); fi
  $DO_NMAP && req+=(nmap)
  $DO_NUCLEI && req+=(nuclei)
  $DO_NIKTO && req+=(nikto)
  $DO_EXPLOITS && req+=(searchsploit msfconsole)
  local missing=()
  for t in "${req[@]}"; do
    # allow multi-word "searchsploit msfconsole" expansions handled above
    for bin in $t; do
      if ! command -v "${bin}" >/dev/null 2>&1; then missing+=("${bin}"); fi
    done
  done
  if (( ${#missing[@]} )); then
    echo "[!] Missing tools for chosen modules: ${missing[*]}" >&2
    echo "    Install them or deselect options." >&2
    exit 4
  fi
}

# -------------------------
# IO helpers
# -------------------------
safe_trim() {
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

# -------------------------
# Subdomain discovery
# -------------------------
discover_subs() {
  # comment: subfinder on domains file
  if [[ -s "${DOMAINS}" ]]; then
    echo "[*] Running subfinder..."
    subfinder -dL "${DOMAINS}" -silent -o "${SUBS}" 2>/dev/null || true
  else
    echo "[*] No domains to run subfinder on."
  fi
  cat "${DOMAINS}" "${SUBS}" 2>/dev/null | sort -u > "${COMBINED}" || true
}

# -------------------------
# Resolve hosts -> host|ip pairs
# -------------------------
resolve_hosts() {
  if [[ -s "${COMBINED}" ]]; then
    echo "[*] Resolving with dnsx..."
    dnsx -a -silent -l "${COMBINED}" | awk '{print $1 "|" $2}' | sort -u > "${RESOLVED}" || true
  fi
  # include raw IPs
  if [[ -s "${IPS}" ]]; then
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      if ! grep -q "|${ip}$" "${RESOLVED}" 2>/dev/null; then
        echo "${ip}|${ip}" >> "${RESOLVED}"
      fi
    done < "${IPS}"
  fi
  sort -u "${RESOLVED}" -o "${RESOLVED}" || true
  echo "[*] Resolved hosts saved to ${RESOLVED}"
}

# -------------------------
# Probe HTTP endpoints (httpx tolerant) => HTTP_URLS
# -------------------------
try_httpx_variants() {
  local in="$1" out="$2"
  if ! command -v httpx >/dev/null 2>&1; then
    return 1
  fi
  set +e
  httpx -l "${in}" --silent -threads 50 -status-code -o "${out}" 2> "${OUTROOT}/httpx_try1.err"
  rc=$?; if [[ $rc -eq 0 && -s "${out}" ]]; then set -e; return 0; fi
  httpx -l "${in}" -silent -threads 50 -status-code -o "${out}" 2> "${OUTROOT}/httpx_try2.err"
  rc=$?; if [[ $rc -eq 0 && -s "${out}" ]]; then set -e; return 0; fi
  httpx -l "${in}" --silent -o "${out}" 2> "${OUTROOT}/httpx_try3.err"
  rc=$?; set -e
  if [[ $rc -eq 0 && -s "${out}" ]]; then return 0; fi
  return 1
}

probe_http() {
  # comment: build hosts list and try httpx, otherwise synthesize http(s) urls
  cut -d'|' -f1 "${RESOLVED}" | sort -u > "${OUTROOT}/hosts_list.tmp" || true
  if [[ -s "${OUTROOT}/hosts_list.tmp" ]]; then
    echo "[*] Probing HTTP endpoints with httpx..."
    if try_httpx_variants "${OUTROOT}/hosts_list.tmp" "${HTTP_URLS}"; then
      echo "[*] httpx produced ${HTTP_URLS} ($(wc -l < "${HTTP_URLS}") URLs)"
      return 0
    else
      echo "[!] httpx attempts failed. See httpx_try*.err in ${OUTROOT}"
    fi
  fi

  echo "[*] Falling back to synthesized http/https candidates..."
  > "${HTTP_URLS}"
  while IFS='|' read -r host ip; do
    [[ -z "${host}" ]] && continue
    echo "http://${host}" >> "${HTTP_URLS}"
    echo "https://${host}" >> "${HTTP_URLS}"
  done < "${RESOLVED}"
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    echo "http://${ip}" >> "${HTTP_URLS}"
    echo "https://${ip}" >> "${HTTP_URLS}"
  done < "${IPS}" 2>/dev/null || true
  sort -u -o "${HTTP_URLS}" "${HTTP_URLS}" || true
  echo "[*] Synthesized HTTP URLs -> ${HTTP_URLS} ($(wc -l < "${HTTP_URLS}") URLs)"
}

# -------------------------
# Nuclei run (detect flags)
# -------------------------
run_nuclei() {
  [[ "${DO_NUCLEI}" == true ]] || return 0
  echo "[*] Running nuclei (robust)..."
  mkdir -p "${NUCLEI_DIR}"
  local N_HELP
  N_HELP=$(nuclei -h 2>&1 || true)
  local RATE_OPT=""
  if echo "$N_HELP" | grep -q -E '\-rate\b|--rate\b'; then RATE_OPT="-rate 150"; fi
  local JSON_OK=false
  if echo "$N_HELP" | grep -q -E '\-json\b|--json\b'; then JSON_OK=true; fi

  local OUT_TXT="${NUCLEI_DIR}/nuclei_results.txt"
  local OUT_JSON="${NUCLEI_DIR}/nuclei_results.jsonl"

  if [[ "$JSON_OK" == true ]]; then
    set +e
    nuclei -l "${HTTP_URLS}" -severity critical,high -c 50 ${RATE_OPT} -json > "${OUT_JSON}" 2> "${OUTROOT}/nuclei_run.err"
    rc=$?; set -e
    if [[ -s "${OUT_JSON}" && command -v jq >/dev/null 2>&1 ]]; then
      jq -r '. | "\(.id) \(.info.name // .template) \(.host // .ip // .matched // "")"' "${OUT_JSON}" | sed -n '1,200p' > "${OUT_TXT}" || cp "${OUT_JSON}" "${OUT_TXT}"
    elif [[ -s "${OUT_JSON}" ]]; then
      head -n 200 "${OUT_JSON}" > "${OUT_TXT}" || true
    fi
  else
    set +e
    nuclei -l "${HTTP_URLS}" -severity critical,high -c 50 ${RATE_OPT} -o "${OUT_TXT}" 2> "${OUTROOT}/nuclei_run.err" || true
    set -e
  fi
  echo "[*] nuclei finished -> ${OUT_TXT}"
}

# -------------------------
# Nikto run per URL
# -------------------------
run_nikto() {
  [[ "${DO_NIKTO}" == true ]] || return 0
  echo "[*] Running nikto on HTTP URLs..."
  mkdir -p "${NIKTO_DIR}"
  local THREADS=6
  while read -r url; do
    [[ -z "$url" ]] && continue
    host="$(echo "$url" | sed -E 's|https?://||; s|[:/].*||')"
    out="${NIKTO_DIR}/${host//[:\/]/_}.nikto.txt"
    nikto -h "${url}" -Tuning 123b -timeout 10 -nointeractive -o "${out}" 2>/dev/null || true &
    while (( $(jobs -r | wc -l) >= THREADS )); do sleep 1; done
  done < "${HTTP_URLS}"
  wait
  echo "[*] nikto finished -> ${NIKTO_DIR}"
}

# -------------------------
# Nmap scans (array options safe)
# -------------------------
run_nmap() {
  [[ "${DO_NMAP}" == true ]] || return 0
  echo "[*] Running nmap scans..."
  mkdir -p "${NMAP_DIR}"
  cut -d'|' -f2 "${RESOLVED}" | sort -u > "${OUTROOT}/target_ips.txt" || true
  local -a NMAP_COMMON=( -Pn -sS -p- -sV --open -T4 --min-rate 500 )
  local NMAP_SCRIPTS="vuln"
  if nmap --script-help vulners >/dev/null 2>&1; then NMAP_SCRIPTS="vuln,vulners"; fi

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    outbase="${NMAP_DIR}/${ip//\//_}"
    if [[ $EUID -ne 0 ]]; then
      echo "    [!] Not root - using -sT for ${ip}"
      nmap "${NMAP_COMMON[@]/-sS/-sT}" --script="${NMAP_SCRIPTS}" -oA "${outbase}" "${ip}" || true
    else
      nmap "${NMAP_COMMON[@]}" --script="${NMAP_SCRIPTS}" -oA "${outbase}" "${ip}" || true
    fi
  done < "${OUTROOT}/target_ips.txt"
  echo "[*] nmap finished -> ${NMAP_DIR}"
}

# -------------------------
# Parse nmap outputs -> services + CVEs
# -------------------------
parse_nmap() {
  > "${SERVICES_FILE}"; > "${CVES_FILE}"
  if [[ "${DO_NMAP}" != true ]]; then return 0; fi
  echo "[*] Parsing nmap outputs..."
  for nm in "${NMAP_DIR}"/*.nmap; do
    [[ -f "$nm" ]] || continue
    ipfile=$(basename "${nm}" .nmap)
    awk '/^[0-9]+\/tcp/ {print}' "${nm}" | while read -r line; do
      port_proto=$(echo "${line}" | awk '{print $1}')
      port=$(echo "${port_proto}" | cut -d'/' -f1)
      proto=$(echo "${port_proto}" | cut -d'/' -f2)
      svc=$(echo "${line}" | awk '{print $3}')
      ver=$(echo "${line}" | cut -d' ' -f4- | sed 's/^[[:space:]]*//')
      printf "%s|%s|%s|%s|%s\n" "${ipfile}" "${port}" "${proto}" "${svc}" "${ver}" >> "${SERVICES_FILE}"
    done
    for f in "${NMAP_DIR}/${ipfile}"*; do
      [[ -f "$f" ]] || continue
      grep -Eo 'CVE-[0-9]{4}-[0-9]+' "$f" | sort -u >> "${CVES_FILE}" || true
    done
  done
  sort -u "${SERVICES_FILE}" -o "${SERVICES_FILE}" || true
  sort -u "${CVES_FILE}" -o "${CVES_FILE}" || true
  echo "[*] Parsed services -> ${SERVICES_FILE}, CVEs -> ${CVES_FILE}"
}

# -------------------------
# Extract CVEs from nuclei outputs
# -------------------------
extract_nuclei_cves() {
  [[ "${DO_NUCLEI}" == true ]] || return 0
  if [[ -f "${NUCLEI_DIR}/nuclei_results.jsonl" ]]; then
    if command -v jq >/dev/null 2>&1; then
      jq -r '..|strings|match("CVE-[0-9]{4}-[0-9]+")?.string // empty' "${NUCLEI_DIR}/nuclei_results.jsonl" | sort -u >> "${CVES_FILE}" || true
    else
      grep -Eo 'CVE-[0-9]{4}-[0-9]+' "${NUCLEI_DIR}/nuclei_results.jsonl" | sort -u >> "${CVES_FILE}" || true
    fi
  fi
  if [[ -f "${NUCLEI_DIR}/nuclei_results.txt" ]]; then
    grep -Eo 'CVE-[0-9]{4}-[0-9]+' "${NUCLEI_DIR}/nuclei_results.txt" | sort -u >> "${CVES_FILE}" || true
  fi
  sort -u "${CVES_FILE}" -o "${CVES_FILE}" || true
}

# -------------------------
# Exploit lookup: searchsploit + msf (non-interactive search only)
# -------------------------
exploit_lookup() {
  [[ "${DO_EXPLOITS}" == true ]] || return 0
  echo "[*] Running exploit lookup (searchsploit + msf search)..."
  mkdir -p "${EXPLOITS_DIR}"
  local SS_SUM="${EXPLOITS_DIR}/searchsploit_summary.txt"
  local MSF_SUM="${EXPLOITS_DIR}/msf_summary.txt"
  > "${SS_SUM}"; > "${MSF_SUM}"

  # searchsploit for services
  if [[ -s "${SERVICES_FILE}" ]]; then
    while IFS='|' read -r ip port proto service version; do
      [[ -z "$service" ]] && continue
      if [[ -n "${version// }" ]]; then
        q="${service} ${version}"
        echo "[*] searchsploit -> ${q}"
        if searchsploit --help 2>&1 | grep -q -- '--json'; then
          searchsploit --json "${q}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.json" 2>/dev/null || true
          if [[ -s "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.json" && command -v jq >/dev/null 2>&1 ]]; then
            jq -r '.[] | "\(.title) -- \(.path) -- \(.date)"' "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.json" >> "${SS_SUM}" || true
          fi
        else
          searchsploit -w --colour 0 "${q}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.txt" 2>/dev/null || true
          grep -E 'Exploit Title|EDB-ID|Date' "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.txt" 2>/dev/null >> "${SS_SUM}" || true
        fi
      fi
      # service only
      echo "[*] searchsploit -> ${service}"
      if searchsploit --help 2>&1 | grep -q -- '--json'; then
        searchsploit --json "${service}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.json" 2>/dev/null || true
        if [[ -s "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.json" && command -v jq >/dev/null 2>&1 ]]; then
          jq -r '.[] | "\(.title) -- \(.path) -- \(.date)"' "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.json" >> "${SS_SUM}" || true
        fi
      else
        searchsploit -w --colour 0 "${service}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.txt" 2>/dev/null || true
        grep -E 'Exploit Title|EDB-ID|Date' "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.txt" 2>/dev/null >> "${SS_SUM}" || true
      fi
    done < "${SERVICES_FILE}"
  fi

  # searchsploit by CVE
  if [[ -s "${CVES_FILE}" ]]; then
    while read -r cve; do
      [[ -z "$cve" ]] && continue
      echo "[*] searchsploit -> ${cve}"
      if searchsploit --help 2>&1 | grep -q -- '--json'; then
        searchsploit --json "${cve}" > "${EXPLOITS_DIR}/${cve}.json" 2>/dev/null || true
        if [[ -s "${EXPLOITS_DIR}/${cve}.json" && command -v jq >/dev/null 2>&1 ]]; then
          jq -r '.[] | "\(.title) -- \(.path) -- \(.date)"' "${EXPLOITS_DIR}/${cve}.json" >> "${SS_SUM}" || true
        fi
      else
        searchsploit -w --colour 0 "${cve}" > "${EXPLOITS_DIR}/${cve}.txt" 2>/dev/null || true
        grep -E 'Exploit Title|EDB-ID|Date' "${EXPLOITS_DIR}/${cve}.txt" 2>/dev/null >> "${SS_SUM}" || true
      fi
    done < "${CVES_FILE}"
  fi

  # metasploit searches (non-interactive)
  if [[ -s "${CVES_FILE}" ]]; then
    while read -r cve; do
      [[ -z "$cve" ]] && continue
      echo "[*] msf -> searching ${cve}"
      msfconsole -q -x "search cve:${cve}; exit" > "${EXPLOITS_DIR}/${cve}.msf.txt" 2>/dev/null || true
      if grep -q -E 'Exploit|Module' "${EXPLOITS_DIR}/${cve}.msf.txt" 2>/dev/null; then
        echo "CVE: ${cve}" >> "${MSF_SUM}"
        sed -n '1,120p' "${EXPLOITS_DIR}/${cve}.msf.txt" >> "${MSF_SUM}"
        echo "----" >> "${MSF_SUM}"
      fi
    done < "${CVES_FILE}"
  fi

  echo "[*] Exploit lookup finished. Results in ${EXPLOITS_DIR}"
}

# -------------------------
# Assemble final markdown report
# -------------------------
assemble_report() {
  echo "[*] Assembling final report -> ${REPORT}"
  {
    echo "# Recon Report"
    echo
    echo "Generated: $(date)"
    echo
    echo "## Summary of modules run"
    echo "- nmap: ${DO_NMAP}"
    echo "- nuclei: ${DO_NUCLEI}"
    echo "- nikto: ${DO_NIKTO}"
    echo "- exploit-finding: ${DO_EXPLOITS}"
    echo
    echo "## Resolved hosts (host | ip)"
    echo '```'
    cat "${RESOLVED}" 2>/dev/null || echo "(none)"
    echo '```'
    echo
    echo "## HTTP endpoints probed"
    echo '```'
    cat "${HTTP_URLS}" 2>/dev/null || echo "(none)"
    echo '```'
    echo
    if [[ "${DO_NUCLEI}" == true ]]; then
      echo "## Nuclei (first 200 lines)"
      echo '```'
      head -n 200 "${NUCLEI_DIR}/nuclei_results.txt" 2>/dev/null || echo "(no nuclei output)"
      echo '```'
      echo
    fi
    if [[ "${DO_NIKTO}" == true ]]; then
      echo "## Nikto results (per host, first 120 lines)"
      for f in "${NIKTO_DIR}"/*.nikto.txt; do
        [[ -f "$f" ]] || continue
        echo "### $(basename "$f")"
        echo '```'
        sed -n '1,120p' "$f"
        echo '```'
      done
      echo
    fi
    if [[ "${DO_NMAP}" == true ]]; then
      echo "## Nmap discovered services"
      echo '```'
      if [[ -s "${SERVICES_FILE}" ]]; then
        column -t -s '|' "${SERVICES_FILE}" || cat "${SERVICES_FILE}"
      else
        echo "(no services discovered)"
      fi
      echo '```'
      echo
    fi
    echo "## Discovered CVEs"
    echo '```'
    if [[ -s "${CVES_FILE}" ]]; then
      cat "${CVES_FILE}"
    else
      echo "(no CVEs discovered)"
    fi
    echo '```'
    echo
    if [[ "${DO_EXPLOITS}" == true ]]; then
      echo "## Searchsploit summary (extract)"
      echo '```'
      head -n 300 "${EXPLOITS_DIR}/searchsploit_summary.txt" 2>/dev/null || echo "(no searchsploit results)"
      echo '```'
      echo
      echo "## Metasploit search summary (extract)"
      echo '```'
      head -n 300 "${EXPLOITS_DIR}/msf_summary.txt" 2>/dev/null || echo "(no msf results)"
      echo '```'
      echo
    fi
    echo "## Raw output locations"
    echo "- nmap: ${NMAP_DIR}"
    echo "- nuclei: ${NUCLEI_DIR}"
    echo "- nikto: ${NIKTO_DIR}"
    echo "- exploits: ${EXPLOITS_DIR}"
    echo
    echo "## Notes"
    echo "- This script only searches for exploit references (searchsploit / Metasploit)."
    echo "- Do NOT run exploit modules automatically without explicit permission."
  } > "${REPORT}"
  echo "[*] Report produced: ${REPORT}"
}

# -------------------------
# Main
# -------------------------
main() {
  parse_args "$@"
  check_tools

  # sanitize input
  grep -E -v '^\s*#' "${TARGETS_FILE}" | safe_trim | grep -E -v '^$' > "${RAW}"
  > "${DOMAINS}"; > "${IPS}"
  while read -r entry; do
    if [[ "$entry" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$entry" >> "${IPS}"
    else
      echo "$entry" >> "${DOMAINS}"
    fi
  done < "${RAW}"

  discover_subs
  resolve_hosts
  probe_http
  run_nuclei
  run_nikto
  run_nmap
  parse_nmap
  extract_nuclei_cves
  exploit_lookup
  assemble_report

  echo "[*] All done. Outputs: ${OUTROOT}"
}

# invoke main with all arguments
main "$@"
