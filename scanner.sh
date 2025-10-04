#!/usr/bin/env bash
# scanner_fixed.sh
# Usage: sudo ./scanner_fixed.sh --targets <file> [--nmap] [--nuclei] [--nikto] [--exploit] [--full] [--help]
#
# Manual long-option parser (no getopt required).
# Fixes:
#  - Nmap options are passed as an array to avoid word-splitting/quoting issues.
#  - httpx invocation tries multiple common flag combinations and falls back to synthesized URLs.
#
set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Defaults / flags
# -------------------------
TARGETS_FILE=""
DO_NMAP=false
DO_NUCLEI=false
DO_NIKTO=false
DO_EXPLOITS=false
DO_FULL=false

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="recon_fixed_${TIMESTAMP}"
mkdir -p "${OUTDIR}"

# -------------------------
# Usage
# -------------------------
usage() {
  cat <<EOF
Usage: $0 --targets <file> [options]

Options:
  --targets <file>   Targets file (one domain or IP per line) (required)
  --nmap             Run nmap port & service scan
  --nuclei           Run nuclei on HTTP endpoints
  --nikto            Run nikto on HTTP endpoints
  --exploit          Run exploit-finding (searchsploit + msf search). This will enable --nmap and --nikto automatically.
  --full             Enable all (nmap + nuclei + nikto + exploit-finding)
  --help             Show this help

Examples:
  $0 --targets mytargets.txt --nmap --nuclei
  $0 --targets mytargets.txt --full
EOF
}

# -------------------------
# Simple manual long option parser
# -------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets)
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        echo "Error: --targets requires a value" >&2
        usage
        exit 1
      fi
      TARGETS_FILE="$2"
      shift 2
      ;;
    --nmap)
      DO_NMAP=true
      shift
      ;;
    --nuclei)
      DO_NUCLEI=true
      shift
      ;;
    --nikto)
      DO_NIKTO=true
      shift
      ;;
    --exploit)
      DO_EXPLOITS=true
      shift
      ;;
    --full)
      DO_FULL=true
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Apply --full
if [[ "${DO_FULL}" == true ]]; then
  DO_NMAP=true; DO_NUCLEI=true; DO_NIKTO=true; DO_EXPLOITS=true
fi

# If exploit requested, force required modules
if [[ "${DO_EXPLOITS}" == true ]]; then
  DO_NMAP=true
  DO_NIKTO=true
fi

# Validate targets file
if [[ -z "${TARGETS_FILE}" ]]; then
  echo "[!] targets file required (--targets)." >&2
  usage
  exit 2
fi
if [[ ! -f "${TARGETS_FILE}" ]]; then
  echo "[!] targets file '${TARGETS_FILE}' not found." >&2
  exit 3
fi

# -------------------------
# Tool checks (only for selected options)
# -------------------------
REQUIRED_TOOLS=(subfinder dnsx)
# httpx optional but we will try to use it if present
if command -v httpx >/dev/null 2>&1; then
  REQUIRED_TOOLS+=(httpx)
fi
if [[ "${DO_NMAP}" == true ]]; then REQUIRED_TOOLS+=(nmap); fi
if [[ "${DO_NUCLEI}" == true ]]; then REQUIRED_TOOLS+=(nuclei); fi
if [[ "${DO_NIKTO}" == true ]]; then REQUIRED_TOOLS+=(nikto); fi
if [[ "${DO_EXPLOITS}" == true ]]; then REQUIRED_TOOLS+=(searchsploit msfconsole); fi

MISSING=()
for t in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v ${t} >/dev/null 2>&1; then
    MISSING+=("${t}")
  fi
done
if (( ${#MISSING[@]} )); then
  echo "[!] Missing required tools for selected options: ${MISSING[*]}" >&2
  echo "    Install them and re-run." >&2
  # Note: we don't force-exit if httpx missing; httpx already included in REQUIRED_TOOLS conditionally
  exit 4
fi

# -------------------------
# File layout
# -------------------------
RAW="${OUTDIR}/raw_targets.txt"
DOMAINS="${OUTDIR}/domains.txt"
IPS="${OUTDIR}/ips.txt"
SUBS="${OUTDIR}/subdomains.txt"
COMBINED="${OUTDIR}/combined_domains.txt"
RESOLVED="${OUTDIR}/resolved_hosts.txt"   # host|ip
HTTP_URLS="${OUTDIR}/httpx_urls.txt"
NMAP_DIR="${OUTDIR}/nmap"
NUCLEI_DIR="${OUTDIR}/nuclei"
NIKTO_DIR="${OUTDIR}/nikto"
EXPLOITS_DIR="${OUTDIR}/exploits"
SERVICES_FILE="${OUTDIR}/discovered_services.txt"  # ip|port|proto|service|version
CVES_FILE="${OUTDIR}/discovered_cves.txt"
REPORT="${OUTDIR}/final_report.md"

mkdir -p "${NMAP_DIR}" "${NUCLEI_DIR}" "${NIKTO_DIR}" "${EXPLOITS_DIR}"

# -------------------------
# Step 0: sanitize input
# -------------------------
grep -E -v '^\s*#' "${TARGETS_FILE}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -E -v '^$' > "${RAW}"

# split ips/domains
> "${DOMAINS}"; > "${IPS}"
while read -r entry; do
  if [[ "${entry}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "${entry}" >> "${IPS}"
  else
    echo "${entry}" >> "${DOMAINS}"
  fi
done < "${RAW}"

# -------------------------
# Step 1: subdomain discovery
# -------------------------
if [[ -s "${DOMAINS}" ]]; then
  echo "[*] Running subfinder..."
  subfinder -dL "${DOMAINS}" -silent -o "${SUBS}" 2>/dev/null || true
else
  echo "[*] No domains to run subfinder on."
fi

cat "${DOMAINS}" "${SUBS}" 2>/dev/null | sort -u > "${COMBINED}" || true

# -------------------------
# Step 2: resolve hosts with dnsx (host|ip)
# -------------------------
if [[ -s "${COMBINED}" ]]; then
  echo "[*] Resolving domains with dnsx..."
  dnsx -a -silent -l "${COMBINED}" | awk '{print $1 "|" $2 }' | sort -u > "${RESOLVED}" || true
fi

# include raw IPs as host|ip
if [[ -s "${IPS}" ]]; then
  while read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! grep -q "|${ip}$" "${RESOLVED}" 2>/dev/null; then
      echo "${ip}|${ip}" >> "${RESOLVED}"
    fi
  done < "${IPS}"
fi
sort -u "${RESOLVED}" -o "${RESOLVED}" || true

# -------------------------
# Helper: try httpx with different flag variants
# -------------------------
run_httpx() {
  # $1 = input hosts file
  # $2 = output file
  local in="$1"
  local out="$2"
  # try variant 1: common PD httpx form (short -l, long --silent)
  if command -v httpx >/dev/null 2>&1; then
    echo "[*] Trying httpx variant: httpx -l <file> --silent -threads 50 -status-code -o <out>"
    set +e
    httpx -l "${in}" --silent -threads 50 -status-code -o "${out}" 2> "${OUTDIR}/httpx_try1.err"
    rc=$?
    set -e
    if [[ ${rc} -eq 0 && -s "${out}" ]]; then
      echo "[*] httpx variant1 succeeded -> ${out}"
      return 0
    fi

    # try variant 2: older/alternate forms (single-dash long-word)
    echo "[*] Trying httpx variant: httpx -l <file> -silent -threads 50 -status-code -o <out>"
    set +e
    httpx -l "${in}" -silent -threads 50 -status-code -o "${out}" 2> "${OUTDIR}/httpx_try2.err"
    rc=$?
    set -e
    if [[ ${rc} -eq 0 && -s "${out}" ]]; then
      echo "[*] httpx variant2 succeeded -> ${out}"
      return 0
    fi

    # try variant 3: minimal (just -l and --silent)
    echo "[*] Trying httpx minimal variant: httpx -l <file> --silent -o <out>"
    set +e
    httpx -l "${in}" --silent -o "${out}" 2> "${OUTDIR}/httpx_try3.err"
    rc=$?
    set -e
    if [[ ${rc} -eq 0 && -s "${out}" ]]; then
      echo "[*] httpx minimal succeeded -> ${out}"
      return 0
    fi

    # all attempts failed
    echo "[!] httpx attempts failed. Check ${OUTDIR}/httpx_try1.err ${OUTDIR}/httpx_try2.err ${OUTDIR}/httpx_try3.err for details."
    return 1
  else
    echo "[*] httpx not installed; skipping httpx probing."
    return 1
  fi
}

# -------------------------
# Step 3: probe HTTP endpoints with httpx (for nuclei/nikto)
# -------------------------
cut -d'|' -f1 "${RESOLVED}" | sort -u > "${OUTDIR}/hosts_list.tmp" || true
echo "[*] Probing HTTP endpoints with httpx..."
HTTPX_SUCCESS=false
if [[ -s "${OUTDIR}/hosts_list.tmp" ]]; then
  if run_httpx "${OUTDIR}/hosts_list.tmp" "${HTTP_URLS}"; then
    HTTPX_SUCCESS=true
  fi
fi

# synthesize http/https candidates if httpx empty or failed
if [[ "${HTTPX_SUCCESS}" != true || ! -s "${HTTP_URLS}" ]]; then
  echo "[*] httpx returned no live URLs or not available; producing http/https candidates..."
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
fi

# -------------------------
# Step 4: nuclei
# -------------------------
if [[ "${DO_NUCLEI}" == true ]]; then
  echo "[*] Running nuclei..."
  NUCLEI_OUT="${NUCLEI_DIR}/nuclei_results.txt"
  NUCLEI_OUT_JSON="${NUCLEI_DIR}/nuclei_results.jsonl"
  nuclei -l "${HTTP_URLS}" -severity critical,high -c 50 -rate 150 -o "${NUCLEI_OUT}" -json -oJ "${NUCLEI_OUT_JSON}" || true
  echo "[*] nuclei finished -> ${NUCLEI_OUT}"
fi

# -------------------------
# Step 5: nikto
# -------------------------
if [[ "${DO_NIKTO}" == true ]]; then
  echo "[*] Running nikto on HTTP endpoints..."
  NIKTO_THREADS=8
  while read -r url; do
    [[ -z "$url" ]] && continue
    h=$(echo "${url}" | sed -E 's|https?://||; s|[:/].*||')
    out="${NIKTO_DIR}/${h//[:\/]/_}.nikto.txt"
    nikto -h "${url}" -Tuning 123b -timeout 10 -nointeractive -o "${out}" 2>/dev/null || true &
    while (( $(jobs -r | wc -l) >= NIKTO_THREADS )); do sleep 1; done
  done < "${HTTP_URLS}"
  wait
  echo "[*] nikto finished. outputs in ${NIKTO_DIR}"
fi

# -------------------------
# Step 6: nmap (use array for options to preserve word splitting)
# -------------------------
TARGET_IPS="${OUTDIR}/target_ips.txt"
cut -d'|' -f2 "${RESOLVED}" | sort -u > "${TARGET_IPS}" || true

if [[ "${DO_NMAP}" == true ]]; then
  echo "[*] Running nmap scans..."
  # use array to avoid quoting issues
  NMAP_COMMON=( -Pn -sS -p- -sV --open -T4 --min-rate 500 )
  if nmap --script-help vulners >/dev/null 2>&1; then
    NMAP_SCRIPTS="vuln,vulners"
  else
    NMAP_SCRIPTS="vuln"
  fi

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    safe=$(echo "$ip" | tr '/' '_')
    outbase="${NMAP_DIR}/${safe}"
    if [[ $EUID -ne 0 ]]; then
      echo "    [!] Not root - using -sT for ${ip}"
      # pass array and then add -sT (note: -sT replaces -sS)
      nmap "${NMAP_COMMON[@]/-sS/-sT}" --script="${NMAP_SCRIPTS}" -oA "${outbase}" "${ip}" || true
    else
      nmap "${NMAP_COMMON[@]}" --script="${NMAP_SCRIPTS}" -oA "${outbase}" "${ip}" || true
    fi
  done < "${TARGET_IPS}"
  echo "[*] nmap scans finished. outputs in ${NMAP_DIR}"
fi

# -------------------------
# Step 7: parse nmap + collect CVEs
# -------------------------
> "${SERVICES_FILE}"
> "${CVES_FILE}"
if [[ "${DO_NMAP}" == true ]]; then
  echo "[*] Parsing nmap outputs for services and CVEs..."
  for nm in "${NMAP_DIR}"/*.nmap; do
    [[ -f "$nm" ]] || continue
    ipfile=$(basename "${nm}" .nmap)
    awk '/^[0-9]+\/tcp/ {print}' "${nm}" | while read -r line; do
      port_proto=$(echo "${line}" | awk '{print $1}')
      port=$(echo "${port_proto}" | cut -d'/' -f1)
      proto=$(echo "${port_proto}" | cut -d'/' -f2)
      service=$(echo "${line}" | awk '{print $3}')
      version=$(echo "${line}" | cut -d' ' -f4- | sed 's/^[[:space:]]*//')
      printf "%s|%s|%s|%s|%s\n" "${ipfile}" "${port}" "${proto}" "${service}" "${version}" >> "${SERVICES_FILE}"
    done

    for f in "${NMAP_DIR}/${ipfile}"*; do
      [[ -f "$f" ]] || continue
      grep -Eo 'CVE-[0-9]{4}-[0-9]+' "$f" | sort -u >> "${CVES_FILE}" || true
    done
  done
  sort -u "${SERVICES_FILE}" -o "${SERVICES_FILE}" || true
  sort -u "${CVES_FILE}" -o "${CVES_FILE}" || true
fi

# extract CVEs from nuclei
if [[ "${DO_NUCLEI}" == true ]]; then
  if [[ -f "${NUCLEI_DIR}/nuclei_results.jsonl" ]]; then
    echo "[*] Extracting CVEs from nuclei output..."
    if command -v jq >/dev/null 2>&1; then
      jq -r '..|strings|match("CVE-[0-9]{4}-[0-9]+")?.string // empty' "${NUCLEI_DIR}/nuclei_results.jsonl" | sort -u >> "${CVES_FILE}" || true
    else
      grep -Eo 'CVE-[0-9]{4}-[0-9]+' "${NUCLEI_DIR}/nuclei_results.jsonl" | sort -u >> "${CVES_FILE}" || true
    fi
    sort -u "${CVES_FILE}" -o "${CVES_FILE}" || true
  fi
fi

# -------------------------
# Step 8: exploit-finding (searchsploit + msf)
# -------------------------
if [[ "${DO_EXPLOITS}" == true ]]; then
  echo "[*] Running exploit-finding (searchsploit + msf searches)..."
  SS_SUM="${EXPLOITS_DIR}/searchsploit_summary.txt"
  MSF_SUM="${EXPLOITS_DIR}/msf_summary.txt"
  > "${SS_SUM}"; > "${MSF_SUM}"

  if [[ -s "${SERVICES_FILE}" ]]; then
    while IFS='|' read -r ip port proto service version; do
      [[ -z "${service}" ]] && continue
      q="${service}"
      if [[ -n "${version// }" ]]; then
        qver="${service} ${version}"
        echo "[*] searchsploit -> ${qver}"
        if searchsploit --help 2>&1 | grep -q -- '--json'; then
          searchsploit --json "${qver}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.json" 2>/dev/null || true
          if [[ -s "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.json" ]]; then
            jq -r '.[] | "\(.title) -- \(.path) -- \(.date)"' "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.json" >> "${SS_SUM}" || true
          fi
        else
          searchsploit -w --colour 0 "${qver}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.txt" 2>/dev/null || true
          grep -E 'Exploit Title|EDB-ID|Date' "${EXPLOITS_DIR}/${ip}_${port}_${service}_ver.txt" 2>/dev/null >> "${SS_SUM}" || true
        fi
      fi
      echo "[*] searchsploit -> ${service}"
      if searchsploit --help 2>&1 | grep -q -- '--json'; then
        searchsploit --json "${service}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.json" 2>/dev/null || true
        if [[ -s "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.json" ]]; then
          jq -r '.[] | "\(.title) -- \(.path) -- \(.date)"' "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.json" >> "${SS_SUM}" || true
        fi
      else
        searchsploit -w --colour 0 "${service}" > "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.txt" 2>/dev/null || true
        grep -E 'Exploit Title|EDB-ID|Date' "${EXPLOITS_DIR}/${ip}_${port}_${service}_svc.txt" 2>/dev/null >> "${SS_SUM}" || true
      fi
    done < "${SERVICES_FILE}"
  fi

  if [[ -s "${CVES_FILE}" ]]; then
    while read -r cve; do
      [[ -z "$cve" ]] && continue
      echo "[*] searchsploit -> ${cve}"
      if searchsploit --help 2>&1 | grep -q -- '--json'; then
        searchsploit --json "${cve}" > "${EXPLOITS_DIR}/${cve}.json" 2>/dev/null || true
        jq -r '.[] | "\(.title) -- \(.path) -- \(.date)"' "${EXPLOITS_DIR}/${cve}.json" 2>/dev/null >> "${SS_SUM}" || true
      else
        searchsploit -w --colour 0 "${cve}" > "${EXPLOITS_DIR}/${cve}.txt" 2>/dev/null || true
        grep -E 'Exploit Title|EDB-ID|Date' "${EXPLOITS_DIR}/${cve}.txt" 2>/dev/null >> "${SS_SUM}" || true
      fi
    done < "${CVES_FILE}"
  fi

  # Metasploit search (non-interactive)
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

  # product tokens from SERVICES_FILE
  if [[ -s "${SERVICES_FILE}" ]]; then
    awk -F'|' '{print $4 " " $5}' "${SERVICES_FILE}" | sed 's/^[ \t]*//; s/[ \t]*$//' | sort -u | while read -r token; do
      [[ -z "$token" ]] && continue
      if echo "$token" | grep -Eiq 'open|tcp|http|ssl|unknown|service'; then
        continue
      fi
      q=$(echo "$token" | sed 's/[^A-Za-z0-9_.- ]/ /g' | awk '{print $1" "$2}' | sed 's/ $//; s/  / /g')
      if [[ -z "$q" ]]; then continue; fi
      echo "[*] msf -> searching for '${q}'"
      msfconsole -q -x "search name:${q}; exit" > "${EXPLOITS_DIR}/product_${q// /_}.msf.txt" 2>/dev/null || true
      if grep -q -E 'Exploit|Module' "${EXPLOITS_DIR}/product_${q// /_}.msf.txt" 2>/dev/null; then
        echo "Product: ${q}" >> "${MSF_SUM}"
        sed -n '1,120p' "${EXPLOITS_DIR}/product_${q// /_}.msf.txt" >> "${MSF_SUM}"
        echo "----" >> "${MSF_SUM}"
      fi
    done
  fi

  echo "[*] Exploit-finding finished. Results in ${EXPLOITS_DIR}"
fi

# -------------------------
# Step 9: assemble final markdown report
# -------------------------
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

echo "[*] Done. Report: ${REPORT}"
echo "[*] All raw outputs are in: ${OUTDIR}"
