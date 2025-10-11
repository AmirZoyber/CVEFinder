#!/usr/bin/env bash
#
# recon.sh - modular reconnaissance & scanning wrapper
# Author: generated (example). Modify as needed.
#
# REQUIREMENTS (install these tools before use):
#  - subfinder
#  - nmap
#  - nikto
#  - nuclei
#  - searchsploit (exploitdb)
#  - msfconsole (Metasploit) (optional)
#
# WARNING: Only use against authorized targets.

set -o errexit
set -o pipefail
set -o nounset

### --------------------------
### Config / defaults
### --------------------------
TARGET_FILE=""
OUT_ROOT="recon_results_$(date +%Y%m%d_%H%M%S)"
DO_NMAP=false
DO_NIKTO=false
DO_NUCLEI=false
DO_SUBFINDER=false
DO_FULL=false
VERBOSE=true

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

# Logging helper
log_file_global=""

### --------------------------
### Utility functions
### --------------------------
log() {
  local msg="$1"
  local level="${2:-INFO}"
  local ts
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  echo -e "[$ts] [$level] $msg" | tee -a "$log_file_global"
}

info()    { echo -e "${BLUE}${BOLD}[+]${RESET} $1"; log "$1" "INFO"; }
success() { echo -e "${GREEN}${BOLD}[✓]${RESET} $1"; log "$1" "OK"; }
warn()    { echo -e "${YELLOW}${BOLD}[!]${RESET} $1"; log "$1" "WARN"; }
error()   { echo -e "${RED}${BOLD}[-]${RESET} $1"; log "$1" "ERROR"; }

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1 || { warn "Command '$1' not found in PATH."; return 1; }
  return 0
}

mk_outdir() {
  local dir="$1"
  mkdir -p "$dir"
  log_file_global="$dir/$(date +%Y%m%d_%H%M%S)_recon.log"
  touch "$log_file_global"
  info "Logging to $log_file_global"
}

is_ip() {
  # basic IPv4 check
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_domain() {
  # simple heuristic: contains letters or hyphens and dots
  [[ $1 =~ [A-Za-z] ]] && [[ $1 != *" "* ]]
}

resolve_domain_to_ips() {
  local domain="$1"
  local outfile="$2"
  # try 'dig', 'getent', 'host' as available
  if ensure_cmd dig >/dev/null 2>&1; then
    dig +short A "$domain" | sed '/^$/d' | tee -a "$outfile"
  elif ensure_cmd getent >/dev/null 2>&1; then
    getent ahosts "$domain" | awk '/STREAM/ {print $1}' | sort -u | tee -a "$outfile"
  elif ensure_cmd host >/dev/null 2>&1; then
    host -t A "$domain" | awk '/has address/ {print $4}' | tee -a "$outfile"
  else
    warn "No DNS resolution tool found (dig/getent/host). Skipping DNS resolution for $domain"
  fi
}

# Parse nmap XML for searchsploit
run_searchsploit_on_nmap() {
  local nmap_xml="$1"
  local outdir="$2"
  if ensure_cmd searchsploit >/dev/null 2>&1; then
    info "Running searchsploit --nmap on $nmap_xml"
    searchsploit --nmap "$nmap_xml" | tee "$outdir/searchsploit_from_nmap.txt"
    success "searchsploit saved to $outdir/searchsploit_from_nmap.txt"
  else
    warn "searchsploit not installed, skipping."
  fi
}

# Import nmap XML into Metasploit DB and list vulns (if msfconsole exists)
run_msf_import_nmap() {
  local nmap_xml="$1"
  local outdir="$2"
  if ensure_cmd msfconsole >/dev/null 2>&1; then
    info "Attempting to import Nmap XML into Metasploit DB (msfconsole). This may take a while."
    # create temporary rc script to import and list vulns then exit
    local rcfile
    rcfile="$(mktemp)"
    cat >"$rcfile" <<EOF
db_import $nmap_xml
vulns
exit -y
EOF
    msfconsole -q -r "$rcfile" 2>&1 | tee "$outdir/metasploit_import.txt"
    rm -f "$rcfile"
    success "Metasploit import logged to $outdir/metasploit_import.txt"
  else
    warn "msfconsole not found; skipping Metasploit import."
  fi
}

### --------------------------
### Scanning modules
### --------------------------

run_subfinder_and_resolve() {
  local targets_file="$1"
  local outdir="$2"
  local subfinder_out="$outdir/subfinder_raw.txt"
  local subdomains_file="$outdir/subdomains.txt"
  local resolved_ips="$outdir/resolved_ips.txt"

  >"$subfinder_out"
  >"$subdomains_file"
  >"$resolved_ips"

  ensure_cmd subfinder || warn "subfinder not found. Install it to enumerate subdomains."

  info "Collecting domains from target file for subdomain enumeration..."
  # gather domain lines only
  awk 'NF && $0 !~ /^#/ {print $0}' "$targets_file" | while read -r t; do
    if is_domain "$t" && ! is_ip "$t"; then
      echo "$t" >> "$subfinder_out"
    fi
  done

  if [[ ! -s "$subfinder_out" ]]; then
    warn "No domains detected in target file for subfinder."
    return 0
  fi

  # Run subfinder per domain (safer to run per domain than all at once)
  while read -r domain; do
    info "Running subfinder for $domain"
    if ensure_cmd subfinder >/dev/null 2>&1; then
      subfinder -silent -d "$domain" 2>/dev/null | tee -a "$subdomains_file"
    else
      warn "subfinder not available, cannot enumerate $domain"
    fi
  done < "$subfinder_out"

  # remove duplicates
  sort -u "$subdomains_file" -o "$subdomains_file"

  # resolve subdomains to IPs
  info "Resolving subdomains to IPs..."
  while read -r sd; do
    resolve_domain_to_ips "$sd" "$resolved_ips"
  done < "$subdomains_file"

  # remove duplicates and empty lines
  sort -u "$resolved_ips" -o "$resolved_ips" || true

  success "Subfinder results: $subdomains_file"
  success "Resolved IPs: $resolved_ips"
}

run_nmap_quick() {
  local target="$1"
  local outdir="$2"
  local base
  base="$outdir/nmap_quick_$(echo "$target" | tr '/' '_' | tr ':' '_' )"
  info "Running quick nmap (ports+service) on $target"
  nmap -Pn -T4 -sS -sV --min-rate=500 -oA "$base" "$target" 2>&1 | tee "$base.nmap.log"
  success "Nmap quick results saved to ${base}.*"
}

run_nmap_vuln() {
  local target="$1"
  local outdir="$2"
  local base
  base="$outdir/nmap_vuln_$(echo "$target" | tr '/' '_' | tr ':' '_' )"
  info "Running nmap vulnerability-oriented scan on $target (service detection + vuln scripts)"
  # Note: adjust script selection as needed. --script vuln runs the community vuln scripts.
  nmap -Pn -T4 -sV --script vuln -oA "$base" "$target" 2>&1 | tee "$base.nmap.log"
  success "Nmap vuln results saved to ${base}.*"
  # Return XML path for searchsploit import
  echo "${base}.xml"
}

run_nikto() {
  local target="$1"
  local outdir="$2"
  local base
  base="$outdir/nikto_$(echo "$target" | tr '/' '_' | tr ':' '_' )"
  if ensure_cmd nikto >/dev/null 2>&1; then
    info "Running nikto on $target"
    # nikto expects a host (domain/ip with optional port)
    nikto -h "$target" -output "$base.txt" 2>&1 | tee "$base.nikto.log"
    success "Nikto results: $base.txt"
  else
    warn "nikto not installed; skipping nikto for $target"
  fi
}

run_nuclei() {
  local targets_list="$1"  # file containing list of targets
  local outdir="$2"
  if ensure_cmd nuclei >/dev/null 2>&1; then
    info "Running nuclei against list: $targets_list"
    nuclei -l "$targets_list" -o "$outdir/nuclei_results.txt" 2>&1 | tee "$outdir/nuclei.log"
    success "Nuclei results: $outdir/nuclei_results.txt"
  else
    warn "nuclei not found; skipping nuclei."
  fi
}

### --------------------------
### Argument parsing
### --------------------------
print_help() {
cat <<EOF
Usage: $0 --targets <file> [options]

Options:
  --targets <file>   File with targets (IP or domain per line)
  --folder <name>    Output folder name (default: $OUT_ROOT)
  --nmap             Run nmap (if used alone => quick port/service scan)
  --nikto            Run nikto against targets
  --nuclei           Run nuclei against targets list
  --subfinder        Run subfinder (only) and exit (still requires --targets)
  --full             Run nmap + nikto + nuclei + searchsploit + metasploit import
  --help             Show this help

Examples:
  $0 --targets targets.txt --folder run1 --nmap
  $0 --targets targets.txt --subfinder
  $0 --targets targets.txt --folder run2 --full

NOTE: Ensure you have permission to scan the targets.
EOF
}

# parse long options
if [[ $# -eq 0 ]]; then
  print_help
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets)
      TARGET_FILE="$2"; shift 2;;
    --folder)
      OUT_ROOT="$2"; shift 2;;
    --nmap)
      DO_NMAP=true; shift;;
    --nikto)
      DO_NIKTO=true; shift;;
    --nuclei)
      DO_NUCLEI=true; shift;;
    --subfinder)
      DO_SUBFINDER=true; shift;;
    --full)
      DO_FULL=true; shift;;
    --help|-h)
      print_help; exit 0;;
    *)
      warn "Unknown option: $1"; print_help; exit 1;;
  esac
done

### --------------------------
### Validate input
### --------------------------
if [[ -z "$TARGET_FILE" ]]; then
  error "No --targets file provided."
  print_help
  exit 2
fi

if [[ ! -f "$TARGET_FILE" ]]; then
  error "Targets file '$TARGET_FILE' not found."
  exit 2
fi

mk_outdir "$OUT_ROOT"

# canonicalize targets: strip comments and blanks
targets_clean="$OUT_ROOT/targets_clean.txt"
awk 'NF && $0 !~ /^#/ {print $1}' "$TARGET_FILE" | sort -u > "$targets_clean"

if [[ ! -s "$targets_clean" ]]; then
  error "No valid targets found in $TARGET_FILE (after removing comments/empty lines)."
  exit 2
fi

info "Targets processed: $(wc -l < "$targets_clean") items"

### --------------------------
### Step 1: If domains present, run subfinder -> resolve -> update IP list
### --------------------------
# We'll detect domains and run subfinder if any domain exists.
any_domains=false
while read -r t; do
  if is_domain "$t" && ! is_ip "$t"; then
    any_domains=true
    break
  fi
done < "$targets_clean"

if $any_domains; then
  info "Domains detected in targets. Running subfinder + DNS resolution."
  run_subfinder_and_resolve "$targets_clean" "$OUT_ROOT"
  # combine original IPs + resolved ips into a single ips file
  ips_file="$OUT_ROOT/ips_combined.txt"
  >"$ips_file"
  # original IPs from targets
  awk 'NF && $0 !~ /^#/ {print $1}' "$targets_clean" | while read -r t; do
    if is_ip "$t"; then echo "$t" >> "$ips_file"; fi
  done
  # append resolved ips
  if [[ -f "$OUT_ROOT/resolved_ips.txt" ]]; then
    cat "$OUT_ROOT/resolved_ips.txt" >> "$ips_file"
  fi
  sort -u "$ips_file" -o "$ips_file" || true
  success "Combined IP list: $ips_file"
else
  info "No domains in targets. Gathering IP list from targets."
  ips_file="$OUT_ROOT/ips_combined.txt"
  awk 'NF && $0 !~ /^#/ {print $1}' "$targets_clean" | while read -r t; do
    if is_ip "$t"; then echo "$t"; fi
  done > "$ips_file"
  [[ -s "$ips_file" ]] || warn "No IPs found in targets."
fi

# If user asked only for subfinder, exit now
if $DO_SUBFINDER && ! $DO_FULL && ! $DO_NMAP && ! $DO_NIKTO && ! $DO_NUCLEI; then
  info "--subfinder specified alone: finished enumeration. Outputs in $OUT_ROOT"
  exit 0
fi

### --------------------------
### Step 2: Run scans according to flags
### --------------------------

# prepare list of "targets for HTTP scanners" (domains + IPs)
targets_for_http="$OUT_ROOT/targets_for_http.txt"
awk 'NF && $0 !~ /^#/ {print $1}' "$targets_clean" > "$targets_for_http"
# if subdomains enumerated, add them to http targets
if [[ -f "$OUT_ROOT/subdomains.txt" ]]; then
  cat "$OUT_ROOT/subdomains.txt" >> "$targets_for_http"
fi
sort -u "$targets_for_http" -o "$targets_for_http" || true

# determine which scans to run
if $DO_FULL; then
  DO_NMAP=true
  DO_NIKTO=true
  DO_NUCLEI=true
fi

# If only --nmap provided and nothing else -> quick port/service scan
only_nmap_mode=$DO_NMAP
if $DO_NMAP; then
  if $DO_NIKTO || $DO_NUCLEI || $DO_FULL; then
    only_nmap_mode=false
  fi
fi

# Loop through IPs / hosts and run appropriate tools
while read -r tgt; do
  [[ -z "$tgt" ]] && continue
  # choose a per-target subdir
  tgt_dir="$OUT_ROOT/targets/$(echo "$tgt" | tr '/: ' '_' )"
  mkdir -p "$tgt_dir"

  # Nmap
  if $DO_NMAP; then
    if $only_nmap_mode; then
      run_nmap_quick "$tgt" "$tgt_dir"
    else
      # run vuln-oriented nmap and capture returned XML for searchsploit/metasploit
      nmap_xml="$(run_nmap_vuln "$tgt" "$tgt_dir")"
      if [[ -n "$nmap_xml" && -f "$nmap_xml" ]]; then
        run_searchsploit_on_nmap "$nmap_xml" "$tgt_dir" || true
        run_msf_import_nmap "$nmap_xml" "$tgt_dir" || true
      fi
    fi
  fi

  # Nikto (only for HTTP-style hosts)
  if $DO_NIKTO; then
    # run only for hostnames or IPs that are likely to be HTTP servers; we will still attempt
    run_nikto "$tgt" "$tgt_dir"
  fi

done < "$targets_for_http"

# Nuclei: run once over list of hosts that nuclei expects
if $DO_NUCLEI; then
  # prefer subdomains list (hosts with HTTP) else fallback to targets_for_http
  nuclei_targets="$OUT_ROOT/subdomains.txt"
  if [[ ! -s "$nuclei_targets" ]]; then
    nuclei_targets="$targets_for_http"
  fi
  if [[ -s "$nuclei_targets" ]]; then
    run_nuclei "$nuclei_targets" "$OUT_ROOT"
  else
    warn "No targets available for nuclei."
  fi
fi

success "All requested scans finished. Check results in $OUT_ROOT"

# Summarize key result files
echo
echo -e "${BOLD}Quick summary of outputs:${RESET}"
ls -1 "$OUT_ROOT" | sed -n '1,200p' | sed 's/^/  - /'
echo
info "Main log: $log_file_global"
