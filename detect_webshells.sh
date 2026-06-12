#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# JSP Webshell + PeopleSoft IOC Scanner
# ============================================================
#
# Purpose:
#   Recursively scans a target directory for:
#     1. Suspicious JSP webshell patterns
#     2. Oracle PeopleSoft / ShinyHunters / UNC6240 indicators
#     3. Known filenames, paths, hashes, and C2 strings
#
# Usage:
#   ./detect_webshells.sh /path/to/webroot
#   ./detect_webshells.sh /u01/app/psoft
#   ./detect_webshells.sh .
#
# Notes:
#   Findings are triage leads, not definitive proof of compromise.
#   Validate with EDR, file metadata, web access logs, known-good baselines,
#   and forensic review.
#
# ============================================================

SEARCH_DIR="${1:-.}"

echo "============================================================"
echo "[*] JSP Webshell + PeopleSoft IOC Scanner"
echo "[*] Scanning directory: $SEARCH_DIR"
echo "============================================================"

if [[ ! -d "$SEARCH_DIR" ]]; then
  echo "[ERROR] Directory does not exist: $SEARCH_DIR"
  exit 1
fi

section() {
  echo
  echo "==== $1 ===="
}

print_hit_block() {
  local label="$1"
  local value="$2"
  local hits="$3"

  if [[ -n "$hits" ]]; then
    echo
    echo "[HIT] $label: $value"
    echo "$hits" | head -200
  fi
}

# ------------------------------------------------------------
# 1. Suspicious JSP webshell patterns
# ------------------------------------------------------------

section "1. Suspicious JSP code patterns"

JSP_PATTERNS=(
  "Runtime\\.getRuntime\\("
  "\\.exec\\("
  "ProcessBuilder"
  "request\\.getParameter\\("
  "response\\.getWriter\\("
  "out\\.println\\("
  "new File\\("
  "FileWriter"
  "PrintWriter"
  "FileOutputStream"
  "InputStreamReader"
  "BufferedReader"
  "cmd="
  "command="
  "powershell"
  "cmd.exe"
  "/bin/sh"
  "/bin/bash"
  "BASE64Decoder"
  "BASE64Encoder"
  "Base64\\.getDecoder"
  "Base64\\.getEncoder"
  "new String\\(Base64"
  "javax\\.crypto"
  "Cipher\\.getInstance"
  "Class\\.forName"
  "getDeclaredMethod"
  "setAccessible\\("
  "java\\.lang\\.reflect"
  "pageContext\\.getRequest"
  "session\\.getAttribute"
  "application\\.getAttribute"
  "getServletContext"
  "sun\\.misc"
  "URLClassLoader"
  "defineClass"
)

for pattern in "${JSP_PATTERNS[@]}"; do
  hits="$(grep -iErn --include='*.jsp' --include='*.jspx' "$pattern" "$SEARCH_DIR" 2>/dev/null || true)"
  print_hit_block "Suspicious JSP pattern" "$pattern" "$hits"
done

# ------------------------------------------------------------
# 2. PeopleSoft / ShinyHunters HTTP path indicators
# ------------------------------------------------------------

section "2. PeopleSoft / ShinyHunters HTTP path indicators"

HTTP_PATTERNS=(
  "POST /PSEMHUB/hub"
  "POST /PSIGW/HttpListeningConnector"
  "/PSEMHUB/hub"
  "/PSIGW/HttpListeningConnector"
  "/PSEMHUB/"
  "PSEMHUB.war"
)

for pattern in "${HTTP_PATTERNS[@]}"; do
  hits="$(grep -RIn "$pattern" "$SEARCH_DIR" 2>/dev/null || true)"
  print_hit_block "HTTP/path indicator" "$pattern" "$hits"
done

# ------------------------------------------------------------
# 3. PeopleSoft PSEMHUB filesystem indicators
# ------------------------------------------------------------

section "3. PeopleSoft PSEMHUB filesystem indicators"

find "$SEARCH_DIR" -type f -path "*/PSEMHUB.war/*" -name "*.jsp" 2>/dev/null | while read -r f; do
  echo "[REVIEW] JSP under PSEMHUB.war: $f"
done

find "$SEARCH_DIR" -type f -path "*/PSEMHUB.war/*" -name "*.jspx" 2>/dev/null | while read -r f; do
  echo "[REVIEW] JSPX under PSEMHUB.war: $f"
done

find "$SEARCH_DIR" -type d -path "*/PSEMHUB.war/envmetadata/transactions/*" 2>/dev/null | while read -r d; do
  echo "[HIT/REVIEW] Directory under PSEMHUB envmetadata transactions: $d"
done

find "$SEARCH_DIR" -type d \( \
  -path "*/PSEMHUB*/logs" -o \
  -path "*/PSEMHUB*/persistantstorage" -o \
  -path "*/PSEMHUB*/persistentstorage" -o \
  -path "*/PSEMHUB*/scratchpad" \
\) 2>/dev/null | while read -r d; do
  echo "[HIT/REVIEW] Suspicious or interesting PSEMHUB directory: $d"
done

find "$SEARCH_DIR" -type f -path "*/envmetadata/data/environment/*.xml" -mtime -45 2>/dev/null | while read -r f; do
  echo "[REVIEW] Recently modified environment XML: $f"
done

# ------------------------------------------------------------
# 4. Filename indicators
# ------------------------------------------------------------

section "4. Filename indicators"

FILENAME_PATTERNS=(
  "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT"
  "*_fanout.sh"
  "meshagent"
  "meshagent.exe"
  "meshagent32-azure-ops.exe"
  "meshagent64-azure-ops.exe"
  "meshagent64-v2.exe"
  "meshctrl.js"
  ".bash_history"
)

for fname in "${FILENAME_PATTERNS[@]}"; do
  find "$SEARCH_DIR" -type f -name "$fname" 2>/dev/null | while read -r f; do
    echo "[HIT] Suspicious filename: $f"
  done
done

# ------------------------------------------------------------
# 5. Network / C2 indicators in files and logs
# ------------------------------------------------------------

section "5. Network/C2 indicators in files and logs"

NETWORK_IOCS=(
  "142.11.200.186"
  "142.11.200.187"
  "142.11.200.188"
  "142.11.200.189"
  "142.11.200.190"
  "108.174.202.99"
  "176.120.22.24"
  "azurenetfiles.net"
  "wss://azurenetfiles.net:443/agent.ashx"
)

for ioc in "${NETWORK_IOCS[@]}"; do
  hits="$(grep -RIn "$ioc" "$SEARCH_DIR" 2>/dev/null || true)"
  print_hit_block "Network/C2 IOC" "$ioc" "$hits"
done

# ------------------------------------------------------------
# 6. PeopleSoft reconnaissance and lateral movement strings
# ------------------------------------------------------------

section "6. PeopleSoft recon and lateral movement strings"

RECON_PATTERNS=(
  "psappsrv.cfg"
  "config.xml"
  "ps_config"
  "psoft"
  "sshpass"
  "cat /etc/hosts"
  "mount | grep"
  "zstd"
  "tar"
  "exfil"
  "meshctrl.js"
)

for pattern in "${RECON_PATTERNS[@]}"; do
  hits="$(grep -RIn "$pattern" "$SEARCH_DIR" 2>/dev/null || true)"
  print_hit_block "Recon/lateral movement string" "$pattern" "$hits"
done

# ------------------------------------------------------------
# 7. SHA256 hash indicators
# ------------------------------------------------------------

section "7. SHA256 hash indicators"

HASH_IOCS=(
  "2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35"
  "f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc"
  "d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f"
  "c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f"
  "68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309"
)

if command -v sha256sum >/dev/null 2>&1; then
  find "$SEARCH_DIR" -type f 2>/dev/null | while read -r f; do
    hash="$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || true)"

    if [[ -z "$hash" ]]; then
      continue
    fi

    for ioc_hash in "${HASH_IOCS[@]}"; do
      if [[ "$hash" == "$ioc_hash" ]]; then
        echo "[HIT] SHA256 match: $f $hash"
      fi
    done
  done
else
  echo "[WARN] sha256sum not found; skipping hash checks."
fi

# ------------------------------------------------------------
# 8. Local process hints
# ------------------------------------------------------------

section "8. Local process hints"

if command -v ps >/dev/null 2>&1; then
  ps auxww 2>/dev/null | grep -Ei "meshagent|meshcentral|meshctrl|azurenetfiles|sshpass" | grep -v grep || true
else
  echo "[INFO] ps command not available; skipping process checks."
fi

# ------------------------------------------------------------
# Complete
# ------------------------------------------------------------

echo
echo "============================================================"
echo "[*] Scan complete."
echo "[*] Treat findings as triage leads."
echo "[*] Validate using EDR, logs, file timestamps, and known-good baselines."
echo "============================================================"