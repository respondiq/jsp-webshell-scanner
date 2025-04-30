#!/bin/bash

# === JSP Webshell Scanner for CVE-2025-31324 ===
# Author: Mo Faghani
# Version: 1.0
# Description:
#   Recursively scans all .jsp files in the current or specified directory
#   for suspicious code patterns commonly seen in webshells and exploited in
#   SAP NetWeaver CVE-2025-31324.

SEARCH_DIR=${1:-.}

echo "============================================================"
echo "[*] Scanning directory: $SEARCH_DIR"
echo "[*] Place this script in the web server folder where JSP files are executed."
echo "============================================================"

# Suspicious pattern definitions
PATTERNS=(
    "Runtime\\.getRuntime\\("
    "request\\.getParameter\\("
    "response\\.getWriter\\("
    "new File\\("
    "out\\.println\\("
    "cmd="
    "command="
    "ProcessBuilder"
    "InputStreamReader"
    "BASE64Decoder"
    "BASE64Encoder"
    "new String\\(Base64"
)

# Main scan loop
for pattern in "${PATTERNS[@]}"; do
    echo ""
    echo "[*] Searching for pattern: \"$pattern\""
    grep -iErn --include="*.jsp" "$pattern" "$SEARCH_DIR"
done

echo ""
echo "[*] Scan complete. Review findings above."
