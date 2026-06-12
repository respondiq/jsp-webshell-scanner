<#
.SYNOPSIS
JSP Webshell + PeopleSoft IOC Scanner

.DESCRIPTION
Recursively scans a target directory for:
  1. Suspicious JSP webshell patterns
  2. Oracle PeopleSoft / ShinyHunters / UNC6240 indicators
  3. Known filenames, paths, hashes, and C2 strings

Usage:
  .\detect_webshells.ps1 -Path .
  .\detect_webshells.ps1 -Path C:\inetpub\wwwroot
  .\detect_webshells.ps1 -Path D:\PeopleSoft

Notes:
  Findings are triage leads, not definitive proof of compromise.
  Validate with EDR, file metadata, web access logs, known-good baselines,
  and forensic review.
#>

param (
    [string]$Path = "."
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[*] JSP Webshell + PeopleSoft IOC Scanner" -ForegroundColor Cyan
Write-Host "[*] Scanning directory: $Path" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not (Test-Path -Path $Path)) {
    Write-Host "[ERROR] Path does not exist: $Path" -ForegroundColor Red
    exit 1
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "==== $Title ====" -ForegroundColor Yellow
}

function Write-Hit {
    param(
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Red
}

function Write-Review {
    param(
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Magenta
}

# ------------------------------------------------------------
# Collect files once
# ------------------------------------------------------------

Write-Section "Preparing file inventory"

try {
    $AllFiles = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
    $AllDirs  = Get-ChildItem -Path $Path -Recurse -Directory -ErrorAction SilentlyContinue
    $JspFiles = $AllFiles | Where-Object { $_.Extension -match "^\.jspx?$" }

    Write-Host "[*] Files discovered: $($AllFiles.Count)"
    Write-Host "[*] Directories discovered: $($AllDirs.Count)"
    Write-Host "[*] JSP/JSPX files discovered: $($JspFiles.Count)"
}
catch {
    Write-Host "[ERROR] Failed to enumerate files: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------
# 1. Suspicious JSP webshell patterns
# ------------------------------------------------------------

Write-Section "1. Suspicious JSP code patterns"

$JspPatterns = @(
    "Runtime\.getRuntime\(",
    "\.exec\(",
    "ProcessBuilder",
    "request\.getParameter\(",
    "response\.getWriter\(",
    "out\.println\(",
    "new File\(",
    "FileWriter",
    "PrintWriter",
    "FileOutputStream",
    "InputStreamReader",
    "BufferedReader",
    "cmd=",
    "command=",
    "powershell",
    "cmd\.exe",
    "/bin/sh",
    "/bin/bash",
    "BASE64Decoder",
    "BASE64Encoder",
    "Base64\.getDecoder",
    "Base64\.getEncoder",
    "new String\(Base64",
    "javax\.crypto",
    "Cipher\.getInstance",
    "Class\.forName",
    "getDeclaredMethod",
    "setAccessible\(",
    "java\.lang\.reflect",
    "pageContext\.getRequest",
    "session\.getAttribute",
    "application\.getAttribute",
    "getServletContext",
    "sun\.misc",
    "URLClassLoader",
    "defineClass"
)

foreach ($file in $JspFiles) {
    try {
        $matches = Select-String -Path $file.FullName -Pattern $JspPatterns -AllMatches -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            Write-Hit "[HIT] Suspicious JSP pattern in $($m.Path):$($m.LineNumber): $($m.Line.Trim())"
        }
    }
    catch {
        # Skip unreadable files
    }
}

# ------------------------------------------------------------
# 2. PeopleSoft / ShinyHunters HTTP path indicators
# ------------------------------------------------------------

Write-Section "2. PeopleSoft / ShinyHunters HTTP path indicators"

$HttpPatterns = @(
    "POST /PSEMHUB/hub",
    "POST /PSIGW/HttpListeningConnector",
    "/PSEMHUB/hub",
    "/PSIGW/HttpListeningConnector",
    "/PSEMHUB/",
    "PSEMHUB.war"
)

foreach ($pattern in $HttpPatterns) {
    try {
        $matches = Select-String -Path $AllFiles.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            Write-Hit "[HIT] HTTP/path IOC '$pattern' in $($m.Path):$($m.LineNumber): $($m.Line.Trim())"
        }
    }
    catch {
        # Skip unreadable files
    }
}

# ------------------------------------------------------------
# 3. PeopleSoft PSEMHUB filesystem indicators
# ------------------------------------------------------------

Write-Section "3. PeopleSoft PSEMHUB filesystem indicators"

$AllFiles |
    Where-Object {
        $_.FullName -match "PSEMHUB\.war" -and
        $_.Extension -match "^\.jspx?$"
    } |
    ForEach-Object {
        Write-Review "[REVIEW] JSP/JSPX under PSEMHUB.war: $($_.FullName)"
    }

$AllDirs |
    Where-Object {
        $_.FullName -match "PSEMHUB\.war.*envmetadata.*transactions"
    } |
    ForEach-Object {
        Write-Hit "[HIT/REVIEW] Directory under PSEMHUB envmetadata transactions: $($_.FullName)"
    }

$AllDirs |
    Where-Object {
        $_.FullName -match "PSEMHUB.*\\logs$" -or
        $_.FullName -match "PSEMHUB.*\\persistantstorage$" -or
        $_.FullName -match "PSEMHUB.*\\persistentstorage$" -or
        $_.FullName -match "PSEMHUB.*\\scratchpad$"
    } |
    ForEach-Object {
        Write-Hit "[HIT/REVIEW] Suspicious or interesting PSEMHUB directory: $($_.FullName)"
    }

$AllFiles |
    Where-Object {
        $_.Extension -ieq ".xml" -and
        $_.FullName -match "envmetadata.*data.*environment" -and
        $_.LastWriteTime -gt (Get-Date).AddDays(-45)
    } |
    ForEach-Object {
        Write-Review "[REVIEW] Recently modified environment XML: $($_.FullName)"
    }

# ------------------------------------------------------------
# 4. Filename indicators
# ------------------------------------------------------------

Write-Section "4. Filename indicators"

$FilenameIndicators = @(
    "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT",
    "meshagent",
    "meshagent.exe",
    "meshagent32-azure-ops.exe",
    "meshagent64-azure-ops.exe",
    "meshagent64-v2.exe",
    "meshctrl.js",
    ".bash_history"
)

foreach ($indicator in $FilenameIndicators) {
    $AllFiles |
        Where-Object { $_.Name -ieq $indicator } |
        ForEach-Object {
            Write-Hit "[HIT] Suspicious filename '$indicator': $($_.FullName)"
        }
}

$AllFiles |
    Where-Object { $_.Name -like "*_fanout.sh" } |
    ForEach-Object {
        Write-Hit "[HIT] Possible fanout script: $($_.FullName)"
    }

# ------------------------------------------------------------
# 5. Network / C2 indicators in files and logs
# ------------------------------------------------------------

Write-Section "5. Network/C2 indicators in files and logs"

$NetworkIocs = @(
    "142.11.200.186",
    "142.11.200.187",
    "142.11.200.188",
    "142.11.200.189",
    "142.11.200.190",
    "108.174.202.99",
    "176.120.22.24",
    "azurenetfiles.net",
    "wss://azurenetfiles.net:443/agent.ashx"
)

foreach ($ioc in $NetworkIocs) {
    try {
        $matches = Select-String -Path $AllFiles.FullName -Pattern $ioc -SimpleMatch -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            Write-Hit "[HIT] Network/C2 IOC '$ioc' in $($m.Path):$($m.LineNumber): $($m.Line.Trim())"
        }
    }
    catch {
        # Skip unreadable files
    }
}

# ------------------------------------------------------------
# 6. PeopleSoft reconnaissance and lateral movement strings
# ------------------------------------------------------------

Write-Section "6. PeopleSoft recon and lateral movement strings"

$ReconPatterns = @(
    "psappsrv.cfg",
    "config.xml",
    "ps_config",
    "psoft",
    "sshpass",
    "cat /etc/hosts",
    "mount | grep",
    "zstd",
    "tar",
    "exfil",
    "meshctrl.js"
)

foreach ($pattern in $ReconPatterns) {
    try {
        $matches = Select-String -Path $AllFiles.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            Write-Review "[REVIEW] Recon/lateral movement string '$pattern' in $($m.Path):$($m.LineNumber): $($m.Line.Trim())"
        }
    }
    catch {
        # Skip unreadable files
    }
}

# ------------------------------------------------------------
# 7. SHA256 hash indicators
# ------------------------------------------------------------

Write-Section "7. SHA256 hash indicators"

$HashIocs = @(
    "2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35",
    "f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc",
    "d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f",
    "c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f",
    "68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309"
)

foreach ($file in $AllFiles) {
    try {
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()

        if ($HashIocs -contains $hash) {
            Write-Hit "[HIT] SHA256 match: $($file.FullName) $hash"
        }
    }
    catch {
        # Skip unreadable or locked files
    }
}

# ------------------------------------------------------------
# 8. Local process hints
# ------------------------------------------------------------

Write-Section "8. Local process hints"

try {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProcessName -match "mesh|agent|ssh|java|weblogic"
        } |
        Select-Object ProcessName, Id, Path |
        Format-Table -AutoSize
}
catch {
    Write-Host "[INFO] Could not enumerate processes."
}

# ------------------------------------------------------------
# Complete
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[*] Scan complete." -ForegroundColor Cyan
Write-Host "[*] Treat findings as triage leads." -ForegroundColor Cyan
Write-Host "[*] Validate using EDR, logs, file timestamps, and known-good baselines." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan